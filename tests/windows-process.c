#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>

static int fail(const char *what) {
    fprintf(stderr, "process-probe: %s (error=%lu)\n", what, (unsigned long)GetLastError());
    return 1;
}

static int token_is_appcontainer(void) {
    HANDLE token = NULL;
    BOOL value = FALSE;
    DWORD size = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return -1;
    if (!GetTokenInformation(token, TokenIsAppContainer, &value, sizeof(value), &size)) {
        CloseHandle(token);
        return -1;
    }
    CloseHandle(token);
    return value ? 1 : 0;
}

static int probe_identity(int sandbox) {
    HANDLE token = NULL;
    DWORD size = 0;
    TOKEN_USER *user = NULL;
    WCHAR *sid = NULL;
    int appcontainer = token_is_appcontainer();
    if (appcontainer < 0) return fail("TokenIsAppContainer");
    if (appcontainer != (sandbox ? 1 : 0)) {
        fprintf(stderr, "process-probe: identity mismatch appcontainer=%d expected=%d\n",
                appcontainer, sandbox ? 1 : 0);
        return 1;
    }
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return fail("OpenProcessToken");
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    user = (TOKEN_USER *)malloc(size);
    if (!user || !GetTokenInformation(token, TokenUser, user, size, &size)) {
        free(user); CloseHandle(token); return fail("TokenUser");
    }
    if (!ConvertSidToStringSidW(user->User.Sid, &sid)) {
        free(user); CloseHandle(token); return fail("ConvertSidToStringSid");
    }
    wprintf(L"PROCESS identity appcontainer=%d sid=%ls\n", appcontainer, sid);
    LocalFree(sid); free(user); CloseHandle(token);
    return 0;
}

static int probe_nul_and_final_path(void) {
    HANDLE nul = CreateFileW(L"\\\\.\\NUL", GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    WCHAR path[32768], wide[32768];
    char ansi[32768];
    HANDLE file;
    DWORD wlength, alength;
    if (nul == INVALID_HANDLE_VALUE) return fail("CreateFileW NUL");
    CloseHandle(nul);
    if (!GetModuleFileNameW(NULL, path, sizeof(path) / sizeof(path[0])))
        return fail("GetModuleFileNameW");
    file = CreateFileW(path, FILE_READ_ATTRIBUTES,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return fail("Open executable for final path");
    wlength = GetFinalPathNameByHandleW(file, wide, sizeof(wide) / sizeof(wide[0]), 0);
    if (!wlength || wlength >= sizeof(wide) / sizeof(wide[0])) {
        CloseHandle(file); return fail("GetFinalPathNameByHandleW executable");
    }
    alength = GetFinalPathNameByHandleA(file, ansi, sizeof(ansi), 0);
    if (!alength || alength >= sizeof(ansi)) {
        CloseHandle(file); return fail("GetFinalPathNameByHandleA executable");
    }
    wprintf(L"PROCESS NUL final-path-w=%ls\n", wide);
    printf("PROCESS NUL final-path-a=%s\n", ansi);
    CloseHandle(file);
    return 0;
}

static WCHAR *environment_block(void) {
    WCHAR root[32768];
    WCHAR *block;
    DWORD length = GetEnvironmentVariableW(L"SystemRoot", root, sizeof(root) / sizeof(root[0]));
    size_t chars;
    if (!length || length >= sizeof(root) / sizeof(root[0])) return NULL;
    chars = 11 + length + 2;
    block = (WCHAR *)calloc(chars + 1, sizeof(WCHAR));
    if (!block) return NULL;
    swprintf(block, chars + 1, L"SystemRoot=%ls", root);
    block[11 + length] = L'\0';
    block[12 + length] = L'\0';
    return block;
}

static int wait_child(HANDLE process, const char *label) {
    DWORD status;
    if (WaitForSingleObject(process, 5000) != WAIT_OBJECT_0) return fail(label);
    if (!GetExitCodeProcess(process, &status)) return fail("GetExitCodeProcess");
    if (status != 0) {
        fprintf(stderr, "process-probe: %s exit=%lu\n", label, (unsigned long)status);
        return 1;
    }
    return 0;
}

static int run_suspended_w(const WCHAR *path, const WCHAR *label, int sandbox) {
    WCHAR command[32768];
    WCHAR *environment = environment_block();
    STARTUPINFOW startup = {0}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION process = {0};
    DWORD status;
    int result = 0;
    if (!environment) return fail("environment block");
    swprintf(command, sizeof(command) / sizeof(command[0]), L"\"%ls\" --suspended-leaf %d", path, sandbox);
    if (!CreateProcessW(path, command, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                        environment, NULL, &startup, &process)) {
        free(environment); return fail("CreateProcessW");
    }
    if (GetExitCodeProcess(process.hProcess, &status) && status != STILL_ACTIVE) {
        fprintf(stderr, "process-probe: %ls ran before ResumeThread (exit=%lu)\n", label,
                (unsigned long)status);
        result = 1;
    }
    if (WaitForSingleObject(process.hProcess, 100) != WAIT_TIMEOUT) {
        fprintf(stderr, "process-probe: %ls was not suspended\n", label);
        result = 1;
    }
    if (!result && ResumeThread(process.hThread) != 1) result = fail("ResumeThread");
    if (!result) result = wait_child(process.hProcess, "CreateProcessW child");
    CloseHandle(process.hThread); CloseHandle(process.hProcess); free(environment);
    return result;
}

static int run_suspended_a(const WCHAR *path, const char *label, int sandbox) {
    char narrow_path[32768];
    char command[32768];
    STARTUPINFOA startup = {0}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION process = {0};
    WCHAR *environment = environment_block();
    DWORD status;
    int result = 0;
    if (!environment || !WideCharToMultiByte(CP_ACP, 0, path, -1, narrow_path,
                                             sizeof(narrow_path), NULL, NULL)) {
        free(environment); return fail("ANSI process path");
    }
    _snprintf(command, sizeof(command), "\"%s\" --suspended-leaf %d", narrow_path, sandbox);
    if (!CreateProcessA(narrow_path, command, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, environment,
                        NULL, &startup, &process)) {
        free(environment); return fail("CreateProcessA");
    }
    if (GetExitCodeProcess(process.hProcess, &status) && status != STILL_ACTIVE) {
        fprintf(stderr, "process-probe: %s ran before ResumeThread (exit=%lu)\n", label,
                (unsigned long)status);
        result = 1;
    }
    if (WaitForSingleObject(process.hProcess, 100) != WAIT_TIMEOUT) {
        fprintf(stderr, "process-probe: %s was not suspended\n", label);
        result = 1;
    }
    if (!result && ResumeThread(process.hThread) != 1) result = fail("ResumeThread");
    if (!result) result = wait_child(process.hProcess, label);
    CloseHandle(process.hThread); CloseHandle(process.hProcess); free(environment);
    return result;
}

static int run_as_user_w(const WCHAR *path, BOOL ansi, int sandbox) {
    HANDLE source = NULL, token = NULL;
    STARTUPINFOW startup = {0}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION process = {0};
    WCHAR command[32768], *environment = environment_block();
    DWORD error;
    BOOL ok;
    if (!environment || !OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &source) ||
        !DuplicateTokenEx(source, TOKEN_ALL_ACCESS, NULL, SecurityIdentification,
                          TokenPrimary, &token)) {
        free(environment); if (source) CloseHandle(source); return fail("duplicate process token");
    }
    swprintf(command, sizeof(command) / sizeof(command[0]), L"\"%ls\" --suspended-leaf %d", path, sandbox);
    ok = CreateProcessAsUserW(token, path, command, NULL, NULL, FALSE,
                              CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, environment,
                              NULL, &startup, &process);
    error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok && (error == ERROR_ACCESS_DENIED || error == ERROR_PRIVILEGE_NOT_HELD ||
                error == ERROR_NOT_ALL_ASSIGNED || error == ERROR_INVALID_PARAMETER)) {
        printf("PROCESS CreateProcessAsUser%s skipped error=%lu\n", ansi ? "A" : "W",
               (unsigned long)error);
        CloseHandle(token); CloseHandle(source); free(environment); return 0;
    }
    if (!ok) { SetLastError(error); CloseHandle(token); CloseHandle(source); free(environment); return fail("CreateProcessAsUserW"); }
    if (WaitForSingleObject(process.hProcess, 100) != WAIT_TIMEOUT)
        error = ERROR_INVALID_DATA;
    else if (ResumeThread(process.hThread) != 1) error = GetLastError();
    else error = wait_child(process.hProcess, "CreateProcessAsUserW child") ? ERROR_INVALID_DATA : ERROR_SUCCESS;
    CloseHandle(process.hThread); CloseHandle(process.hProcess); CloseHandle(token); CloseHandle(source); free(environment);
    if (error) { SetLastError(error); return 1; }
    return 0;
}

static int run_as_user_a(const WCHAR *path, int sandbox) {
    HANDLE source = NULL, token = NULL;
    char narrow_path[32768], command[32768];
    STARTUPINFOA startup = {0}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION process = {0};
    WCHAR *environment = environment_block();
    DWORD error;
    BOOL ok;
    if (!environment || !WideCharToMultiByte(CP_ACP, 0, path, -1, narrow_path,
                                             sizeof(narrow_path), NULL, NULL)) {
        free(environment); return fail("ANSI AsUser path");
    }
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &source) ||
        !DuplicateTokenEx(source, TOKEN_ALL_ACCESS, NULL, SecurityIdentification,
                          TokenPrimary, &token)) {
        free(environment); if (source) CloseHandle(source); return fail("duplicate process token");
    }
    _snprintf(command, sizeof(command), "\"%s\" --suspended-leaf %d", narrow_path, sandbox);
    ok = CreateProcessAsUserA(token, narrow_path, command, NULL, NULL, FALSE,
                              CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, environment,
                              NULL, &startup, &process);
    error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok && (error == ERROR_ACCESS_DENIED || error == ERROR_PRIVILEGE_NOT_HELD ||
                error == ERROR_NOT_ALL_ASSIGNED || error == ERROR_INVALID_PARAMETER)) {
        printf("PROCESS CreateProcessAsUserA skipped error=%lu\n", (unsigned long)error);
        CloseHandle(token); CloseHandle(source); free(environment); return 0;
    }
    if (!ok) { SetLastError(error); CloseHandle(token); CloseHandle(source); free(environment); return fail("CreateProcessAsUserA"); }
    if (WaitForSingleObject(process.hProcess, 100) != WAIT_TIMEOUT)
        error = ERROR_INVALID_DATA;
    else if (ResumeThread(process.hThread) != 1) error = GetLastError();
    else error = wait_child(process.hProcess, "CreateProcessAsUserA child") ? ERROR_INVALID_DATA : ERROR_SUCCESS;
    CloseHandle(process.hThread); CloseHandle(process.hProcess); CloseHandle(token); CloseHandle(source); free(environment);
    if (error) { SetLastError(error); return 1; }
    return 0;
}

static int probe_alias_tamper(const WCHAR *profile) {
    WCHAR target[32768];
    DWORD length;
    BOOL removed;
    BOOL redefined;
    if (token_is_appcontainer() != 1) {
        fprintf(stderr, "process-probe: alias tamper requires AppContainer identity\n");
        return 1;
    }
    length = GetCurrentDirectoryW(sizeof(target) / sizeof(target[0]), target);
    if (!length || length >= sizeof(target) / sizeof(target[0]) ||
        swprintf(target + length, sizeof(target) / sizeof(target[0]) - length,
                 L"\\\\alias-tamper-denied.txt") < 0)
        return fail("alias tamper target");
    SetLastError(ERROR_SUCCESS);
    removed = DefineDosDeviceW(DDD_REMOVE_DEFINITION | DDD_RAW_TARGET_PATH,
                               profile, NULL);
    if (removed || GetLastError() != ERROR_ACCESS_DENIED) {
        if (removed)
            DefineDosDeviceW(DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE |
                             DDD_RAW_TARGET_PATH, profile, NULL);
        fprintf(stderr, "process-probe: alias removal was not denied (removed=%d error=%lu)\n",
                removed ? 1 : 0, (unsigned long)GetLastError());
        return 1;
    }
    SetLastError(ERROR_SUCCESS);
    redefined = DefineDosDeviceW(DDD_RAW_TARGET_PATH, profile, target);
    if (redefined) {
        DefineDosDeviceW(DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE |
                         DDD_RAW_TARGET_PATH, profile, target);
        fprintf(stderr, "process-probe: alias redefinition unexpectedly succeeded\n");
        return 1;
    }
    if (GetLastError() != ERROR_ACCESS_DENIED) {
        fprintf(stderr, "process-probe: alias redefinition error=%lu, expected 5\n",
                (unsigned long)GetLastError());
        return 1;
    }
    printf("PROCESS alias tamper denied profile=%ls error=5\n", profile);
    return 0;
}
static int probe_leaf(int sandbox) {
    WCHAR path[32768];
    if (token_is_appcontainer() != (sandbox ? 1 : 0)) {
        fprintf(stderr, "process-probe: leaf identity mismatch\n");
        return 1;
    }
    if (!GetEnvironmentVariableW(L"PATH", path, sizeof(path) / sizeof(path[0])))
        printf("PROCESS leaf PATH absent\n");
    else {
        fprintf(stderr, "process-probe: leaf PATH unexpectedly present\n");
        return 1;
    }
    return probe_identity(sandbox) | probe_nul_and_final_path();
}

static int probe_root(int sandbox, const WCHAR *peer) {
    WCHAR path[32768];
    int result = 0;
    if (!GetModuleFileNameW(NULL, path, sizeof(path) / sizeof(path[0]))) return fail("GetModuleFileNameW");
    result |= probe_identity(sandbox);
    result |= probe_nul_and_final_path();
    result |= run_suspended_w(path, L"CreateProcessW", sandbox);
    result |= run_suspended_a(path, "CreateProcessA", sandbox);
    result |= run_as_user_w(path, FALSE, sandbox);
    result |= run_as_user_a(path, sandbox);
    if (peer && *peer) {
        WCHAR command[32768], *environment = environment_block();
        STARTUPINFOW startup = {0}; startup.cb = sizeof(startup);
        PROCESS_INFORMATION process = {0};
        swprintf(command, sizeof(command) / sizeof(command[0]),
                 L"\"%ls\" --peer-leaf %d \"%ls\"", peer, sandbox, path);
        if (!environment || !CreateProcessW(peer, command, NULL, NULL, FALSE,
                                            CREATE_UNICODE_ENVIRONMENT, environment, NULL,
                                            &startup, &process)) {
            if (environment) free(environment);
            return fail("cross-bitness CreateProcessW");
        }
        result |= wait_child(process.hProcess, "cross-bitness child");
        CloseHandle(process.hThread); CloseHandle(process.hProcess); free(environment);
    }
    return result ? 1 : 0;
}

int wmain(int argc, wchar_t **argv) {
    int sandbox = 0;
    const WCHAR *peer = NULL;
    if (argc >= 3 && !_wcsicmp(argv[1], L"--suspended-leaf"))
        return probe_leaf(_wtoi(argv[2]));
    if (argc >= 3 && !_wcsicmp(argv[1], L"--peer-leaf")) {
        sandbox = _wtoi(argv[2]);
        if (argc < 4) return fail("peer leaf executable");
        return probe_leaf(sandbox) | run_suspended_w(argv[3], L"return cross-bitness child", sandbox);
    }
    if (argc >= 3 && !_wcsicmp(argv[1], L"alias-tamper"))
        return probe_alias_tamper(argv[2]);
    for (int i = 1; i < argc; ++i) {
        if (!_wcsicmp(argv[i], L"--sandbox")) sandbox = 1;
        else if (!_wcsicmp(argv[i], L"--peer") && i + 1 < argc) peer = argv[++i];
    }
    return probe_root(sandbox, peer);
}
