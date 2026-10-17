#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <aclapi.h>
#include <sddl.h>

static int write_file(const wchar_t *path) {
    HANDLE file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return (int)GetLastError();
    DWORD written;
    BOOL ok = WriteFile(file, "sandbox\n", 8, &written, NULL);
    DWORD error = ok ? 0 : GetLastError();
    CloseHandle(file);
    return (int)error;
}
static int probe_nul_path(const wchar_t *path) {
    int status = 0, error;
    HANDLE handle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 NULL, OPEN_EXISTING, 0, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        error = (int)GetLastError();
        wprintf(L"NUL path=%ls access=read open-error=%d\n", path, error);
        status = error;
    } else {
        char byte; DWORD count = 99;
        BOOL ok = ReadFile(handle, &byte, 1, &count, NULL);
        error = ok && count == 0 ? 0 : (ok ? ERROR_INVALID_DATA : (int)GetLastError());
        wprintf(L"NUL path=%ls access=read result=%d bytes=%lu\n", path, error, count);
        if (error && !status) status = error;
        CloseHandle(handle);
    }
    handle = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, OPEN_EXISTING, 0, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        error = (int)GetLastError();
        wprintf(L"NUL path=%ls access=write open-error=%d\n", path, error);
        if (!status) status = error;
    } else {
        DWORD count = 0; BOOL ok = WriteFile(handle, "nul", 3, &count, NULL);
        error = ok && count == 3 ? 0 : (ok ? ERROR_INVALID_DATA : (int)GetLastError());
        wprintf(L"NUL path=%ls access=write result=%d bytes=%lu\n", path, error, count);
        if (error && !status) status = error;
        CloseHandle(handle);
    }
    handle = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        error = (int)GetLastError();
        wprintf(L"NUL path=%ls access=read-write open-error=%d\n", path, error);
        if (!status) status = error;
    } else {
        CloseHandle(handle);
        wprintf(L"NUL path=%ls access=read-write result=0\n", path);
    }
    return status;
}

static int probe_nul(void) {
    static const wchar_t *paths[] = {L"NUL", L"\\\\.\\NUL", L"\\\\?\\GLOBALROOT\\Device\\Null"};
    int status = 0;
    for (unsigned i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        int result = probe_nul_path(paths[i]);
        if (result && !status) status = result;
    }
    return status;
}
static int probe_nul_security(void) {
    HANDLE handle = CreateFileW(L"\\\\?\\GLOBALROOT\\Device\\Null", READ_CONTROL,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (handle == INVALID_HANDLE_VALUE) return (int)GetLastError();
    PSECURITY_DESCRIPTOR descriptor = NULL;
    SECURITY_INFORMATION information = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                       DACL_SECURITY_INFORMATION;
    DWORD error = GetSecurityInfo(handle, SE_FILE_OBJECT, information,
                                 NULL, NULL, NULL, NULL, &descriptor);
    if (!error) {
        wchar_t *text = NULL;
        if (ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, SDDL_REVISION_1,
                                                                 information, &text, NULL)) {
            wprintf(L"NUL security=%ls\n", text);
            LocalFree(text);
        } else error = GetLastError();
    }
    if (descriptor) LocalFree(descriptor);
    CloseHandle(handle);
    return (int)error;
}

static int probe_nul_descendant(void) {
    wchar_t executable[32768], line[32768];
    if (!GetModuleFileNameW(NULL, executable, sizeof(executable) / sizeof(*executable))) return 99;
    if (swprintf(line, sizeof(line) / sizeof(*line), L"\"%ls\" nul", executable) < 0) return 99;
    STARTUPINFOW startup = {0}; PROCESS_INFORMATION process = {0};
    startup.cb = sizeof(startup);
    if (!CreateProcessW(executable, line, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &startup, &process)) return (int)GetLastError();
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD status = 99;
    GetExitCodeProcess(process.hProcess, &status);
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    wprintf(L"NUL descendant exit=%lu\n", status);
    return (int)status;
}


static int probe_cwd(void) {
    wchar_t cwd[32768], path[32768];
    DWORD count = GetCurrentDirectoryW(32768, cwd);
    if (!count || count >= 32768) return (int)GetLastError();
    wprintf(L"CWD current=%ls\n", cwd);
    HANDLE handle = CreateFileW(cwd, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (handle == INVALID_HANDLE_VALUE) return (int)GetLastError();
    const DWORD flags[] = {0, FILE_NAME_OPENED, VOLUME_NAME_NT, VOLUME_NAME_NT | FILE_NAME_OPENED};
    for (unsigned i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i) {
        count = GetFinalPathNameByHandleW(handle, path, 32768, flags[i]);
        if (count && count < 32768) wprintf(L"CWD final flags=%lu path=%ls\n", flags[i], path);
        else wprintf(L"CWD final flags=%lu error=%lu\n", flags[i], GetLastError());
    }
    CloseHandle(handle);
    count = GetLongPathNameW(cwd, path, 32768);
    if (count && count < 32768) wprintf(L"CWD long path=%ls\n", path);
    else wprintf(L"CWD long error=%lu\n", GetLastError());
    return 0;
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 2) return 99;
    if (!wcscmp(argv[1], L"identity")) {
        HANDLE token;
        DWORD appcontainer = 0, size;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return 99;
        BOOL ok = GetTokenInformation(token, TokenIsAppContainer, &appcontainer, sizeof(appcontainer), &size);
        CloseHandle(token);
        return ok && appcontainer == 1 ? 0 : 98;
    }
    if (!wcscmp(argv[1], L"echo")) {
        for (int i = 2; i < argc; ++i) wprintf(L"[%ls]\n", argv[i]);
        return 0;
    }
    if (!wcscmp(argv[1], L"nul")) return probe_nul();
    if (!wcscmp(argv[1], L"nul-descendant")) return probe_nul_descendant();
    if (!wcscmp(argv[1], L"nul-security")) return probe_nul_security();
    if (!wcscmp(argv[1], L"cwd")) return probe_cwd();

    if (argc < 3) return 99;

    if (!wcscmp(argv[1], L"protect-acl")) {
        PSECURITY_DESCRIPTOR descriptor = NULL;
        PACL acl = NULL;
        DWORD error = GetNamedSecurityInfoW(argv[2], SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                            NULL, NULL, &acl, NULL, &descriptor);
        if (error) return (int)error;
        error = SetNamedSecurityInfoW(argv[2], SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    NULL, NULL, acl, NULL);
        LocalFree(descriptor);
        return (int)error;
    }
    if (!wcscmp(argv[1], L"acl")) {
        PSECURITY_DESCRIPTOR descriptor = NULL;
        DWORD error = GetNamedSecurityInfoW(argv[2], SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                            NULL, NULL, NULL, NULL, &descriptor);
        if (error) return (int)error;
        wchar_t *text = NULL;
        if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, SDDL_REVISION_1,
                     DACL_SECURITY_INFORMATION, &text, NULL)) return (int)GetLastError();
        wprintf(L"%ls\n", text);
        LocalFree(text); LocalFree(descriptor);
        return 0;
    }
    if (!wcscmp(argv[1], L"write-delete")) {
        int error = write_file(argv[2]);
        if (error) return error;
        return DeleteFileW(argv[2]) ? 0 : (int)GetLastError();
    }
    if (!wcscmp(argv[1], L"change-acl")) {
        HANDLE file = CreateFileW(argv[2], WRITE_DAC, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (file == INVALID_HANDLE_VALUE) return (int)GetLastError();
        CloseHandle(file);
        return 0;
    }
    if (!wcscmp(argv[1], L"write")) return write_file(argv[2]);
    if (!wcscmp(argv[1], L"read")) {
        HANDLE file = CreateFileW(argv[2], GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (file == INVALID_HANDLE_VALUE) return (int)GetLastError();
        CloseHandle(file);
        return 0;
    }
    if (!wcscmp(argv[1], L"delete")) return DeleteFileW(argv[2]) ? 0 : (int)GetLastError();
    if (!wcscmp(argv[1], L"rename") && argc == 4)
        return MoveFileW(argv[2], argv[3]) ? 0 : (int)GetLastError();
    if (!wcscmp(argv[1], L"connect")) {
        WSADATA data;
        if (WSAStartup(MAKEWORD(2, 2), &data)) return 99;
        SOCKET socket = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
        if (socket == INVALID_SOCKET) {
            int error = WSAGetLastError();
            fprintf(stderr, "WSASocketW error %d\n", error);
            return error == WSAEACCES ? ERROR_ACCESS_DENIED : 99;
        }
        struct sockaddr_in address;
        ZeroMemory(&address, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons((u_short)_wtoi(argv[2]));
        u_long nonblocking = 1;
        if (ioctlsocket(socket, FIONBIO, &nonblocking)) return 99;
        int code = connect(socket, (struct sockaddr *)&address, sizeof(address)) ? WSAGetLastError() : 0;
        if (code == WSAEWOULDBLOCK) {
            fd_set writable, errors;
            FD_ZERO(&writable); FD_SET(socket, &writable);
            FD_ZERO(&errors); FD_SET(socket, &errors);
            struct timeval deadline = {2, 0};
            int ready = select(0, NULL, &writable, &errors, &deadline);
            if (ready == 0) code = WSAETIMEDOUT;
            else if (ready == SOCKET_ERROR) code = WSAGetLastError();
            else {
                int size = sizeof(code);
                if (getsockopt(socket, SOL_SOCKET, SO_ERROR, (char *)&code, &size)) code = WSAGetLastError();
            }
        }
        closesocket(socket);
        WSACleanup();
        if (code) fprintf(stderr, "connect error %d\n", code);
        return code == WSAEACCES || code == WSAETIMEDOUT ? ERROR_ACCESS_DENIED : (code ? 99 : 0);
    }
    if (!wcscmp(argv[1], L"delayed-write")) { Sleep(1500); return write_file(argv[2]); }
    if (!wcscmp(argv[1], L"spawn") || !wcscmp(argv[1], L"spawn-exit")) {
        wchar_t executable[32768], line[32768];
        if (!GetModuleFileNameW(NULL, executable, 32768)) return 99;
        if (swprintf(line, 32768, L"\"%ls\" delayed-write \"%ls\"", executable, argv[2]) < 0) return 99;
        STARTUPINFOW startup = {0}; PROCESS_INFORMATION process = {0};
        startup.cb = sizeof(startup);
        if (!CreateProcessW(executable, line, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                            NULL, NULL, &startup, &process)) return (int)GetLastError();
        CloseHandle(process.hThread); CloseHandle(process.hProcess);
        if (!wcscmp(argv[1], L"spawn")) Sleep(10000);
        return 0;
    }
    return 99;
}
