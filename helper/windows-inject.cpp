/* Inject only the adjacent, architecture-matching compatibility DLL. */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <wchar.h>
#include <string.h>
#include <stdio.h>
#include <vector>
#include <new>
#include "windows-inject.h"

static BOOL library_path(const broker_payload *payload, bool wow64, char *path, size_t capacity) {
    if (!memchr(payload->library, 0, sizeof(payload->library)) ||
        strcpy_s(path, capacity, payload->library)) return FALSE;
    size_t length = strlen(path);
    if (length < 6 || (strcmp(path + length - 6, "64.dll") &&
                       strcmp(path + length - 6, "32.dll"))) {
        SetLastError(ERROR_BAD_PATHNAME);
        return FALSE;
    }
    memcpy(path + length - 6, wow64 ? "32" : "64", 2);
    return TRUE;
}

/* Use the public Detours helper payload, but resolve Windows independently of
 * the caller's environment and bound the helper lifetime. The target has not
 * executed application code. Every auxiliary process joins the invocation Job. */
static BOOL inject_via_helper(HANDLE process, const char *library, HANDLE job,
                              PDETOUR_CREATE_PROCESS_ROUTINEW create_process) {
    wchar_t executable[MAX_PATH], command[1024];
    UINT length = GetWindowsDirectoryW(executable, MAX_PATH);
    if (!length || length >= MAX_PATH) return FALSE;
#ifdef _WIN64
    const wchar_t *suffix = L"\\SysWOW64\\rundll32.exe";
#else
    const wchar_t *suffix = L"\\Sysnative\\rundll32.exe";
#endif
    if (wcscat_s(executable, MAX_PATH, suffix)) { SetLastError(ERROR_BAD_PATHNAME); return FALSE; }
    wchar_t wide_library[512];
    size_t count = strlen(library);
    if (count >= 512) { SetLastError(ERROR_FILENAME_EXCED_RANGE); return FALSE; }
    for (size_t i = 0; i <= count; ++i) {
        if (static_cast<unsigned char>(library[i]) > 127) { SetLastError(ERROR_NO_UNICODE_TRANSLATION); return FALSE; }
        wide_library[i] = static_cast<unsigned char>(library[i]);
    }
    if (swprintf_s(command, 1024, L"rundll32.exe \"%s\",#1", wide_library) < 0) return FALSE;
    std::vector<BYTE> storage(sizeof(DETOUR_EXE_HELPER) + count + 1, 0);
    DETOUR_EXE_HELPER *payload = reinterpret_cast<DETOUR_EXE_HELPER *>(storage.data());
    payload->cb = static_cast<DWORD>(storage.size());
    payload->pid = GetProcessId(process);
    payload->nDlls = 1;
    memcpy(payload->rDlls, library, count + 1);
    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION helper = {};
    if (!create_process(executable, command, NULL, NULL, FALSE, CREATE_SUSPENDED,
                        NULL, NULL, &startup, &helper)) return FALSE;
    BOOL ok = (!job || AssignProcessToJobObject(job, helper.hProcess)) &&
              DetourCopyPayloadToProcess(helper.hProcess, DETOUR_EXE_HELPER_GUID,
                                        payload, payload->cb) &&
              ResumeThread(helper.hThread) != static_cast<DWORD>(-1);
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (ok) {
        DWORD result = WaitForSingleObject(helper.hProcess, broker_timeout);
        DWORD status = ERROR_DLL_INIT_FAILED;
        if (result == WAIT_OBJECT_0 && GetExitCodeProcess(helper.hProcess, &status)) {
            ok = status == 0;
            if (!ok) error = status;
        } else {
            ok = FALSE;
            error = result == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
        }
    }
    if (!ok) {
        TerminateProcess(helper.hProcess, 125);
        /* The invocation Job owns any process still terminating at the deadline. */
        if (WaitForSingleObject(helper.hProcess, broker_timeout) != WAIT_OBJECT_0)
            error = ERROR_TIMEOUT;
    }
    CloseHandle(helper.hThread);
    CloseHandle(helper.hProcess);
    SetLastError(error);
    return ok;
}

BOOL sandbox_inject_process(HANDLE process, const broker_payload *payload, HANDLE job,
                            PDETOUR_CREATE_PROCESS_ROUTINEW create_process) {
    try {
        SYSTEM_INFO host = {};
        GetNativeSystemInfo(&host);
        if (host.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) {
            SetLastError(ERROR_NOT_SUPPORTED);
            return FALSE;
        }
        BOOL wow64 = FALSE;
        if (!IsWow64Process(process, &wow64)) return FALSE;
        char library[32768];
        if (!library_path(payload, wow64 != FALSE, library, sizeof(library)) ||
            !DetourCopyPayloadToProcess(process, sandbox_payload_id, payload, sizeof(*payload))) return FALSE;
        if ((sizeof(void *) == 4) != (wow64 != FALSE))
            return inject_via_helper(process, library, job, create_process);
        const char *libraries[] = {library};
        return DetourUpdateProcessWithDll(process, libraries, 1);
    } catch (const std::bad_alloc &) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
}

#ifndef CL_EXEC_SANDBOX_NULL_DLL
extern "C" const broker_payload *sandbox_broker_endpoint(void);

static BOOL alias_target(wchar_t *target, size_t capacity) {
    wchar_t directory[32768];
    DWORD length = GetModuleFileNameW(NULL, directory, 32768);
    if (!length || length >= 32768) return FALSE;
    wchar_t *leaf = wcsrchr(directory, L'\\');
    if (!leaf) { SetLastError(ERROR_BAD_PATHNAME); return FALSE; }
    *leaf = 0;
    if (!wcsncmp(directory, L"\\\\", 2) && wcsncmp(directory, L"\\\\?\\", 4))
        return swprintf_s(target, capacity, L"\\??\\UNC\\%s", directory + 2) > 0;
    const wchar_t *path = wcsncmp(directory, L"\\\\?\\", 4) ? directory : directory + 4;
    return swprintf_s(target, capacity, L"\\??\\%s", path) > 0;
}

extern "C" BOOL sandbox_remove_null_alias(const wchar_t *profile) {
    wchar_t target[32768];
    if (!alias_target(target, 32768)) return FALSE;
    if (DefineDosDeviceW(DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE |
                         DDD_RAW_TARGET_PATH | DDD_NO_BROADCAST_SYSTEM, profile, target)) return TRUE;
    return GetLastError() == ERROR_FILE_NOT_FOUND;
}

extern "C" BOOL sandbox_inject_null(HANDLE process, HANDLE job, const wchar_t *profile) {
    broker_payload payload = *sandbox_broker_endpoint();
    char ascii_profile[64];
    size_t length = wcslen(profile);
    if (length >= sizeof(ascii_profile)) { SetLastError(ERROR_INVALID_NAME); return FALSE; }
    for (size_t i = 0; i <= length; ++i) {
        if (profile[i] > 127) { SetLastError(ERROR_INVALID_NAME); return FALSE; }
        ascii_profile[i] = static_cast<char>(profile[i]);
    }
    wchar_t target[32768], existing[32768];
    if (!alias_target(target, 32768)) return FALSE;
    if (QueryDosDeviceW(profile, existing, 32768)) { SetLastError(ERROR_ALREADY_EXISTS); return FALSE; }
    if (GetLastError() != ERROR_FILE_NOT_FOUND ||
        !DefineDosDeviceW(DDD_RAW_TARGET_PATH | DDD_NO_BROADCAST_SYSTEM, profile, target)) return FALSE;
    if (sprintf_s(payload.library, sizeof(payload.library),
                  "\\\\?\\%s\\cl-exec-sandbox-compat64.dll", ascii_profile) < 0) return FALSE;
    return sandbox_inject_process(process, &payload, job, CreateProcessW);
}
#endif
