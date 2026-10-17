/* Experimental x64 compatibility hook. AppContainer enforces all access policy.
 * This experiment uses an ASCII fixture path for Detours' import-table API. */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <winternl.h>
#include <wchar.h>
#include <string.h>
#include "detours.h"

static const GUID payload_id = {0x96c7a064, 0x183a, 0x47c3, {0xa2,0xc1,0x4d,0xf2,0x2b,0xe7,0x67,0x93}};
struct null_payload { HANDLE handle; };

/* Duplicate explicitly, including when the target did not inherit handles. */
static BOOL inject_null(HANDLE process, HANDLE source, const char *dll) {
    null_payload payload = {};
    if (!DuplicateHandle(GetCurrentProcess(), source, process, &payload.handle,
                         0, FALSE, DUPLICATE_SAME_ACCESS)) return FALSE;
    if (!DetourCopyPayloadToProcess(process, payload_id, &payload, sizeof(payload))) return FALSE;
    const char *libraries[] = {dll};
    return DetourUpdateProcessWithDll(process, libraries, 1);
}

#ifndef CL_EXEC_SANDBOX_NULL_DLL
extern "C" BOOL sandbox_inject_null(HANDLE process) {
    wchar_t path[32768];
    DWORD length = GetModuleFileNameW(NULL, path, 32768);
    if (!length || length >= 32768) return FALSE;
    wchar_t *leaf = wcsrchr(path, L'\\');
    if (!leaf) { SetLastError(ERROR_BAD_PATHNAME); return FALSE; }
    if (wcscpy_s(leaf + 1, 32768 - (size_t)(leaf + 1 - path), L"cl-exec-sandbox-null.dll")) {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return FALSE;
    }
    char ascii[32768];
    for (size_t i = 0; ; ++i) {
        if (path[i] > 127) { SetLastError(ERROR_NO_UNICODE_TRANSLATION); return FALSE; }
        ascii[i] = (char)path[i];
        if (!path[i]) break;
    }
    HANDLE source = CreateFileW(L"\\\\?\\GLOBALROOT\\Device\\Null", GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (source == INVALID_HANDLE_VALUE) return FALSE;
    BOOL result = inject_null(process, source, ascii);
    DWORD error = GetLastError();
    CloseHandle(source);
    SetLastError(error);
    return result;
}
#else
static HANDLE null_handle;
static char dll_path[32768];
static decltype(&NtCreateFile) real_create_file = NtCreateFile;
typedef NTSTATUS (NTAPI *open_file_type)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                        PIO_STATUS_BLOCK, ULONG, ULONG);
static open_file_type real_open_file;
static decltype(&CreateProcessW) real_create_process_w = CreateProcessW;
static decltype(&CreateProcessA) real_create_process_a = CreateProcessA;

static BOOL null_name(POBJECT_ATTRIBUTES attributes) {
    if (!attributes || attributes->RootDirectory || !attributes->ObjectName) return FALSE;
    const UNICODE_STRING *name = attributes->ObjectName;
    static const wchar_t *names[] = {L"\\Device\\Null", L"\\??\\NUL", L"\\??\\GLOBALROOT\\Device\\Null"};
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        size_t count = wcslen(names[i]);
        if (name->Length == count * sizeof(wchar_t) &&
            !_wcsnicmp(name->Buffer, names[i], count)) return TRUE;
    }
    return FALSE;
}

static NTSTATUS duplicate_null(PHANDLE file, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes,
                               PIO_STATUS_BLOCK status) {
    GENERIC_MAPPING mapping = {FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
    MapGenericMask(&access, &mapping);
    if (!DuplicateHandle(GetCurrentProcess(), null_handle, GetCurrentProcess(), file, access,
                         (attributes->Attributes & OBJ_INHERIT) != 0, 0))
        return (NTSTATUS)0xc0000022L;
    status->Status = 0;
    status->Information = 1; /* FILE_OPENED */
    return 0;
}

static NTSTATUS NTAPI hook_create_file(PHANDLE file, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes,
    PIO_STATUS_BLOCK status, PLARGE_INTEGER allocation, ULONG file_attributes, ULONG share,
    ULONG disposition, ULONG options, PVOID extended, ULONG extended_length) {
    NTSTATUS result = real_create_file(file, access, attributes, status, allocation,
                                      file_attributes, share, disposition, options, extended, extended_length);
    if (result == (NTSTATUS)0xc0000022L && null_name(attributes))
        return duplicate_null(file, access, attributes, status);
    return result;
}

static NTSTATUS NTAPI hook_open_file(PHANDLE file, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes,
                                     PIO_STATUS_BLOCK status, ULONG share, ULONG options) {
    NTSTATUS result = real_open_file(file, access, attributes, status, share, options);
    if (result == (NTSTATUS)0xc0000022L && null_name(attributes))
        return duplicate_null(file, access, attributes, status);
    return result;
}

static BOOL finish_child(BOOL created, DWORD flags, LPPROCESS_INFORMATION process) {
    if (!created) return FALSE;
    if (!inject_null(process->hProcess, null_handle, dll_path) ||
        (!(flags & CREATE_SUSPENDED) && ResumeThread(process->hThread) == (DWORD)-1)) {
        DWORD error = GetLastError();
        TerminateProcess(process->hProcess, 125);
        WaitForSingleObject(process->hProcess, INFINITE);
        CloseHandle(process->hThread);
        CloseHandle(process->hProcess);
        ZeroMemory(process, sizeof(*process));
        SetLastError(error);
        return FALSE;
    }
    return TRUE;
}

static BOOL WINAPI hook_create_process_w(LPCWSTR application, LPWSTR line,
    LPSECURITY_ATTRIBUTES process_security, LPSECURITY_ATTRIBUTES thread_security, BOOL inherit,
    DWORD flags, LPVOID environment, LPCWSTR cwd, LPSTARTUPINFOW startup, LPPROCESS_INFORMATION process) {
    return finish_child(real_create_process_w(application, line, process_security, thread_security,
        inherit, flags | CREATE_SUSPENDED, environment, cwd, startup, process), flags, process);
}

static BOOL WINAPI hook_create_process_a(LPCSTR application, LPSTR line,
    LPSECURITY_ATTRIBUTES process_security, LPSECURITY_ATTRIBUTES thread_security, BOOL inherit,
    DWORD flags, LPVOID environment, LPCSTR cwd, LPSTARTUPINFOA startup, LPPROCESS_INFORMATION process) {
    return finish_child(real_create_process_a(application, line, process_security, thread_security,
        inherit, flags | CREATE_SUSPENDED, environment, cwd, startup, process), flags, process);
}

extern "C" __declspec(dllexport) void null_hook_marker(void) {}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    DetourRestoreAfterWith();
    DWORD bytes = 0;
    null_payload *payload = (null_payload *)DetourFindPayloadEx(payload_id, &bytes);
    if (!payload || bytes != sizeof(*payload)) return FALSE;
    null_handle = payload->handle;
    wchar_t path[32768];
    DWORD length = GetModuleFileNameW(module, path, 32768);
    if (!length || length >= 32768) return FALSE;
    for (DWORD i = 0; i <= length; ++i) {
        if (path[i] > 127) return FALSE;
        dll_path[i] = (char)path[i];
    }
    FARPROC open_address = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenFile");
    static_assert(sizeof(open_address) == sizeof(real_open_file), "Native function pointer size");
    memcpy(&real_open_file, &open_address, sizeof(real_open_file));
    if (!real_open_file) return FALSE;
    if (DetourTransactionBegin() != NO_ERROR) return FALSE;
    LONG error = DetourUpdateThread(GetCurrentThread());
    if (!error) error = DetourAttach(&real_create_file, hook_create_file);
    if (!error) error = DetourAttach(&real_open_file, hook_open_file);
    if (!error) error = DetourAttach(&real_create_process_w, hook_create_process_w);
    if (!error) error = DetourAttach(&real_create_process_a, hook_create_process_a);
    if (error) { DetourTransactionAbort(); return FALSE; }
    return DetourTransactionCommit() == NO_ERROR;
}
#endif
