#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <windows.h>
#include <winternl.h>
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

static int probe_nul_descendant(BOOL clean_environment) {
    wchar_t executable[32768], line[32768];
    if (!GetModuleFileNameW(NULL, executable, sizeof(executable) / sizeof(*executable))) return 99;
    if (swprintf(line, sizeof(line) / sizeof(*line), L"\"%ls\" nul", executable) < 0) return 99;
    wchar_t environment[32768] = {0}, windows[32768];
    if (clean_environment) {
        if (!GetWindowsDirectoryW(windows, 32768) ||
            swprintf(environment, 32767, L"SystemRoot=%ls", windows) < 0) return 99;
    }
    STARTUPINFOW startup = {0}; PROCESS_INFORMATION process = {0};
    startup.cb = sizeof(startup);
    if (!CreateProcessW(executable, line, NULL, NULL, FALSE, CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                        clean_environment ? environment : NULL, NULL, &startup, &process)) return (int)GetLastError();
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

typedef LONG NTSTATUS;
typedef struct _UNICODE_STRING_NATIVE { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } UNICODE_STRING_NATIVE;
typedef struct _OBJECT_ATTRIBUTES_NATIVE { ULONG Length; HANDLE RootDirectory; UNICODE_STRING_NATIVE *ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES_NATIVE;
typedef struct _IO_STATUS_BLOCK_NATIVE { union { NTSTATUS Status; PVOID Pointer; } DUMMYUNIONNAME; ULONG_PTR Information; } IO_STATUS_BLOCK_NATIVE;
typedef NTSTATUS (NTAPI *nt_create_file_function)(PHANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES_NATIVE *, IO_STATUS_BLOCK_NATIVE *, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *nt_open_file_function)(PHANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES_NATIVE *, IO_STATUS_BLOCK_NATIVE *, ULONG, ULONG);
typedef NTSTATUS (NTAPI *nt_query_information_file_function)(HANDLE, IO_STATUS_BLOCK_NATIVE *, PVOID, ULONG, ULONG);

static void native_unicode_string(UNICODE_STRING_NATIVE *string, wchar_t *text) {
    string->Length = (USHORT)(wcslen(text) * sizeof(wchar_t));
    string->MaximumLength = string->Length;
    string->Buffer = text;
}

static NTSTATUS native_open(const wchar_t *name, ACCESS_MASK access, ULONG share,
                            ULONG disposition, ULONG options, HANDLE *result,
                            int use_open) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    FARPROC create_address = GetProcAddress(ntdll, "NtCreateFile");
    FARPROC open_address = GetProcAddress(ntdll, "NtOpenFile");
    nt_create_file_function create_file;
    nt_open_file_function open_file;
    memcpy(&create_file, &create_address, sizeof(create_file));
    memcpy(&open_file, &open_address, sizeof(open_file));
    UNICODE_STRING_NATIVE unicode;
    OBJECT_ATTRIBUTES_NATIVE attributes;
    IO_STATUS_BLOCK_NATIVE io;
    native_unicode_string(&unicode, (wchar_t *)name);
    ZeroMemory(&attributes, sizeof(attributes));
    attributes.Length = sizeof(attributes);
    attributes.ObjectName = &unicode;
    ZeroMemory(&io, sizeof(io));
    if (!create_file || !open_file) return (NTSTATUS)0xC0000002L;
    if (use_open) return open_file(result, access, &attributes, &io, share, options);
    return create_file(result, access, &attributes, &io, NULL, FILE_ATTRIBUTE_NORMAL,
                       share, disposition, options, NULL, 0);
}

static int native_async_read(HANDLE file, const wchar_t *label) {
    OVERLAPPED overlapped;
    char byte = 0;
    DWORD count = 77, error;
    ZeroMemory(&overlapped, sizeof(overlapped));
    overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!overlapped.hEvent) return (int)GetLastError();
    BOOL immediate = ReadFile(file, &byte, 1, &count, &overlapped);
    if (!immediate) {
        error = GetLastError();
        if (error != ERROR_IO_PENDING) {
            wprintf(L"NUL semantics async label=%ls error=%lu\n", label, error);
            CloseHandle(overlapped.hEvent);
            return (int)error;
        }
        if (!GetOverlappedResult(file, &overlapped, &count, TRUE)) {
            error = GetLastError();
            CloseHandle(overlapped.hEvent);
            return (int)error;
        }
    }
    wprintf(L"NUL semantics async label=%ls immediate=%d bytes=%lu\n", label,
            immediate ? 1 : 0, count);
    CloseHandle(overlapped.hEvent);
    return count == 0 ? 0 : ERROR_INVALID_DATA;
}

static void native_matrix_open(const wchar_t *label, ACCESS_MASK access, ULONG share,
                               ULONG disposition, ULONG options) {
    HANDLE file = INVALID_HANDLE_VALUE;
    NTSTATUS status = native_open(L"\\Device\\Null", access, share, disposition,
                                  options, &file, 0);
    wprintf(L"NUL semantics matrix label=%ls access=0x%08lx share=0x%08lx disposition=%lu options=0x%08lx status=0x%08lx\n",
            label, (ULONG)access, share, disposition, options, (ULONG)status);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
}

static int native_iocp_read(HANDLE file, ULONG_PTR key, const wchar_t *label) {
    HANDLE port = CreateIoCompletionPort(file, NULL, key, 1);
    OVERLAPPED overlapped;
    char byte = 0;
    DWORD bytes = 77, error;
    ULONG_PTR completion_key = 0;
    LPOVERLAPPED completed = NULL;
    BOOL immediate;
    if (!port) return (int)GetLastError();
    ZeroMemory(&overlapped, sizeof(overlapped));
    immediate = ReadFile(file, &byte, 1, &bytes, &overlapped);
    if (!immediate) {
        error = GetLastError();
        if (error != ERROR_IO_PENDING) {
            CloseHandle(port);
            return (int)error;
        }
        if (!GetQueuedCompletionStatus(port, &bytes, &completion_key, &completed, 2000)) {
            error = GetLastError();
            CloseHandle(port);
            return (int)error;
        }
        if (completed != &overlapped || completion_key != key) {
            CloseHandle(port);
            return ERROR_INVALID_DATA;
        }
    }
    wprintf(L"NUL semantics iocp label=%ls key=%llu immediate=%d bytes=%lu\n",
            label, (unsigned long long)key, immediate ? 1 : 0, bytes);
    CloseHandle(port);
    return bytes == 0 ? 0 : ERROR_INVALID_DATA;
}

static int probe_nul_semantics(void) {
    const ACCESS_MASK access = GENERIC_READ | GENERIC_WRITE;
    const ULONG share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    const ULONG options = FILE_NON_DIRECTORY_FILE;
    HANDLE synchronous = INVALID_HANDLE_VALUE, asynchronous = INVALID_HANDLE_VALUE;
    HANDLE opened = INVALID_HANDLE_VALUE;
    NTSTATUS status;
    int result = 0;
    native_matrix_open(L"read-open", GENERIC_READ, share, FILE_OPEN, options);
    native_matrix_open(L"write-open-if", GENERIC_WRITE, share, FILE_OPEN_IF, options);
    native_matrix_open(L"read-write-sync", access, share, FILE_OPEN, options | FILE_SYNCHRONOUS_IO_NONALERT);
    native_matrix_open(L"exclusive-share", access, 0, FILE_OPEN, options);
    status = native_open(L"\\Device\\Null", access, share, FILE_OPEN,
                         options | FILE_SYNCHRONOUS_IO_NONALERT, &synchronous, 0);
    wprintf(L"NUL semantics NtCreateFile synchronous status=0x%08lx\n", (ULONG)status);
    if (status < 0) result = 1;
    status = native_open(L"\\Device\\Null", access, share, FILE_OPEN,
                         options, &asynchronous, 0);
    wprintf(L"NUL semantics NtCreateFile asynchronous status=0x%08lx\n", (ULONG)status);
    if (status < 0) result = 1;
    status = native_open(L"\\??\\NUL", access, share, FILE_OPEN, options,
                         &opened, 1);
    wprintf(L"NUL semantics NtOpenFile status=0x%08lx\n", (ULONG)status);
    if (status < 0) result = 1;
    if (synchronous != INVALID_HANDLE_VALUE && asynchronous != INVALID_HANDLE_VALUE &&
        synchronous == asynchronous) {
        wprintf(L"NUL semantics fresh-handle mismatch\n");
        result = 1;
    } else wprintf(L"NUL semantics fresh-handles=independent\n");
    if (asynchronous != INVALID_HANDLE_VALUE && native_async_read(asynchronous, L"first")) result = 1;
    if (opened != INVALID_HANDLE_VALUE && native_async_read(opened, L"second")) result = 1;
    if (asynchronous != INVALID_HANDLE_VALUE && native_iocp_read(asynchronous, 0xA5, L"first")) result = 1;
    if (opened != INVALID_HANDLE_VALUE && native_iocp_read(opened, 0x5A, L"second")) result = 1;
    if (synchronous != INVALID_HANDLE_VALUE) {
        IO_STATUS_BLOCK_NATIVE io;
        FARPROC query_address = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationFile");
        nt_query_information_file_function query;
        memcpy(&query, &query_address, sizeof(query));
        ULONG mode = 0;
        ZeroMemory(&io, sizeof(io));
        if (!query || query(synchronous, &io, &mode, sizeof(mode), 16) < 0 ||
            !(mode & FILE_SYNCHRONOUS_IO_NONALERT)) {
            wprintf(L"NUL semantics synchronous-mode mismatch mode=0x%08lx\n", mode);
            result = 1;
        } else wprintf(L"NUL semantics synchronous-mode=0x%08lx\n", mode);
    }
    if (opened != INVALID_HANDLE_VALUE) CloseHandle(opened);
    if (asynchronous != INVALID_HANDLE_VALUE) CloseHandle(asynchronous);
    if (synchronous != INVALID_HANDLE_VALUE) CloseHandle(synchronous);
    return result;
}

static int probe_final_path_semantics(void) {
    wchar_t cwd[32768], path[32768], output[2];
    HANDLE file;
    DWORD length, error;
    int result = 0;
    if (!GetCurrentDirectoryW(32768, cwd)) return (int)GetLastError();
    if (swprintf(path, 32768, L"%ls\\autolith-final-path-%lu.tmp", cwd,
                 GetCurrentProcessId()) < 0) return ERROR_INSUFFICIENT_BUFFER;
    file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (file == INVALID_HANDLE_VALUE) return (int)GetLastError();
    length = GetFinalPathNameByHandleW(file, output, 1, VOLUME_NAME_DOS | FILE_NAME_OPENED);
    error = length ? 0 : GetLastError();
    wprintf(L"FINAL path sizing flags=%lu result=%lu error=%lu\n",
            VOLUME_NAME_DOS | FILE_NAME_OPENED, length, error);
    if (!length || length < 2) result = 1;
    const DWORD flags[] = {VOLUME_NAME_DOS, VOLUME_NAME_NT,
                           VOLUME_NAME_DOS | FILE_NAME_OPENED,
                           VOLUME_NAME_NT | FILE_NAME_OPENED};
    for (unsigned i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i) {
        DWORD required = GetFinalPathNameByHandleW(file, NULL, 0, flags[i]);
        if (!required) { result = 1; continue; }
        wchar_t *buffer = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                               required * sizeof(wchar_t));
        DWORD actual;
        if (!buffer) { result = ERROR_NOT_ENOUGH_MEMORY; break; }
        actual = GetFinalPathNameByHandleW(file, buffer, required, flags[i]);
        wprintf(L"FINAL path flags=%lu result=%lu text=%ls\n", flags[i], actual, buffer);
        if (!actual || actual >= required || actual + 1 != required) result = 1;
        HeapFree(GetProcessHeap(), 0, buffer);
    }
    SetLastError(0);
    length = GetFinalPathNameByHandleW(INVALID_HANDLE_VALUE, output, 1, VOLUME_NAME_DOS);
    error = GetLastError();
    wprintf(L"FINAL invalid-handle result=%lu error=%lu\n", length, error);
    if (length || error != ERROR_INVALID_HANDLE) result = 1;
    CloseHandle(file);
    DeleteFileW(path);
    return result;
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
    if (!wcscmp(argv[1], L"nul-descendant")) return probe_nul_descendant(FALSE);
    if (!wcscmp(argv[1], L"nul-descendant-clean-environment")) return probe_nul_descendant(TRUE);
    if (!wcscmp(argv[1], L"nul-security")) return probe_nul_security();
    if (!wcscmp(argv[1], L"cwd")) return probe_cwd();
    if (!wcscmp(argv[1], L"nul-semantics")) return probe_nul_semantics();
    if (!wcscmp(argv[1], L"final-path-semantics")) return probe_final_path_semantics();

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
