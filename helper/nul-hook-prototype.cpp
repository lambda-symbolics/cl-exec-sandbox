/* Experimental x64 compatibility client. AppContainer enforces access policy;
 * the ordinary-user helper brokers only Null opens and owned-handle path queries. */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <winternl.h>
#include <wchar.h>
#include <string.h>
#include <stdio.h>
#include <vector>
#include "detours.h"
#include "nul-protocol.h"

static const GUID payload_id = {0x96c7a064, 0x183a, 0x47c3, {0xa2,0xc1,0x4d,0xf2,0x2b,0xe7,0x67,0x93}};

static BOOL inject_null(HANDLE process, const broker_payload *payload, const char *dll) {
    if (!DetourCopyPayloadToProcess(process, payload_id, payload, sizeof(*payload))) return FALSE;
    const char *libraries[] = {dll};
    return DetourUpdateProcessWithDll(process, libraries, 1);
}

#ifndef CL_EXEC_SANDBOX_NULL_DLL
static BOOL prototype_dll_name(HMODULE module, char *result, size_t capacity) {
    char option[2];
    if (GetEnvironmentVariableA("CL_EXEC_SANDBOX_NULL_BASENAME", option, sizeof(option)) == 1 &&
        option[0] == '1') return strcpy_s(result, capacity, "cl-exec-sandbox-null.dll") == 0;
    wchar_t path[32768];
    DWORD length = GetModuleFileNameW(module, path, 32768);
    if (!length || length >= 32768) return FALSE;
    wchar_t *leaf = wcsrchr(path, L'\\');
    if (!leaf) { SetLastError(ERROR_BAD_PATHNAME); return FALSE; }
    if (wcscpy_s(leaf + 1, 32768 - (size_t)(leaf + 1 - path), L"cl-exec-sandbox-null.dll")) {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return FALSE;
    }
    for (size_t i = 0; i < capacity; ++i) {
        if (path[i] > 127) { SetLastError(ERROR_NO_UNICODE_TRANSLATION); return FALSE; }
        result[i] = (char)path[i];
        if (!path[i]) return TRUE;
    }
    SetLastError(ERROR_FILENAME_EXCED_RANGE);
    return FALSE;
}

extern "C" const broker_payload *sandbox_broker_endpoint(void);

/* A random logon-local DOS alias permits an ASCII import name for a Unicode
 * installation directory without depending on PATH or 8.3 name generation. */
static BOOL alias_library(const wchar_t *profile, char *result, size_t capacity) {
    wchar_t directory[32768];
    DWORD length = GetModuleFileNameW(NULL, directory, 32768);
    if (!length || length >= 32768) return FALSE;
    wchar_t *leaf = wcsrchr(directory, L'\\');
    if (!leaf) { SetLastError(ERROR_BAD_PATHNAME); return FALSE; }
    *leaf = 0;
    wchar_t existing[32768];
    if (QueryDosDeviceW(profile, existing, 32768)) { SetLastError(ERROR_ALREADY_EXISTS); return FALSE; }
    if (GetLastError() != ERROR_FILE_NOT_FOUND) return FALSE;
    if (!DefineDosDeviceW(DDD_NO_BROADCAST_SYSTEM, profile, directory)) return FALSE;
    char ascii_profile[64];
    size_t i;
    for (i = 0; profile[i] && i + 1 < sizeof(ascii_profile); ++i) {
        if (profile[i] > 127) { SetLastError(ERROR_NO_UNICODE_TRANSLATION); return FALSE; }
        ascii_profile[i] = static_cast<char>(profile[i]);
    }
    ascii_profile[i] = 0;
    return sprintf_s(result, capacity, "\\\\?\\%s\\cl-exec-sandbox-null.dll", ascii_profile) > 0;
}

extern "C" BOOL sandbox_remove_null_alias(const wchar_t *profile) {
    wchar_t target[32768];
    if (!QueryDosDeviceW(profile, target, 32768)) return GetLastError() == ERROR_FILE_NOT_FOUND;
    return DefineDosDeviceW(DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE |
                            DDD_RAW_TARGET_PATH | DDD_NO_BROADCAST_SYSTEM, profile, target);
}

extern "C" BOOL sandbox_inject_null(HANDLE process, const wchar_t *profile) {
    broker_payload payload = *sandbox_broker_endpoint();
    char option[2];
    BOOL alias = GetEnvironmentVariableA("CL_EXEC_SANDBOX_NULL_ALIAS", option, sizeof(option)) == 1 && option[0] == '1';
    if (alias) {
        if (!alias_library(profile, payload.library, sizeof(payload.library))) return FALSE;
    } else if (!prototype_dll_name(NULL, payload.library, sizeof(payload.library))) return FALSE;
    return inject_null(process, &payload, payload.library);
}
#else
static broker_payload endpoint;
static char dll_path[32768];
static decltype(&NtCreateFile) real_create_file = NtCreateFile;
typedef NTSTATUS (NTAPI *open_file_type)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                        PIO_STATUS_BLOCK, ULONG, ULONG);
static open_file_type real_open_file;
static decltype(&CreateProcessW) real_create_process_w = CreateProcessW;
static decltype(&CreateProcessA) real_create_process_a = CreateProcessA;
static decltype(&GetFinalPathNameByHandleW) real_final_path = GetFinalPathNameByHandleW;

static bool transfer(HANDLE pipe, void *buffer, DWORD size, bool writing) {
    BYTE *cursor = static_cast<BYTE *>(buffer);
    OVERLAPPED operation = {};
    operation.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!operation.hEvent) return false;
    bool ok = true;
    while (size && ok) {
        ResetEvent(operation.hEvent);
        DWORD bytes = 0;
        BOOL started = writing ? WriteFile(pipe, cursor, size, NULL, &operation)
                               : ReadFile(pipe, cursor, size, NULL, &operation);
        if (!started && GetLastError() != ERROR_IO_PENDING) { ok = false; break; }
        if (!started && WaitForSingleObject(operation.hEvent, broker_timeout) != WAIT_OBJECT_0) {
            CancelIoEx(pipe, &operation);
            GetOverlappedResult(pipe, &operation, &bytes, TRUE);
            ok = false;
            break;
        }
        ok = GetOverlappedResult(pipe, &operation, &bytes, FALSE) && bytes != 0;
        if (ok) { cursor += bytes; size -= bytes; }
    }
    CloseHandle(operation.hEvent);
    return ok;
}

static bool trace_failure(const char *stage, DWORD error) {
    static LONG count;
    if (InterlockedIncrement(&count) <= 24) {
        char line[256];
        int length = sprintf_s(line, sizeof(line), "BROKER client stage=%s error=%lu\n", stage, error);
        DWORD written;
        if (length > 0) WriteFile(GetStdHandle(STD_ERROR_HANDLE), line, static_cast<DWORD>(length), &written, NULL);
    }
    SetLastError(error);
    return false;
}

static bool broker_call(broker_request *request, const void *extra, broker_response *response,
                        std::vector<BYTE> *output) {
    request->magic = broker_magic;
    request->version = broker_version;
    HANDLE pipe = INVALID_HANDLE_VALUE;
    ULONGLONG deadline = GetTickCount64() + broker_timeout;
    do {
        pipe = CreateFileW(endpoint.pipe, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                           FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
        if (pipe != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_PIPE_BUSY) return trace_failure("pipe-open", GetLastError());
        WaitNamedPipeW(endpoint.pipe, 100);
    } while (GetTickCount64() < deadline);
    if (pipe == INVALID_HANDLE_VALUE) return false;
    ULONG server = 0;
    bool ok = GetNamedPipeServerProcessId(pipe, &server) && server == endpoint.process_id;
    if (!ok) trace_failure("server-pid", GetLastError());
    if (ok) ok = transfer(pipe, request, sizeof(*request), true) &&
                 (!request->extra_size || transfer(pipe, const_cast<void *>(extra), request->extra_size, true)) &&
                 transfer(pipe, response, sizeof(*response), false);
    if (ok) ok = response->magic == broker_magic && response->version == broker_version &&
                 response->extra_size <= broker_max_extra;
    if (ok) {
        output->resize(response->extra_size);
        ok = output->empty() || transfer(pipe, output->data(), response->extra_size, false);
    }
    BYTE acknowledged = 1;
    if (ok) ok = transfer(pipe, &acknowledged, 1, true);
    if (!ok) trace_failure("exchange", GetLastError());
    CloseHandle(pipe);
    return ok;
}


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

static NTSTATUS broker_null(broker_request *request, PHANDLE file, POBJECT_ATTRIBUTES attributes,
                            PIO_STATUS_BLOCK status, const void *extra) {
    if (attributes->SecurityDescriptor || request->extra_size > broker_max_extra) {
        trace_failure(attributes->SecurityDescriptor ? "security-descriptor" : "ea-size", ERROR_NOT_SUPPORTED);
        return static_cast<NTSTATUS>(0xc0000022L);
    }
    request->object_attributes = attributes->Attributes;
    if (attributes->SecurityQualityOfService) {
        const SECURITY_QUALITY_OF_SERVICE *qos =
            static_cast<const SECURITY_QUALITY_OF_SERVICE *>(attributes->SecurityQualityOfService);
        request->qos_present = 1;
        request->qos_length = qos->Length;
        request->qos_impersonation = qos->ImpersonationLevel;
        request->qos_flags = qos->ContextTrackingMode | (static_cast<uint32_t>(qos->EffectiveOnly) << 8);
    }
    broker_response response = {};
    std::vector<BYTE> output;
    if (!broker_call(request, extra, &response, &output) || response.error || !output.empty()) {
        trace_failure("null-response", response.error);
        return static_cast<NTSTATUS>(0xc0000022L);
    }
    if (response.status < 0) trace_failure("native-null", static_cast<DWORD>(response.status));
    if (response.status >= 0) {
        *file = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(response.handle));
        status->Status = response.io_status;
        status->Information = static_cast<ULONG_PTR>(response.information);
    }
    return response.status;
}

static DWORD WINAPI hook_final_path(HANDLE file, LPWSTR buffer, DWORD capacity, DWORD flags) {
    DWORD result = real_final_path(file, buffer, capacity, flags);
    if (result || GetLastError() != ERROR_ACCESS_DENIED) return result;
    DWORD original_error = GetLastError();
    broker_request request = {};
    request.operation = broker_final_path;
    request.handle = reinterpret_cast<ULONG_PTR>(file);
    request.flags = flags;
    broker_response response = {};
    std::vector<BYTE> output;
    if (!broker_call(&request, NULL, &response, &output)) { SetLastError(original_error); return 0; }
    if (response.error) { SetLastError(response.error); return 0; }
    size_t length = static_cast<size_t>(response.information);
    if (length >= 32768 || output.size() != (length + 1) * sizeof(wchar_t) ||
        reinterpret_cast<const wchar_t *>(output.data())[length] != 0) {
        SetLastError(ERROR_INVALID_DATA);
        return 0;
    }
    if (capacity <= length) return static_cast<DWORD>(length + 1);
    memcpy(buffer, output.data(), output.size());
    return static_cast<DWORD>(length);
}

static NTSTATUS NTAPI hook_create_file(PHANDLE file, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes,
    PIO_STATUS_BLOCK status, PLARGE_INTEGER allocation, ULONG file_attributes, ULONG share,
    ULONG disposition, ULONG options, PVOID extended, ULONG extended_length) {
    NTSTATUS result = real_create_file(file, access, attributes, status, allocation,
                                      file_attributes, share, disposition, options, extended, extended_length);
    if (result == static_cast<NTSTATUS>(0xc0000022L) && null_name(attributes)) {
        broker_request request = {};
        request.operation = broker_create_null;
        request.access = access;
        request.share = share;
        request.disposition = disposition;
        request.options = options;
        request.file_attributes = file_attributes;
        request.has_allocation = allocation != NULL;
        request.allocation = allocation ? allocation->QuadPart : 0;
        request.extra_size = extended_length;
        return broker_null(&request, file, attributes, status, extended);
    }
    return result;
}

static NTSTATUS NTAPI hook_open_file(PHANDLE file, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes,
                                     PIO_STATUS_BLOCK status, ULONG share, ULONG options) {
    NTSTATUS result = real_open_file(file, access, attributes, status, share, options);
    if (result == static_cast<NTSTATUS>(0xc0000022L) && null_name(attributes)) {
        broker_request request = {};
        request.operation = broker_open_null;
        request.access = access;
        request.share = share;
        request.options = options;
        return broker_null(&request, file, attributes, status, NULL);
    }
    return result;
}

static BOOL finish_child(BOOL created, DWORD flags, LPPROCESS_INFORMATION process) {
    if (!created) return FALSE;
    if (!inject_null(process->hProcess, &endpoint, dll_path) ||
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
    (void)module;
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    DetourRestoreAfterWith();
    DWORD bytes = 0;
    broker_payload *payload = (broker_payload *)DetourFindPayloadEx(payload_id, &bytes);
    if (!payload || bytes != sizeof(*payload)) return FALSE;
    endpoint = *payload;
    if (!memchr(endpoint.library, 0, sizeof(endpoint.library)) ||
        strcpy_s(dll_path, sizeof(dll_path), endpoint.library)) return FALSE;
    FARPROC open_address = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenFile");
    static_assert(sizeof(open_address) == sizeof(real_open_file), "Native function pointer size");
    memcpy(&real_open_file, &open_address, sizeof(real_open_file));
    if (!real_open_file) return FALSE;
    if (DetourTransactionBegin() != NO_ERROR) return FALSE;
    LONG error = DetourUpdateThread(GetCurrentThread());
    if (!error) error = DetourAttach(&real_create_file, hook_create_file);
    if (!error) error = DetourAttach(&real_open_file, hook_open_file);
    if (!error) error = DetourAttach(&real_final_path, hook_final_path);
    if (!error) error = DetourAttach(&real_create_process_w, hook_create_process_w);
    if (!error) error = DetourAttach(&real_create_process_a, hook_create_process_a);
    if (error) { DetourTransactionAbort(); return FALSE; }
    return DetourTransactionCommit() == NO_ERROR;
}
#endif
