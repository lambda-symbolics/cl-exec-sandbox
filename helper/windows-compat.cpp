/* AppContainer enforces access policy. The ordinary-user helper brokers
 * canonical Null opens and final paths on client-owned file handles. */
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

#include "windows-inject.h"
static broker_payload endpoint;
static decltype(&NtCreateFile) real_create_file = NtCreateFile;
typedef NTSTATUS (NTAPI *open_file_type)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                        PIO_STATUS_BLOCK, ULONG, ULONG);
static open_file_type real_open_file;
static decltype(&CreateProcessW) real_create_process_w = CreateProcessW;
static decltype(&CreateProcessA) real_create_process_a = CreateProcessA;
static decltype(&CreateProcessAsUserW) real_as_user_w = CreateProcessAsUserW;
static decltype(&CreateProcessAsUserA) real_as_user_a = CreateProcessAsUserA;
static decltype(&CreateProcessWithTokenW) real_with_token = CreateProcessWithTokenW;
static decltype(&CreateProcessWithLogonW) real_with_logon = CreateProcessWithLogonW;
static thread_local unsigned creation_depth;

struct process_creation_scope {
    bool outer;
    process_creation_scope() : outer(creation_depth++ == 0) {}
    ~process_creation_scope() { --creation_depth; }
};
static decltype(&GetFinalPathNameByHandleW) real_final_path = GetFinalPathNameByHandleW;
static decltype(&GetFinalPathNameByHandleA) real_final_path_a = GetFinalPathNameByHandleA;

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
#ifdef CL_EXEC_SANDBOX_DIAGNOSTIC
    static LONG count;
    if (InterlockedIncrement(&count) <= 24) {
        char line[256];
        int length = sprintf_s(line, sizeof(line), "BROKER client stage=%s error=%lu\n", stage, error);
        DWORD written;
        if (length > 0) WriteFile(GetStdHandle(STD_ERROR_HANDLE), line, static_cast<DWORD>(length), &written, NULL);
    }
#else
    (void)stage;
#endif
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
    if (response.handle > UINT32_MAX || response.information > UINTPTR_MAX) {
        trace_failure("null-width", ERROR_INVALID_DATA);
        return static_cast<NTSTATUS>(0xc0000022L);
    }
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
    if (response.information >= 32768) { SetLastError(ERROR_INVALID_DATA); return 0; }
    size_t length = static_cast<size_t>(response.information);
    if (output.size() != (length + 1) * sizeof(wchar_t) ||
        reinterpret_cast<const wchar_t *>(output.data())[length] != 0) {
        SetLastError(ERROR_INVALID_DATA);
        return 0;
    }
    if (capacity <= length) return static_cast<DWORD>(length + 1);
    memcpy(buffer, output.data(), output.size());
    return static_cast<DWORD>(length);
}

static DWORD WINAPI hook_final_path_a(HANDLE file, LPSTR buffer, DWORD capacity, DWORD flags) {
    DWORD result = real_final_path_a(file, buffer, capacity, flags);
    if (result || GetLastError() != ERROR_ACCESS_DENIED) return result;
    wchar_t path[32768];
    if (!hook_final_path(file, path, 32768, flags)) return 0;
    UINT page = AreFileApisANSI() ? CP_ACP : CP_OEMCP;
    int required = WideCharToMultiByte(page, 0, path, -1, NULL, 0, NULL, NULL);
    if (!required) return 0;
    if (capacity < static_cast<DWORD>(required)) return static_cast<DWORD>(required);
    if (!WideCharToMultiByte(page, 0, path, -1, buffer, required, NULL, NULL)) return 0;
    return static_cast<DWORD>(required - 1);
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
    if (!sandbox_inject_process(process->hProcess, &endpoint, NULL, real_create_process_w) ||
        (!(flags & CREATE_SUSPENDED) && ResumeThread(process->hThread) == (DWORD)-1)) {
        DWORD error = GetLastError();
        if (!TerminateProcess(process->hProcess, 125)) {
            error = GetLastError();
        } else {
            // The invocation Job retains ownership if bounded reaping times out.
            DWORD waited = WaitForSingleObject(process->hProcess, broker_timeout);
            if (waited == WAIT_TIMEOUT) error = ERROR_TIMEOUT;
            else if (waited == WAIT_FAILED) error = GetLastError();
        }
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
    process_creation_scope scope;
    BOOL created = real_create_process_w(application, line, process_security, thread_security,
        inherit, scope.outer ? flags | CREATE_SUSPENDED : flags, environment, cwd, startup, process);
    return scope.outer ? finish_child(created, flags, process) : created;
}

static BOOL WINAPI hook_create_process_a(LPCSTR application, LPSTR line,
    LPSECURITY_ATTRIBUTES process_security, LPSECURITY_ATTRIBUTES thread_security, BOOL inherit,
    DWORD flags, LPVOID environment, LPCSTR cwd, LPSTARTUPINFOA startup, LPPROCESS_INFORMATION process) {
    process_creation_scope scope;
    BOOL created = real_create_process_a(application, line, process_security, thread_security,
        inherit, scope.outer ? flags | CREATE_SUSPENDED : flags, environment, cwd, startup, process);
    return scope.outer ? finish_child(created, flags, process) : created;
}

static BOOL WINAPI hook_as_user_w(HANDLE token, LPCWSTR application, LPWSTR line,
    LPSECURITY_ATTRIBUTES process_security, LPSECURITY_ATTRIBUTES thread_security, BOOL inherit,
    DWORD flags, LPVOID environment, LPCWSTR cwd, LPSTARTUPINFOW startup, LPPROCESS_INFORMATION process) {
    process_creation_scope scope;
    BOOL created = real_as_user_w(token, application, line, process_security, thread_security,
        inherit, scope.outer ? flags | CREATE_SUSPENDED : flags, environment, cwd, startup, process);
    return scope.outer ? finish_child(created, flags, process) : created;
}

static BOOL WINAPI hook_as_user_a(HANDLE token, LPCSTR application, LPSTR line,
    LPSECURITY_ATTRIBUTES process_security, LPSECURITY_ATTRIBUTES thread_security, BOOL inherit,
    DWORD flags, LPVOID environment, LPCSTR cwd, LPSTARTUPINFOA startup, LPPROCESS_INFORMATION process) {
    process_creation_scope scope;
    BOOL created = real_as_user_a(token, application, line, process_security, thread_security,
        inherit, scope.outer ? flags | CREATE_SUSPENDED : flags, environment, cwd, startup, process);
    return scope.outer ? finish_child(created, flags, process) : created;
}

static BOOL WINAPI hook_with_token(HANDLE token, DWORD logon_flags, LPCWSTR application, LPWSTR line,
    DWORD flags, LPVOID environment, LPCWSTR cwd, LPSTARTUPINFOW startup, LPPROCESS_INFORMATION process) {
    process_creation_scope scope;
    BOOL created = real_with_token(token, logon_flags, application, line,
        scope.outer ? flags | CREATE_SUSPENDED : flags, environment, cwd, startup, process);
    return scope.outer ? finish_child(created, flags, process) : created;
}

static BOOL WINAPI hook_with_logon(LPCWSTR user, LPCWSTR domain, LPCWSTR password, DWORD logon_flags,
    LPCWSTR application, LPWSTR line, DWORD flags, LPVOID environment, LPCWSTR cwd,
    LPSTARTUPINFOW startup, LPPROCESS_INFORMATION process) {
    process_creation_scope scope;
    BOOL created = real_with_logon(user, domain, password, logon_flags, application, line,
        scope.outer ? flags | CREATE_SUSPENDED : flags, environment, cwd, startup, process);
    return scope.outer ? finish_child(created, flags, process) : created;
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
    (void)reserved;
    (void)module;
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    if (DetourIsHelperProcess()) return TRUE;
    DetourRestoreAfterWith();
    DWORD bytes = 0;
    broker_payload *payload = (broker_payload *)DetourFindPayloadEx(sandbox_payload_id, &bytes);
    if (!payload || bytes != sizeof(*payload)) return FALSE;
    endpoint = *payload;
    if (!memchr(endpoint.library, 0, sizeof(endpoint.library)) ||
        !wmemchr(endpoint.pipe, 0, sizeof(endpoint.pipe) / sizeof(endpoint.pipe[0]))) return FALSE;
    FARPROC open_address = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenFile");
    static_assert(sizeof(open_address) == sizeof(real_open_file), "Native function pointer size");
    memcpy(&real_open_file, &open_address, sizeof(real_open_file));
    if (!real_open_file) return FALSE;
    if (DetourTransactionBegin() != NO_ERROR) return FALSE;
    LONG error = DetourUpdateThread(GetCurrentThread());
    if (!error) error = DetourAttach(&real_create_file, hook_create_file);
    if (!error) error = DetourAttach(&real_open_file, hook_open_file);
    if (!error) error = DetourAttach(&real_final_path, hook_final_path);
    if (!error) error = DetourAttach(&real_final_path_a, hook_final_path_a);
    if (!error) error = DetourAttach(&real_create_process_w, hook_create_process_w);
    if (!error) error = DetourAttach(&real_create_process_a, hook_create_process_a);
    if (!error) error = DetourAttach(&real_as_user_w, hook_as_user_w);
    if (!error) error = DetourAttach(&real_as_user_a, hook_as_user_a);
    if (!error) error = DetourAttach(&real_with_token, hook_with_token);
    if (!error) error = DetourAttach(&real_with_logon, hook_with_logon);
    if (error) { DetourTransactionAbort(); return FALSE; }
    return DetourTransactionCommit() == NO_ERROR;
}
