/* Diagnostic compatibility broker, owned by the existing ordinary-user helper.
 * Only real Null opens and final-path queries on caller-owned handles cross it.
 * Pipe waits are cancellable; a stalled client cannot delay helper shutdown. */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <winternl.h>
#include <sddl.h>
#include <securityappcontainer.h>
#include <stdio.h>
#include <string>
#include <vector>
#include "nul-protocol.h"

static const unsigned worker_count = 4;
static HANDLE broker_job, broker_stop;
static HANDLE workers[worker_count], pipes[worker_count];
static PSECURITY_DESCRIPTOR pipe_security;
static broker_payload endpoint;
typedef NTSTATUS (NTAPI *open_file_type)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                        PIO_STATUS_BLOCK, ULONG, ULONG);
static open_file_type native_open;

/* Finish or cancel every OVERLAPPED before releasing its buffers and event. */
static bool complete_io(HANDLE pipe, OVERLAPPED *operation, BOOL started, DWORD *bytes) {
    if (!started && GetLastError() != ERROR_IO_PENDING) return false;
    HANDLE waits[] = {broker_stop, operation->hEvent};
    DWORD wait = started ? WAIT_OBJECT_0 + 1 : WaitForMultipleObjects(2, waits, FALSE, broker_timeout);
    if (wait != WAIT_OBJECT_0 + 1) {
        CancelIoEx(pipe, operation);
        GetOverlappedResult(pipe, operation, bytes, TRUE);
        return false;
    }
    return GetOverlappedResult(pipe, operation, bytes, FALSE) != FALSE;
}

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
        ok = complete_io(pipe, &operation, started, &bytes) && bytes != 0;
        if (ok) { cursor += bytes; size -= bytes; }
    }
    CloseHandle(operation.hEvent);
    return ok;
}

static HANDLE authenticate(HANDLE pipe) {
    ULONG pid = 0;
    if (!GetNamedPipeClientProcessId(pipe, &pid) || !pid || pid == GetCurrentProcessId()) {
        fprintf(stderr, "BROKER auth=client-pid error=%lu\n", GetLastError());
        return NULL;
    }
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE, FALSE, pid);
    if (!process) { fprintf(stderr, "BROKER auth=open-process pid=%lu error=%lu\n", pid, GetLastError()); return NULL; }
    BOOL member = FALSE;
    if (!IsProcessInJob(process, broker_job, &member) || !member) {
        fprintf(stderr, "BROKER auth=job pid=%lu member=%d error=%lu\n", pid, member, GetLastError());
        CloseHandle(process);
        return NULL;
    }
    return process;
}

static void open_null(const broker_request &request, const std::vector<BYTE> &extra,
                      HANDLE client, broker_response *response) {
    ACCESS_MASK access = request.access;
    GENERIC_MAPPING mapping = {FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
    MapGenericMask(&access, &mapping);
    const ACCESS_MASK allowed = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE;
    if ((access & ~allowed) || (request.object_attributes & ~(OBJ_CASE_INSENSITIVE | OBJ_INHERIT))) {
        response->status = static_cast<NTSTATUS>(0xc0000022L);
        return;
    }
    wchar_t path[] = L"\\Device\\Null";
    UNICODE_STRING name = {sizeof(path) - sizeof(wchar_t), sizeof(path), path};
    OBJECT_ATTRIBUTES attributes = {};
    attributes.Length = sizeof(attributes);
    attributes.ObjectName = &name;
    attributes.Attributes = request.object_attributes;
    SECURITY_QUALITY_OF_SERVICE qos = {};
    if (request.qos_present) {
        qos.Length = request.qos_length;
        qos.ImpersonationLevel = static_cast<SECURITY_IMPERSONATION_LEVEL>(request.qos_impersonation);
        qos.ContextTrackingMode = static_cast<BOOLEAN>(request.qos_flags & 255);
        qos.EffectiveOnly = static_cast<BOOLEAN>((request.qos_flags >> 8) & 255);
        attributes.SecurityQualityOfService = &qos;
    }
    LARGE_INTEGER allocation;
    allocation.QuadPart = request.allocation;
    IO_STATUS_BLOCK status = {};
    HANDLE file = NULL;
    NTSTATUS result;
    if (request.operation == broker_open_null) {
        if (!extra.empty()) { response->error = ERROR_INVALID_DATA; return; }
        result = native_open(&file, request.access, &attributes, &status, request.share, request.options);
    } else {
        result = NtCreateFile(&file, request.access, &attributes, &status,
                              request.has_allocation ? &allocation : NULL, request.file_attributes,
                              request.share, request.disposition, request.options,
                              extra.empty() ? NULL : const_cast<BYTE *>(extra.data()),
                              static_cast<ULONG>(extra.size()));
    }
    response->status = result;
    response->io_status = status.Status;
    response->information = status.Information;
    if (result < 0) return;
    HANDLE remote = NULL;
    if (!DuplicateHandle(GetCurrentProcess(), file, client, &remote, 0,
                         (request.object_attributes & OBJ_INHERIT) != 0, DUPLICATE_SAME_ACCESS))
        response->error = GetLastError();
    else response->handle = reinterpret_cast<ULONG_PTR>(remote);
    CloseHandle(file);
}

static void final_path(const broker_request &request, HANDLE client, broker_response *response,
                       std::vector<BYTE> *extra) {
    HANDLE file = NULL;
    if (!DuplicateHandle(client, reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(request.handle)),
                         GetCurrentProcess(), &file, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        response->error = GetLastError();
        return;
    }
    std::vector<wchar_t> buffer(256);
    for (;;) {
        DWORD size = GetFinalPathNameByHandleW(file, buffer.data(), static_cast<DWORD>(buffer.size()), request.flags);
        if (!size) { response->error = GetLastError(); break; }
        if (size >= buffer.size()) {
            if (size > 32768) { response->error = ERROR_FILENAME_EXCED_RANGE; break; }
            buffer.resize(size);
            continue;
        }
        response->information = size;
        const BYTE *begin = reinterpret_cast<const BYTE *>(buffer.data());
        extra->assign(begin, begin + (static_cast<size_t>(size) + 1) * sizeof(wchar_t));
        response->extra_size = static_cast<uint32_t>(extra->size());
        break;
    }
    CloseHandle(file);
}

static void serve(HANDLE pipe) {
    HANDLE client = authenticate(pipe);
    if (!client) return;
    broker_request request = {};
    broker_response response = {};
    response.magic = broker_magic;
    response.version = broker_version;
    std::vector<BYTE> extra, output;
    bool valid = transfer(pipe, &request, sizeof(request), false) &&
                 request.magic == broker_magic && request.version == broker_version &&
                 request.extra_size <= broker_max_extra;
    if (valid) {
        extra.resize(request.extra_size);
        valid = extra.empty() || transfer(pipe, extra.data(), request.extra_size, false);
    }
    if (valid) {
        switch (request.operation) {
        case broker_create_null: case broker_open_null:
            open_null(request, extra, client, &response);
            break;
        case broker_final_path:
            if (!extra.empty()) response.error = ERROR_INVALID_DATA;
            else final_path(request, client, &response, &output);
            break;
        default: response.error = ERROR_INVALID_FUNCTION;
        }
    } else response.error = ERROR_INVALID_DATA;
    bool replied = transfer(pipe, &response, sizeof(response), true) &&
                   (output.empty() || transfer(pipe, output.data(), response.extra_size, true));
    BYTE acknowledged = 0;
    if (replied) transfer(pipe, &acknowledged, 1, false);
    /* Publication transfers ownership. Never close a client handle number after
     * publication: the client might already have closed and reused its slot. */
    CloseHandle(client);
}

static DWORD WINAPI worker(void *argument) {
    HANDLE pipe = argument;
    OVERLAPPED connection = {};
    connection.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!connection.hEvent) return GetLastError();
    while (WaitForSingleObject(broker_stop, 0) == WAIT_TIMEOUT) {
        ResetEvent(connection.hEvent);
        DWORD bytes = 0;
        BOOL connected = ConnectNamedPipe(pipe, &connection);
        bool ready = !connected && GetLastError() == ERROR_PIPE_CONNECTED;
        if (!ready) ready = complete_io(pipe, &connection, connected, &bytes);
        if (ready) serve(pipe);
        DisconnectNamedPipe(pipe);
    }
    CloseHandle(connection.hEvent);
    return 0;
}

extern "C" void sandbox_stop_broker(void) {
    if (broker_stop) SetEvent(broker_stop);
    for (unsigned i = 0; i < worker_count; ++i)
        if (workers[i]) CancelSynchronousIo(workers[i]);
    for (unsigned i = 0; i < worker_count; ++i) {
        if (workers[i]) {
            if (WaitForSingleObject(workers[i], broker_timeout) != WAIT_OBJECT_0) {
                /* The supervisor owns --cleanup after helper failure. End this
                 * process rather than leave a stuck native query alive. */
                TerminateProcess(GetCurrentProcess(), 125);
            }
            CloseHandle(workers[i]); workers[i] = NULL;
        }
        if (pipes[i] && pipes[i] != INVALID_HANDLE_VALUE) { CloseHandle(pipes[i]); pipes[i] = NULL; }
    }
    if (broker_stop) { CloseHandle(broker_stop); broker_stop = NULL; }
    if (pipe_security) { LocalFree(pipe_security); pipe_security = NULL; }
}

/* The AppContainer check and the ordinary/restricted-token checks both need a
 * grant. Low integrity must be allowed to write to this one invocation pipe. */
static bool make_security(PSID package) {
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    std::vector<BYTE> data(size);
    BOOL read = GetTokenInformation(token, TokenUser, data.data(), size, &size);
    CloseHandle(token);
    if (!read) return false;
    LPWSTR user_sid = NULL, package_sid = NULL;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(data.data())->User.Sid, &user_sid)) return false;
    if (!ConvertSidToStringSidW(package, &package_sid)) { LocalFree(user_sid); return false; }
    std::wstring descriptor = L"D:(A;;GRGW;;;" + std::wstring(user_sid) +
                              L")(A;;GRGW;;;" + std::wstring(package_sid) + L")S:(ML;;NW;;;LW)";
    LocalFree(user_sid);
    LocalFree(package_sid);
    return ConvertStringSecurityDescriptorToSecurityDescriptorW(descriptor.c_str(), SDDL_REVISION_1,
                                                                 &pipe_security, NULL) != FALSE;
}

/* LOCAL names are expanded inside an AppContainer, not in the desktop
 * helper. Create the server in that exact package/session namespace. */
static std::wstring server_pipe_name(PSID package, const wchar_t *profile) {
    wchar_t objects[512], prefix[64];
    ULONG required = 0;
    DWORD session = 0;
    if (!GetAppContainerNamedObjectPath(NULL, package, 512, objects, &required) ||
        !ProcessIdToSessionId(GetCurrentProcessId(), &session) ||
        swprintf_s(prefix, 64, L"\\\\.\\pipe\\Sessions\\%lu\\", session) < 0) return std::wstring();
    return std::wstring(prefix) + objects + L"\\" + profile + L"-null";
}

extern "C" BOOL sandbox_start_broker(HANDLE job, PSID package, const wchar_t *profile) {
    broker_job = job;
    endpoint.process_id = GetCurrentProcessId();
    if (swprintf_s(endpoint.pipe, 256, L"\\\\.\\pipe\\LOCAL\\%ls-null", profile) < 0) return FALSE;
    std::wstring server_name = server_pipe_name(package, profile);
    if (server_name.empty()) return FALSE;
    fwprintf(stderr, L"BROKER server=%ls client=%ls\n", server_name.c_str(), endpoint.pipe);
    HMODULE native = GetModuleHandleW(L"ntdll.dll");
    FARPROC address = GetProcAddress(native, "NtOpenFile");
    static_assert(sizeof(address) == sizeof(native_open), "Native pointer size");
    memcpy(&native_open, &address, sizeof(address));
    if (!native_open || !make_security(package)) return FALSE;
    broker_stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!broker_stop) { sandbox_stop_broker(); return FALSE; }
    SECURITY_ATTRIBUTES security = {sizeof(security), pipe_security, FALSE};
    for (unsigned i = 0; i < worker_count; ++i) {
        DWORD mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        if (i == 0) mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        pipes[i] = CreateNamedPipeW(server_name.c_str(), mode, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE |
                                    PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, worker_count,
                                    broker_max_extra, broker_max_extra, 0, &security);
        if (pipes[i] == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError(); sandbox_stop_broker(); SetLastError(error); return FALSE;
        }
        workers[i] = CreateThread(NULL, 0, worker, pipes[i], 0, NULL);
        if (!workers[i]) {
            DWORD error = GetLastError(); sandbox_stop_broker(); SetLastError(error); return FALSE;
        }
    }
    return TRUE;
}

extern "C" const broker_payload *sandbox_broker_endpoint(void) { return &endpoint; }
