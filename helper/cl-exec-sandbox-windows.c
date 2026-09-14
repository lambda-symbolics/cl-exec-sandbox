/* Native Windows filesystem/network containment. No administrator privileges.
 * The Lisp supervisor owns --cleanup, including after killing this helper.
 * Every ACL entry uses a fresh package SID, never a shared application SID. */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <userenv.h>
#include <aclapi.h>
#include <objbase.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <wctype.h>

#define FAILURE 125
#define WRITE_RIGHTS (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | \
                      FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER)
#define READ_RIGHTS (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE)
#define MAX_RULES 128
#define MAX_PINS 1024

static HANDLE pins[MAX_PINS];
static unsigned pin_count;
static BY_HANDLE_FILE_INFORMATION helper_identity;
static PSID deny_identity;

/* Serialize this library's ACL read/modify/write operations across invocations. */
static HANDLE lock_acls(void) {
    HANDLE mutex = CreateMutexW(NULL, FALSE, L"Local\\cl-exec-sandbox-acls-v1");
    if (!mutex) ExitProcess(FAILURE);
    DWORD status = WaitForSingleObject(mutex, INFINITE);
    if (status != WAIT_OBJECT_0 && status != WAIT_ABANDONED) ExitProcess(FAILURE);
    return mutex;
}
static void unlock_acls(HANDLE mutex) {
    ReleaseMutex(mutex);
    CloseHandle(mutex);
}

static void fail(const wchar_t *operation, DWORD error) {
    fwprintf(stderr, L"cl-exec-sandbox-windows: %ls (Windows error %lu)\n", operation, error);
    ExitProcess(FAILURE);
}
static void require(BOOL ok, const wchar_t *operation) {
    if (!ok) fail(operation, GetLastError());
}
static void *allocate(size_t size) {
    void *result = calloc(1, size);
    if (!result) fail(L"allocate memory", ERROR_NOT_ENOUGH_MEMORY);
    return result;
}
static void check_hr(HRESULT hr, const wchar_t *operation) {
    if (FAILED(hr)) fail(operation, (DWORD)hr);
}
static wchar_t *join(const wchar_t *root, const wchar_t *leaf) {
    size_t n = wcslen(root);
    if (n + wcslen(leaf) + 1 >= 240)
        fail(L"filesystem path too long", ERROR_FILENAME_EXCED_RANGE);
    wchar_t *result = allocate((n + wcslen(leaf) + 2) * sizeof(wchar_t));
    memcpy(result, root, n * sizeof(wchar_t));
    if (n && root[n - 1] != L'\\') result[n++] = L'\\';
    memcpy(result + n, leaf, (wcslen(leaf) + 1) * sizeof(wchar_t));
    return result;
}
static void validate_profile(const wchar_t *profile) {
    if (wcslen(profile) != 52 || wcsncmp(profile, L"cl-exec-sandbox.", 16))
        fail(L"invalid profile name", ERROR_INVALID_PARAMETER);
    for (unsigned i = 16; i < 52; ++i)
        if (!iswxdigit(profile[i]) && profile[i] != L'-')
            fail(L"invalid profile name", ERROR_INVALID_PARAMETER);
}
static void new_profile(void) {
    GUID id;
    wchar_t text[40];
    check_hr(CoCreateGuid(&id), L"generate profile identity");
    require(StringFromGUID2(&id, text, 40) == 39, L"format profile identity");
    text[37] = 0;
    wprintf(L"cl-exec-sandbox.%ls\n", text + 1);
}

/* Keep every rule root and its ancestors fixed until the process tree dies.
 * A grant must not be redirected through a junction, ADS, device or UNC path. */
static wchar_t *local_path(const wchar_t *input) {
    size_t n = wcslen(input);
    if (n <= 3 || n >= 240 || !iswalpha(input[0]) || input[1] != L':' ||
        (input[2] != L'\\' && input[2] != L'/'))
        fail(L"expected a non-root local path shorter than 240 characters", ERROR_INVALID_NAME);
    wchar_t *path = allocate((n + 1) * sizeof(wchar_t));
    memcpy(path, input, (n + 1) * sizeof(wchar_t));
    for (size_t i = 2; i < n; ++i) {
        if (path[i] == L'/') path[i] = L'\\';
        if (path[i] == L':' || path[i] == L'*' || path[i] == L'?' || path[i] == L'"')
            fail(L"refuse path alias or wildcard", ERROR_INVALID_NAME);
        if ((path[i] == L'.' || path[i] == L' ') &&
            (i + 1 == n || path[i + 1] == L'\\' || path[i + 1] == L'/'))
            fail(L"refuse ambiguous path component", ERROR_INVALID_NAME);
    }
    while (n > 3 && path[n - 1] == L'\\') path[--n] = 0;
    return path;
}
static HANDLE open_path(const wchar_t *path, DWORD access, DWORD share) {
    return CreateFileW(path, access, share, NULL, OPEN_EXISTING,
                       FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
}
static BY_HANDLE_FILE_INFORMATION info(HANDLE handle) {
    BY_HANDLE_FILE_INFORMATION result;
    require(GetFileInformationByHandle(handle, &result), L"inspect filesystem object");
    return result;
}
static void pin_path(wchar_t *path) {
    size_t n = wcslen(path);
    for (size_t i = 3; i <= n; ++i) {
        if (path[i] && path[i] != L'\\') continue;
        wchar_t saved = path[i];
        path[i] = 0;
        HANDLE handle = open_path(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE);
        if (handle == INVALID_HANDLE_VALUE) fail(L"pin rule path", GetLastError());
        if (info(handle).dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            fail(L"refuse reparse point in rule ancestry", ERROR_REPARSE_TAG_INVALID);
        if (pin_count == MAX_PINS) fail(L"too many path components", ERROR_BUFFER_OVERFLOW);
        pins[pin_count++] = handle;
        path[i] = saved;
    }
}

/* Preserve ACEs byte-for-byte except those owned by this invocation's SID.
 * This also removes inherited entries without converting somebody else's ACEs. */
static BOOL own_ace(void *ace, PSID sid) {
    ACE_HEADER *header = ace;
    if (header->AceType == ACCESS_ALLOWED_ACE_TYPE)
        return EqualSid(&((ACCESS_ALLOWED_ACE *)ace)->SidStart, sid);
    if (header->AceType == ACCESS_DENIED_ACE_TYPE)
        return EqualSid(&((ACCESS_DENIED_ACE *)ace)->SidStart, sid);
    return FALSE;
}
static void set_acl(HANDLE handle, PSID sid, const wchar_t *kind, BOOL cleanup,
                    BOOL directory, BOOL root) {
    PSECURITY_DESCRIPTOR descriptor = NULL;
    PACL original = NULL;
    DWORD status = GetSecurityInfo(handle, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                  NULL, NULL, &original, NULL, &descriptor);
    if (status) fail(L"read filesystem ACL", status);
    if (!original) {
        LocalFree(descriptor);
        if (cleanup) return;
        fail(L"refuse unrestricted null DACL", ERROR_INVALID_ACL);
    }
    SECURITY_DESCRIPTOR_CONTROL control;
    DWORD revision;
    require(GetSecurityDescriptorControl(descriptor, &control, &revision), L"read ACL control");
    if (!cleanup && (control & SE_DACL_PROTECTED))
        fail(L"protected DACL requires an explicit supported policy", ERROR_ACCESS_DENIED);
    DWORD capacity = original->AclSize + 2 * (sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(sid));
    PACL changed = allocate(capacity);
    require(InitializeAcl(changed, capacity, ACL_REVISION_DS), L"initialize ACL");
    BOOL found = FALSE;
    for (DWORD i = 0; i < original->AceCount; ++i) {
        void *ace;
        require(GetAce(original, i, &ace), L"read ACE");
        if (own_ace(ace, sid) || own_ace(ace, deny_identity)) { found = TRUE; continue; }
        require(AddAce(changed, ACL_REVISION_DS, MAXDWORD, ace, ((ACE_HEADER *)ace)->AceSize),
                L"preserve ACE");
    }
    if (!cleanup) {
        EXPLICIT_ACCESSW entries[2];
        ZeroMemory(entries, sizeof(entries));
        for (unsigned i = 0; i < 2; ++i) {
            entries[i].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            entries[i].Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
            entries[i].Trustee.ptstrName = sid;
            entries[i].grfInheritance = directory ? SUB_CONTAINERS_AND_OBJECTS_INHERIT : NO_INHERITANCE;
        }
        unsigned count = 1;
        if (!wcscmp(kind, L"deny")) {
            entries[0].grfAccessMode = DENY_ACCESS;
            entries[0].Trustee.ptstrName = deny_identity;
            entries[0].grfAccessPermissions = FILE_ALL_ACCESS;
        } else {
            entries[0].grfAccessMode = GRANT_ACCESS;
            entries[0].grfAccessPermissions = READ_RIGHTS;
            if (!wcscmp(kind, L"write")) {
                entries[0].grfAccessPermissions |= FILE_GENERIC_WRITE;
                if (!root) entries[0].grfAccessPermissions |= DELETE;
                else if (directory) {
                    count = 2;
                    entries[1].grfAccessMode = GRANT_ACCESS;
                    entries[1].grfAccessPermissions = DELETE;
                    entries[1].grfInheritance |= INHERIT_ONLY;
                }
            } else {
                count = 2;
                entries[1].grfAccessMode = DENY_ACCESS;
                entries[1].Trustee.ptstrName = deny_identity;
                entries[1].grfAccessPermissions = WRITE_RIGHTS;
            }
        }
        PACL granted = NULL;
        status = SetEntriesInAclW(count, entries, changed, &granted);
        free(changed);
        if (status) fail(L"construct package ACL", status);
        changed = granted;
    }
    if (!cleanup || found) {
        status = SetSecurityInfo(handle, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                 NULL, NULL, changed, NULL);
        if (status) fail(L"update filesystem ACL", status);
    }
    if (cleanup) free(changed); else LocalFree(changed);
    LocalFree(descriptor);
}

/* Validate the entire tree before granting anything. During cleanup, inspect a
 * newly created reparse point itself, never the object to which it points. */
static void walk(const wchar_t *path, PSID sid, const wchar_t *kind,
                 int mode, BOOL root, unsigned depth) {
    if (depth > 128) fail(L"filesystem tree too deep", ERROR_BUFFER_OVERFLOW);
    DWORD access = FILE_READ_ATTRIBUTES | READ_CONTROL;
    if (mode) access |= WRITE_DAC;
    HANDLE handle = open_path(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE);
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (mode == 2 && (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)) return;
        fail(L"open filesystem policy path", error);
    }
    BY_HANDLE_FILE_INFORMATION attributes = info(handle);
    BOOL reparse = (attributes.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    BOOL directory = (attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if (mode != 2 && !wcscmp(kind, L"write") &&
        attributes.dwVolumeSerialNumber == helper_identity.dwVolumeSerialNumber &&
        attributes.nFileIndexHigh == helper_identity.nFileIndexHigh &&
        attributes.nFileIndexLow == helper_identity.nFileIndexLow)
        fail(L"refuse writable sandbox helper", ERROR_ACCESS_DENIED);
    if (mode != 2 && (reparse || (!directory && attributes.nNumberOfLinks != 1)))
        fail(L"refuse reparse point or hard link in filesystem policy", ERROR_NOT_SUPPORTED);
    if (mode) set_acl(handle, sid, kind, mode == 2, directory, root);
    if (!directory || reparse) { CloseHandle(handle); return; }
    wchar_t *pattern = join(path, L"*");
    WIN32_FIND_DATAW data;
    HANDLE search = FindFirstFileW(pattern, &data);
    free(pattern);
    if (search == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND) { CloseHandle(handle); return; }
        fail(L"enumerate filesystem policy", error);
    }
    do {
        if (!wcscmp(data.cFileName, L".") || !wcscmp(data.cFileName, L"..")) continue;
        wchar_t *child = join(path, data.cFileName);
        walk(child, sid, kind, mode, FALSE, depth + 1);
        free(child);
    } while (FindNextFileW(search, &data));
    DWORD error = GetLastError();
    FindClose(search);
    CloseHandle(handle);
    if (error != ERROR_NO_MORE_FILES) fail(L"enumerate filesystem policy", error);
}

/* CommandLineToArgvW / Microsoft CRT quoting: only double backslashes before
 * a quote or the closing quote, not ordinary path separators. */
static wchar_t *command_line(int count, wchar_t **arguments) {
    size_t capacity = 1;
    for (int i = 0; i < count; ++i) capacity += 2 * wcslen(arguments[i]) + 3;
    if (capacity > 32767) fail(L"command line too long", ERROR_BUFFER_OVERFLOW);
    wchar_t *line = allocate(capacity * sizeof(wchar_t)), *out = line;
    for (int i = 0; i < count; ++i) {
        if (i) *out++ = L' ';
        *out++ = L'"';
        const wchar_t *in = arguments[i];
        while (*in) {
            unsigned slashes = 0;
            while (*in == L'\\') { ++slashes; ++in; }
            unsigned copies = (*in == L'"' || !*in) ? 2 * slashes : slashes;
            while (copies--) *out++ = L'\\';
            if (*in == L'"') *out++ = L'\\';
            if (*in) *out++ = *in++;
        }
        *out++ = L'"';
    }
    *out = 0;
    return line;
}
static HANDLE inherited_stdio(DWORD which, BOOL input) {
    HANDLE source = GetStdHandle(which), copy = NULL;
    if (source == NULL || source == INVALID_HANDLE_VALUE) {
        SECURITY_ATTRIBUTES attributes = {sizeof(attributes), NULL, TRUE};
        copy = CreateFileW(L"NUL", input ? GENERIC_READ : GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes, OPEN_EXISTING, 0, NULL);
        if (copy == INVALID_HANDLE_VALUE) fail(L"open null stream", GetLastError());
    } else {
        require(DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(),
                                &copy, 0, TRUE, DUPLICATE_SAME_ACCESS), L"duplicate standard handle");
    }
    return copy;
}
static void terminate_job(HANDLE job) {
    require(TerminateJobObject(job, FAILURE), L"terminate process tree");
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info;
    for (;;) {
        require(QueryInformationJobObject(job, JobObjectBasicAccountingInformation,
                                           &info, sizeof(info), NULL), L"wait for process tree");
        if (!info.ActiveProcesses) break;
        Sleep(10);
    }
}
/* Package SIDs cannot be used as ordinary restricting SIDs. Use a separate
 * invocation-specific NT SID for deny checks and retain AppContainer as the
 * allow boundary. The copied caller identities do not enlarge normal access. */
static HANDLE restricted_token(void) {
    HANDLE caller, restricted;
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE |
                             TOKEN_ASSIGN_PRIMARY, &caller), L"open caller token");
    DWORD bytes = 0;
    GetTokenInformation(caller, TokenGroups, NULL, 0, &bytes);
    TOKEN_GROUPS *groups = allocate(bytes);
    require(GetTokenInformation(caller, TokenGroups, groups, bytes, &bytes), L"read caller groups");
    DWORD user_bytes = 0;
    GetTokenInformation(caller, TokenUser, NULL, 0, &user_bytes);
    TOKEN_USER *user = allocate(user_bytes);
    require(GetTokenInformation(caller, TokenUser, user, user_bytes, &user_bytes), L"read caller SID");
    SID_AND_ATTRIBUTES *sids = allocate((groups->GroupCount + 2) * sizeof(*sids));
    DWORD count = 0;
    for (DWORD i = 0; i < groups->GroupCount; ++i)
        if (!(groups->Groups[i].Attributes & SE_GROUP_INTEGRITY))
            sids[count++].Sid = groups->Groups[i].Sid;
    sids[count++].Sid = user->User.Sid;
    sids[count++].Sid = deny_identity;
    require(CreateRestrictedToken(caller, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL,
                                  count, sids, &restricted), L"restrict deny identity");
    CloseHandle(caller);
    free(sids); free(user); free(groups);
    return restricted;
}
static DWORD launch(PSID sid, const wchar_t *profile, const wchar_t *cwd,
                    int count, wchar_t **arguments) {
    wchar_t *job_name = join(L"Local", profile);
    SetLastError(ERROR_SUCCESS);
    HANDLE job = CreateJobObjectW(NULL, job_name);
    free(job_name);
    if (!job || GetLastError() == ERROR_ALREADY_EXISTS) fail(L"create private job", GetLastError());
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    ZeroMemory(&limits, sizeof(limits));
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    require(SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
            L"configure process tree containment");
    HANDLE handles[3] = {inherited_stdio(STD_INPUT_HANDLE, TRUE),
                         inherited_stdio(STD_OUTPUT_HANDLE, FALSE),
                         inherited_stdio(STD_ERROR_HANDLE, FALSE)};
    STARTUPINFOEXW startup;
    PROCESS_INFORMATION process;
    ZeroMemory(&startup, sizeof(startup));
    ZeroMemory(&process, sizeof(process));
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = handles[0];
    startup.StartupInfo.hStdOutput = handles[1];
    startup.StartupInfo.hStdError = handles[2];
    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(NULL, 2, 0, &bytes);
    startup.lpAttributeList = allocate(bytes);
    require(InitializeProcThreadAttributeList(startup.lpAttributeList, 2, 0, &bytes), L"initialize process attributes");
    SECURITY_CAPABILITIES capabilities;
    ZeroMemory(&capabilities, sizeof(capabilities));
    capabilities.AppContainerSid = sid;
    require(UpdateProcThreadAttribute(startup.lpAttributeList, 0,
                                      PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                      &capabilities, sizeof(capabilities), NULL, NULL), L"set AppContainer identity");
    require(UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                      handles, sizeof(handles), NULL, NULL), L"restrict inherited handles");
    wchar_t *line = command_line(count, arguments);
    HANDLE token = restricted_token();
    require(CreateProcessAsUserW(token, arguments[0], line, NULL, NULL, TRUE,
                                EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW,
                                NULL, cwd, &startup.StartupInfo, &process), L"create AppContainer process");
    CloseHandle(token);
    if (!AssignProcessToJobObject(job, process.hProcess)) {
        DWORD error = GetLastError();
        TerminateProcess(process.hProcess, FAILURE);
        WaitForSingleObject(process.hProcess, INFINITE);
        fail(L"assign suspended process to job", error);
    }
    require(ResumeThread(process.hThread) != (DWORD)-1, L"start contained process");
    require(WaitForSingleObject(process.hProcess, INFINITE) == WAIT_OBJECT_0, L"wait for command");
    DWORD status;
    require(GetExitCodeProcess(process.hProcess, &status), L"read command exit code");
    terminate_job(job);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    CloseHandle(job);
    for (unsigned i = 0; i < 3; ++i) CloseHandle(handles[i]);
    DeleteProcThreadAttributeList(startup.lpAttributeList);
    free(startup.lpAttributeList);
    free(line);
    return status;
}
int wmain(int argc, wchar_t **argv) {
    if (argc == 2 && !wcscmp(argv[1], L"--new-profile")) { new_profile(); return 0; }
    if (argc == 2 && !wcscmp(argv[1], L"--probe")) { puts("appcontainer-v1"); return 0; }
    BOOL cleanup = argc >= 3 && !wcscmp(argv[1], L"--cleanup");
    if ((!cleanup && (argc < 7 || wcscmp(argv[1], L"--run") || wcscmp(argv[3], L"isolated"))) || argc < 3)
        fail(L"invalid helper arguments", ERROR_INVALID_PARAMETER);
    validate_profile(argv[2]);
    int start = cleanup ? 3 : 5, end = start;
    while (end < argc && wcscmp(argv[end], L"--")) end += 2;
    if (end > argc || (!cleanup && end + 1 >= argc) || (cleanup && end != argc) ||
        (end - start) / 2 > MAX_RULES)
        fail(L"invalid filesystem rule list", ERROR_INVALID_PARAMETER);
    wchar_t *paths[MAX_RULES];
    for (int i = start; i < end; i += 2) {
        if (wcscmp(argv[i], L"read") && wcscmp(argv[i], L"write") && wcscmp(argv[i], L"deny"))
            fail(L"unknown filesystem access", ERROR_INVALID_PARAMETER);
        paths[(i - start) / 2] = local_path(argv[i + 1]);
    }
    PSID sid = NULL;
    check_hr(DeriveAppContainerSidFromAppContainerName(argv[2], &sid), L"derive package SID");
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    require(AllocateAndInitializeSid(&authority, 5, SECURITY_NT_NON_UNIQUE,
             *GetSidSubAuthority(sid, 1), *GetSidSubAuthority(sid, 2),
             *GetSidSubAuthority(sid, 3), *GetSidSubAuthority(sid, 4),
             0, 0, 0, &deny_identity), L"derive invocation deny SID");
    wchar_t executable[MAX_PATH];
    DWORD length = GetModuleFileNameW(NULL, executable, MAX_PATH);
    require(length && length < MAX_PATH, L"locate helper executable");
    HANDLE self = open_path(executable, FILE_READ_ATTRIBUTES, FILE_SHARE_READ);
    if (self == INVALID_HANDLE_VALUE) fail(L"pin helper executable", GetLastError());
    helper_identity = info(self);
    HANDLE mutex;
    if (cleanup) {
        wchar_t *name = join(L"Local", argv[2]);
        HANDLE job = OpenJobObjectW(JOB_OBJECT_TERMINATE | JOB_OBJECT_QUERY, FALSE, name);
        free(name);
        if (job) { terminate_job(job); CloseHandle(job); }
        mutex = lock_acls();
        for (int i = start; i < end; i += 2)
            if (GetFileAttributesW(paths[(i - start) / 2]) != INVALID_FILE_ATTRIBUTES)
                pin_path(paths[(i - start) / 2]);
        for (int i = start; i < end; i += 2)
            walk(paths[(i - start) / 2], sid, argv[i], 2, TRUE, 0);
        HRESULT hr = DeleteAppContainerProfile(argv[2]);
        if (hr != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) && hr != HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND))
            check_hr(hr, L"delete AppContainer profile");
        unlock_acls(mutex);
    } else {
        mutex = lock_acls();
        for (int i = start; i < end; i += 2) pin_path(paths[(i - start) / 2]);
        for (int i = start; i < end; i += 2)
            walk(paths[(i - start) / 2], sid, argv[i], 0, TRUE, 0);
        PSID created = NULL;
        check_hr(CreateAppContainerProfile(argv[2], argv[2], L"cl-exec-sandbox invocation", NULL, 0, &created),
                 L"create unique AppContainer profile");
        FreeSid(created);
        for (int i = start; i < end; i += 2)
            walk(paths[(i - start) / 2], sid, argv[i], 1, TRUE, 0);
        DWORD result = launch(sid, argv[2], argv[4], argc - end - 1, argv + end + 1);
        for (int i = start; i < end; i += 2)
            walk(paths[(i - start) / 2], sid, argv[i], 2, TRUE, 0);
        check_hr(DeleteAppContainerProfile(argv[2]), L"delete AppContainer profile");
        unlock_acls(mutex);
        FreeSid(sid);
        return (int)result;
    }
    FreeSid(sid);
    return 0;
}
