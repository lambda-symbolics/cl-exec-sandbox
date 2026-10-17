#define WIN32_NO_STATUS
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601

#include <windows.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wattributes"
#include <winternl.h>
#pragma GCC diagnostic pop
#include <stdio.h>
#include <stdint.h>
#include <wchar.h>

typedef NTSTATUS (NTAPI *nt_create_file_function)(PHANDLE, ACCESS_MASK,
    POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG,
    ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *nt_open_file_function)(PHANDLE, ACCESS_MASK,
    POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);

typedef struct native_case {
    const char *name;
    ULONG disposition;
    ULONG options;
    int qos_kind;
} native_case;

enum { qos_none, qos_zero_length, qos_invalid_level, qos_invalid_context,
       qos_oversized_length };

static const ULONG_PTR file_sentinel = (ULONG_PTR)0x13579bdfUL;
static const LONG status_sentinel = (LONG)0x2468ace0L;
static const ULONG_PTR information_sentinel = (ULONG_PTR)0x0badc0deUL;

static void initialize_qos(SECURITY_QUALITY_OF_SERVICE *qos, int kind) {
    qos->Length = sizeof(*qos);
    qos->ImpersonationLevel = SecurityImpersonation;
    qos->ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    qos->EffectiveOnly = FALSE;
    if (kind == qos_zero_length)
        qos->Length = 0;
    else if (kind == qos_invalid_level)
        qos->ImpersonationLevel = (SECURITY_IMPERSONATION_LEVEL)99;
    else if (kind == qos_invalid_context)
        qos->ContextTrackingMode = 2;
    else if (kind == qos_oversized_length)
        qos->Length = sizeof(*qos) + 16;
}

static void initialize_object_attributes(OBJECT_ATTRIBUTES *attributes,
                                         UNICODE_STRING *name,
                                         SECURITY_QUALITY_OF_SERVICE *qos,
                                         int qos_kind) {
    attributes->Length = sizeof(*attributes);
    attributes->RootDirectory = NULL;
    attributes->ObjectName = name;
    attributes->Attributes = OBJ_CASE_INSENSITIVE;
    attributes->SecurityDescriptor = NULL;
    attributes->SecurityQualityOfService = NULL;
    if (qos_kind != qos_none) {
        initialize_qos(qos, qos_kind);
        attributes->SecurityQualityOfService = qos;
    }
}

static void print_result(const char *api, const native_case *test,
                         NTSTATUS status, HANDLE file, IO_STATUS_BLOCK *iosb) {
    int file_untouched = (file == (HANDLE)file_sentinel);
    int status_untouched = (iosb->Status == status_sentinel);
    int information_untouched = (iosb->Information == information_sentinel);
    printf("api=%s case=%s status=0x%08lx file=", api, test->name,
           (unsigned long)(ULONG)status);
    if (file_untouched)
        printf("untouched");
    else if (status >= 0 && file != NULL && file != INVALID_HANDLE_VALUE) {
        printf("valid");
        (void)CloseHandle(file);
    } else {
        printf("changed");
    }
    printf(" iosb.status=");
    if (status_untouched)
        printf("untouched");
    else
        printf("0x%08lx", (unsigned long)(ULONG)iosb->Status);
    printf(" iosb.information=");
    if (information_untouched)
        printf("untouched\n");
    else
        printf("0x%llx\n", (unsigned long long)(ULONG_PTR)iosb->Information);
}

static void run_create_case(nt_create_file_function function,
                            const native_case *test, UNICODE_STRING *name) {
    HANDLE file = (HANDLE)file_sentinel;
    IO_STATUS_BLOCK iosb;
    OBJECT_ATTRIBUTES attributes;
    SECURITY_QUALITY_OF_SERVICE qos;
    NTSTATUS status;
    iosb.Status = status_sentinel;
    iosb.Information = information_sentinel;
    initialize_object_attributes(&attributes, name, &qos, test->qos_kind);
    status = function(&file, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attributes,
                      &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      test->disposition, test->options, NULL, 0);
    print_result("NtCreateFile", test, status, file, &iosb);
}

static void run_open_case(nt_open_file_function function,
                          const native_case *test, UNICODE_STRING *name) {
    HANDLE file = (HANDLE)file_sentinel;
    IO_STATUS_BLOCK iosb;
    OBJECT_ATTRIBUTES attributes;
    SECURITY_QUALITY_OF_SERVICE qos;
    NTSTATUS status;
    iosb.Status = status_sentinel;
    iosb.Information = information_sentinel;
    initialize_object_attributes(&attributes, name, &qos, test->qos_kind);
    status = function(&file, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attributes,
                      &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      test->options);
    print_result("NtOpenFile", test, status, file, &iosb);
}

int main(void) {
    static const native_case create_cases[] = {
        {"control", FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, qos_none},
        {"invalid-disposition", 6, FILE_NON_DIRECTORY_FILE, qos_none},
        {"inconsistent-options", FILE_OPEN, FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE, qos_none},
        {"qos-zero-length", FILE_OPEN, FILE_NON_DIRECTORY_FILE, qos_zero_length},
        {"qos-invalid-level", FILE_OPEN, FILE_NON_DIRECTORY_FILE, qos_invalid_level},
        {"qos-invalid-context", FILE_OPEN, FILE_NON_DIRECTORY_FILE, qos_invalid_context},
        {"qos-oversized-length", FILE_OPEN, FILE_NON_DIRECTORY_FILE, qos_oversized_length}
    };
    static const native_case open_cases[] = {
        {"control", FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, qos_none},
        {"inconsistent-options", FILE_OPEN, FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE, qos_none},
        {"invalid-options", FILE_OPEN, FILE_OPEN_REQUIRING_OPLOCK | FILE_NON_DIRECTORY_FILE, qos_none},
        {"qos-zero-length", FILE_OPEN, FILE_NON_DIRECTORY_FILE, qos_zero_length},
        {"qos-invalid-level", FILE_OPEN, FILE_NON_DIRECTORY_FILE, qos_invalid_level},
        {"qos-invalid-context", FILE_OPEN, FILE_NON_DIRECTORY_FILE, qos_invalid_context},
        {"qos-oversized-length", FILE_OPEN, FILE_NON_DIRECTORY_FILE, qos_oversized_length}
    };
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    nt_create_file_function create_file;
    nt_open_file_function open_file;
    union { FARPROC raw; nt_create_file_function function; } create_symbol;
    union { FARPROC raw; nt_open_file_function function; } open_symbol;
    WCHAR path[] = L"\\??\\NUL";
    UNICODE_STRING name;
    size_t index;
    if (ntdll == NULL) {
        fprintf(stderr, "windows-native: GetModuleHandleW ntdll.dll failed\n");
        return 1;
    }
    create_symbol.raw = GetProcAddress(ntdll, "NtCreateFile");
    create_file = create_symbol.function;
    open_symbol.raw = GetProcAddress(ntdll, "NtOpenFile");
    open_file = open_symbol.function;
    if (create_file == NULL || open_file == NULL) {
        fprintf(stderr, "windows-native: required native entry point unavailable\n");
        return 1;
    }
    name.Length = (USHORT)(wcslen(path) * sizeof(WCHAR));
    name.MaximumLength = name.Length;
    name.Buffer = path;
    for (index = 0; index < sizeof(create_cases) / sizeof(create_cases[0]); ++index)
        run_create_case(create_file, &create_cases[index], &name);
    for (index = 0; index < sizeof(open_cases) / sizeof(open_cases[0]); ++index)
        run_open_case(open_file, &open_cases[index], &name);
    return 0;
}
