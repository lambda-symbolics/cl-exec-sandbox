/* Fixed-width Windows client/broker protocol. No client filesystem path RPC. */
#ifndef CL_EXEC_SANDBOX_NULL_PROTOCOL_H
#define CL_EXEC_SANDBOX_NULL_PROTOCOL_H
#include <windows.h>
#include <winternl.h>
#include <stddef.h>
#include <stdint.h>

static const uint32_t broker_magic = 0x4e554c42;
static const uint32_t broker_version = 1;
static const uint32_t broker_max_extra = 65536;
static const DWORD broker_timeout = 10000;
enum broker_operation : uint32_t { broker_create_null = 1, broker_open_null, broker_final_path };

struct broker_request {
    uint32_t magic, version, operation, extra_size;
    uint32_t access, share, disposition, options, file_attributes, object_attributes;
    uint32_t has_allocation, flags;
    int64_t allocation;
    uint64_t handle;
    /* Windows real handles are interoperable 32-bit values, zero-extended. */
    uint32_t qos_present, qos_length, qos_impersonation, qos_flags;
};
struct broker_response {
    uint32_t magic, version, error, extra_size;
    int32_t status;
    int32_t io_status;
    uint64_t handle, information;
};
struct broker_payload {
    DWORD process_id;
    wchar_t pipe[256];
    char library[32768];
};
static_assert(sizeof(broker_request) == 80, "Stable request layout");
static_assert(sizeof(broker_response) == 40, "Stable response layout");
static_assert(sizeof(wchar_t) == 2 && sizeof(NTSTATUS) == 4, "Windows scalar widths");
static_assert(offsetof(broker_request, allocation) == 48 && offsetof(broker_request, handle) == 56 &&
              offsetof(broker_request, qos_present) == 64, "Stable request offsets");
static_assert(offsetof(broker_response, handle) == 24 && offsetof(broker_response, information) == 32,
              "Stable response offsets");
static_assert(sizeof(broker_payload) == 33284 && offsetof(broker_payload, pipe) == 4 &&
              offsetof(broker_payload, library) == 516, "Stable payload layout");
#endif
