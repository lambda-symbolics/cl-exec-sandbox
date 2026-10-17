/* Suspended-process compatibility injection, shared by helper and client DLL. */
#ifndef CL_EXEC_SANDBOX_WINDOWS_INJECT_H
#define CL_EXEC_SANDBOX_WINDOWS_INJECT_H
#include "detours.h"
#include "nul-protocol.h"

static const GUID sandbox_payload_id = {0x96c7a064, 0x183a, 0x47c3, {0xa2,0xc1,0x4d,0xf2,0x2b,0xe7,0x67,0x93}};

BOOL sandbox_inject_process(HANDLE process, const broker_payload *payload, HANDLE job,
                            PDETOUR_CREATE_PROCESS_ROUTINEW create_process);
#endif
