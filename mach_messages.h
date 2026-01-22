//
// mach_messages.h
// SimpleDebugger
//
// ARM64 / iOS compatible
//

#pragma once

#include <mach/mach.h>
#include <mach/exception_types.h>

//
// ========== REQUEST MESSAGE ==========
// kernel → userland
//

typedef struct {
    mach_msg_header_t          header;
    mach_msg_body_t            body;

    // Ports
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;

    // Data
    NDR_record_t               NDR;
    exception_type_t           exception;
    mach_msg_type_number_t     codeCnt;

    // ⚠️ out-of-line exception data
    mach_msg_ool_descriptor_t  code;

} MachExceptionMessage;



//
// ========== REPLY MESSAGE ==========
// userland → kernel
//

typedef struct {
    mach_msg_header_t header;
    NDR_record_t      NDR;
    kern_return_t     returnCode;
} MachReplyMessage;
