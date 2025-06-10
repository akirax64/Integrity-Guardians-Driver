#ifndef _ENUM_H_
#define _ENUM_H_
#pragma once

#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>

// identificador único para o nosso driver para comunicação com o user mode.
#define DEVICE_ID 0x8000

// link simbólico para comunicação com o user mode
#define DEVICE_NAME     L"\\Host\\IGAntiRansomware"
#define DOS_DEVICE_NAME L"\\DOSCallHost\\IGAntiRansomware"

// IOCTL codes para comunicação com o user mode
#define IOCTL_LOAD_RULES CTL_CODE( \
    DEVICE_ID, \
    0x800, METHOD_BUFFERED, FILE_ANY_ACCESS \
)
#define IOCTL_GET_ALERT CTL_CODE( \
    DEVICE_ID, \
    0x801, METHOD_BUFFERED, FILE_READ_ACCESS \
)
#define IOCTL_CONFIGURE_MONITORING CTL_CODE( \
    DEVICE_ID, \
    0x802, METHOD_BUFFERED, FILE_ANY_ACCESS \
)
#define IOCTL_STATUS CTL_CODE( \
    DEVICE_ID, \
    0x803, METHOD_BUFFERED, FILE_READ_ACCESS \
)

// tags para identificar os dados no user mode
#define TAG_DATA_RULE   'DTRL'
#define TAG_RULE_NAME   'RLNM'
#define TAG_PATTERN     'PTDT'
#define TAG_ALERT       'WARN'
#define TAG_RULE_ERROR  'RERR'

#define RULE_FLAG_MATCH  0x01

#endif