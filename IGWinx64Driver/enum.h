#ifndef _ENUM_H_
#define _ENUM_H_
#pragma once

#include <fltKernel.h>
#include <ntstrsafe.h>

// identificador único para o nosso driver para comunicação com o user mode.
#define DEVICE_ID 0x800

// link simbólico para comunicação com o user mode
#define DEVICE_NAME     L"\\Device\\IGAntiRansomware"
#define DOS_DEVICE_NAME L"\\DosDevices\\IGAntiRansomware"

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
#define IOCTL_ADD_EXCLUDED_PATH CTL_CODE( \
    DEVICE_ID, \
    0x804, METHOD_BUFFERED, FILE_ANY_ACCESS \
)
#define IOCTL_REMOVE_EXCLUDED_PATH CTL_CODE( \
    DEVICE_ID, \
    0x805, METHOD_BUFFERED, FILE_ANY_ACCESS \
)
#define IOCTL_GET_EXCLUDED_PATHS   CTL_CODE( \
    DEVICE_ID, \
    0x806, METHOD_BUFFERED, FILE_READ_ACCESS \
)
#define IOCTL_CLEAR_EXCLUDED_PATHS CTL_CODE( \
    DEVICE_ID, \
    0x807, METHOD_BUFFERED, FILE_ANY_ACCESS \
)

// tags para identificar os dados no user mode
#define TAG_DATA_RULE   'DTRL'
#define TAG_RULE_NAME   'RLNM'
#define TAG_PATTERN     'PTDT'
#define TAG_ALERT       'WARN'
#define TAG_RULE_ERROR  'RERR'
#define TAG_SCAN        'SCAN'
#define TAG_BACKUP      'BCKP'

#define RULE_FLAG_MATCH  0x01

// tamanho máximo para leitura de arquivos para escaneamento
#define MAX_SCAN_LENGTH (1024 * 1024)

#endif