#ifndef GLOBALS_H
#define GLOBALS_H

#include "antirnsm.h"
#include "enum.h"

#pragma once

// variaveis globais
extern PFLT_FILTER g_FilterHandle;
extern PDEVICE_OBJECT g_DeviceObject;
extern PFLT_PORT g_ServerPort;
extern DRIVER_CONTEXT g_driverContext;
extern UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
extern UNICODE_STRING g_DosDeviceName = RTL_CONSTANT_STRING(DOS_DEVICE_NAME);

// definicao da lista de registro de callbacks
extern CONST FLT_OPERATION_REGISTRATION Callbacks[];

// definição do GUID do mini-filter
extern CONST GUID MiniFilterGuid;

#endif // !GLOBALS_H



