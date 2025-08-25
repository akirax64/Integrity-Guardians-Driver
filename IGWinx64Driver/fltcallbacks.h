#ifndef FILTER_CALLBACKS_H
#define FILTER_CALLBACKS_H

#include "antirnsm.h"
#include <fltKernel.h>

#pragma once

// protótipos de funções de callback para filtros

NTSTATUS 
InitializeFilter(
	_In_ PDRIVER_OBJECT driverObject,
	_In_ CONST FLT_REGISTRATION* fltRegistration
);

VOID
CleanFilter(VOID);

NTSTATUS FLTAPI
FilterUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS flags
);

// callbacks de pré e pos-operação
FLT_PREOP_CALLBACK_STATUS
InPreCreate(
	_Inout_ PFLT_CALLBACK_DATA data,
	_In_ PCFLT_RELATED_OBJECTS fltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* ptr_context
);

FLT_POSTOP_CALLBACK_STATUS
InPostCreate(
	_Inout_ PFLT_CALLBACK_DATA data,
	_In_ PCFLT_RELATED_OBJECTS fltObjects,
	_In_opt_ PVOID context,
	_In_ FLT_POST_OPERATION_FLAGS flags
);

FLT_PREOP_CALLBACK_STATUS
InPreWrite(
	_Inout_ PFLT_CALLBACK_DATA data,
	_In_ PCFLT_RELATED_OBJECTS fltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* ptr_context
);

FLT_POSTOP_CALLBACK_STATUS
InPostWrite(
	_Inout_ PFLT_CALLBACK_DATA data,
	_In_ PCFLT_RELATED_OBJECTS fltObjects,
	_In_opt_ PVOID context,
	_In_ FLT_POST_OPERATION_FLAGS flags
);

// Callbacks de gerenciamento de instância
NTSTATUS FLTAPI 
InstanceConfig(
	_In_ PCFLT_RELATED_OBJECTS fltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS flags,
	_In_ DEVICE_TYPE volType,
	_In_ FLT_FILESYSTEM_TYPE volSysType
);

NTSTATUS FLTAPI
InstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS fltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS flags
);

VOID FLTAPI 
InstanceTeardownStart(
	_In_ PCFLT_RELATED_OBJECTS fltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS flags
);

VOID FLTAPI 
InstanceTeardownComplete(
	_In_ PCFLT_RELATED_OBJECTS fltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS flags
);
#endif// !FILTER_CALLBACKS_H