#ifndef CALLBACKS_H
#define CALLBACKS_H

#include <fltKernel.h>

#pragma once

// callbacks.c
extern CONST FLT_OPERATION_REGISTRATION Callbacks[];
FLT_PREOP_CALLBACK_STATUS InPreCreate(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS fltObjects, _Flt_CompletionContext_Outptr_ PVOID* ptr_context);
FLT_POSTOP_CALLBACK_STATUS InPostCreate(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS fltObjects, _In_opt_ PVOID context, _In_ FLT_POST_OPERATION_FLAGS flags);
FLT_PREOP_CALLBACK_STATUS InPreWrite(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS fltObjects, _Flt_CompletionContext_Outptr_ PVOID* ptr_context);
FLT_POSTOP_CALLBACK_STATUS InPostWrite(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS fltObjects, _In_opt_ PVOID context, _In_ FLT_POST_OPERATION_FLAGS flags);

// Callbacks de gerenciamento de instância
NTSTATUS FLTAPI InstanceConfig(_In_ PCFLT_RELATED_OBJECTS fltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS flags, _In_ DEVICE_TYPE volType, _In_ FLT_FILESYSTEM_TYPE volSysType);
VOID FLTAPI InstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS fltObjects, _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS flags);
VOID FLTAPI InstanceTeardownStart(_In_ PCFLT_RELATED_OBJECTS fltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS flags);
VOID FLTAPI InstanceTeardownComplete(_In_ PCFLT_RELATED_OBJECTS fltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS flags);

#endif

