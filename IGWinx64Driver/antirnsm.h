#ifndef _ANTI_RANSOMWARE_H_
#define _ANTI_RANSOMWARE_H_

#pragma once

#include <fltKernel.h>
#include <ntddk.h>
#include <wdm.h>      
#include <ntstrsafe.h>

// defini��o do GUID do mini-filter
extern CONST GUID MiniFilterGuid;

// Estrutura para regra de detec��o
typedef struct RULE_INFO {
    LIST_ENTRY  ListEntry;
    ULONG       Id;
    UNICODE_STRING RuleName;
    ULONG       Flags;
    ULONG       PatternLength;
    PVOID       PatternData;
    // adicionar outros campos conforme necess�rio, como express�es regulares, etc.
} RULE_INFO, * PTR_RULE_INFO;

// Estrutura para passar m�ltiplas regras do user mode
typedef struct RULES_DATA {
    ULONG         NumberOfRules;
    RULE_INFO Rules[1];
} RULES_DATA, * PTR_RULES_DATA;

// Estrutura de alerta de detec��o que ir� ser enviado ao user mode
typedef struct ALERT_DATA {
    LARGE_INTEGER Timestamp;
    ULONG         ProcessId;
    ULONG         ThreadId;
    WCHAR         FilePath[UNICODE_STRING_MAX_BYTES];
    ULONG         DetectionType;
    WCHAR         AlertMessage[256];
} ALERT_DATA, * PTR_ALERT_DATA;

// Estrutura para uma entrada na fila de alertas (inclui LIST_ENTRY para a lista ligada)
typedef struct ALERT_DATA_ENTRY {
    LIST_ENTRY ListEntry;
    ALERT_DATA Alert;
} ALERT_DATA_ENTRY, * PTR_ALERT_DATA_ENTRY;

// Estrutura para monitoramento e exclus�o de caminhos
typedef struct IS_MONITORED_PATH_INFO {
    LIST_ENTRY     ListEntry;
    UNICODE_STRING Path;
    BOOLEAN        IsExcluded;
} IS_MONITORED_PATH_INFO, * PTR_IS_MONITORED_PATH_INFO;

// conexto do driver, contendo todos os recursos necess�rios
// o tipo EX_PUSH_LOCK � usado para proteger o acesso a listas e filas
typedef struct DRIVER_CONTEXT {
    PFLT_PORT   ClientPort;
    LIST_ENTRY  AlertQueue;
    EX_PUSH_LOCK AlertQueueLock;

    LIST_ENTRY  RulesList;
    EX_PUSH_LOCK RulesListLock;

    LIST_ENTRY  MonitoredPathsList;
    EX_PUSH_LOCK MonitoredPathsLock;

    LIST_ENTRY  ExcludedPathsList;
    EX_PUSH_LOCK ExcludedPathsLock;

    BOOLEAN     MonitoringEnabled;
    ULONG       DetectionMode;
    BOOLEAN     BackupOnDetection;

} DRIVER_CONTEXT, * PTR_DRIVER_CONTEXT;

extern DRIVER_CONTEXT g_driverContext;
extern PFLT_FILTER g_FilterHandle;
extern PDEVICE_OBJECT g_DeviceObject;
extern UNICODE_STRING g_DosDeviceName;
extern PFLT_PORT g_ServerPort;

// prototipos de fun��es

// main.c
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT d_Object, _In_ PUNICODE_STRING r_Path);
NTSTATUS Unload(_In_ FLT_FILTER_UNLOAD_FLAGS flags);
NTSTATUS DeviceControl(_In_ PDEVICE_OBJECT deviceObject, _Inout_ PIRP irp);
NTSTATUS ConnectionNotifyCallback(_In_ PFLT_PORT clientPort, _In_ PVOID serverPortCookie, _In_ PVOID connectionContext, _In_ ULONG size, _Out_ PVOID* connectionPortCookie);
VOID DisconnectionNotifyCallback(_In_ PVOID connectionCookie);
NTSTATUS MessageNotifyCallback(_In_ PVOID portCookie, _In_ PVOID inputBuffer, _In_ ULONG inputBufferLength, _Out_ PVOID outputBuffer, _In_ ULONG outputBufferLength, _Out_ PULONG returnOutputBufferLength);

// callbacks.c
extern CONST FLT_OPERATION_REGISTRATION Callbacks[];
FLT_PREOP_CALLBACK_STATUS InPreCreate(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS fltObjects, _Flt_CompletionContext_Outptr_ PVOID* ptr_context);
FLT_POSTOP_CALLBACK_STATUS InPostCreate(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS fltObjects, _In_opt_ PVOID context, _In_ FLT_POST_OPERATION_FLAGS flags);
FLT_PREOP_CALLBACK_STATUS InPreWrite(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS fltObjects, _Flt_CompletionContext_Outptr_ PVOID* ptr_context);
FLT_POSTOP_CALLBACK_STATUS InPostWrite(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS fltObjects, _In_opt_ PVOID context, _In_ FLT_POST_OPERATION_FLAGS flags);

// Callbacks de gerenciamento de inst�ncia
NTSTATUS FLTAPI InstanceConfig(_In_ PCFLT_RELATED_OBJECTS fltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS flags, _In_ DEVICE_TYPE volType, _In_ FLT_FILESYSTEM_TYPE volSysType);
VOID FLTAPI InstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS fltObjects, _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS flags);
VOID FLTAPI InstanceTeardownStart(_In_ PCFLT_RELATED_OBJECTS fltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS flags);
VOID FLTAPI InstanceTeardownComplete(_In_ PCFLT_RELATED_OBJECTS fltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS flags);

// detection.c
BOOLEAN ScanBuffer(_In_ PVOID buffer, _In_ ULONG length, _In_ PUNICODE_STRING fileName, _In_opt_ PEPROCESS process);
BOOLEAN ScanFileContent(_In_ PFILE_OBJECT fileObject, _In_opt_ PEPROCESS process);
NTSTATUS LoadRules(_In_ PTR_RULES_DATA rulesData, _In_ ULONG rulesDataLength);

// mitigation.c 
//NTSTATUS BackupFile(_In_ PFILE_OBJECT fileObject, _In_ PUNICODE_STRING originalFileName);
//VOID KillMaliciousProcess(_In_ PVOID buffer, _In_ ULONG length, _In_ PUNICODE_STRING fileName, _In_ PEPROCESS process);

// communication.c (criar um arquivo separado para comunica��o com o user mode)
NTSTATUS QueueAlert(_In_ ALERT_DATA alertData);
NTSTATUS GetAlert(_Out_ PVOID outputBuffer, _In_ ULONG outputBufferLength, _Out_ PULONG returnOutputBufferLength);

// utils.c (criar um arquivo separado para utilit�rios)
NTSTATUS GetProcessImageName(_In_ HANDLE processId, _Out_ PUNICODE_STRING imageName);

#endif