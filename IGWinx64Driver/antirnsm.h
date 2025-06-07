#ifndef _ANTI_RANSOMWARE_DRIVER_H_
#define _ANTI_RANSOMWARE_DRIVER_H_

#pragma once

#include <fltKernel.h>
#include <ntddk.h>
#include <wdm.h>      
#include <ntstrsafe.h>

// definição do GUID do mini-filter
extern CONST GUID MiniFilterGuid;

// link simbólico para comunicação com o user mode
#define DEVICE_NAME     L"\\Host\\IGAntiRansomware"
#define DOS_DEVICE_NAME L"\\DOSCallHost\\IGAntiRansomware"

// identificador único para o nosso driver para comunicação com o user mode.
#define DEVICE_ID 0x8000

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

// Estrutura para regra de detecção
typedef struct RULE_INFO {
    LIST_ENTRY  ListEntry;
    ULONG       Id;
    UNICODE_STRING RuleName;
    ULONG       Flags;
    ULONG       PatternLength;
    PCHAR       PatternData;
    // adicionar outros campos conforme necessário, como expressões regulares, etc.
} RULE_INFO, * PTR_RULE_INFO;

// Estrutura para passar múltiplas regras do user mode
typedef struct RULES_DATA {
    ULONG         NumberOfRules;
    RULE_INFO Rules[1];
} RULES_DATA, * PTR_RULES_DATA;

// Estrutura de alerta de detecção que irá ser enviado ao user mode
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

// Estrutura para monitoramento e exclusão de caminhos
typedef struct IS_MONITORED_PATH_INFO {
    LIST_ENTRY     ListEntry;
    UNICODE_STRING Path;
    BOOLEAN        IsExcluded;
} IS_MONITORED_PATH_INFO, * PTR_IS_MONITORED_PATH_INFO;

// conexto do driver, contendo todos os recursos necessários
// o tipo EX_PUSH_LOCK é usado para proteger o acesso a listas e filas
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

// prototipos de funções

// main.c
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT d_Object, _In_ PUNICODE_STRING r_Path);
NTSTATUS Unload(_In_ FLT_FILTER_UNLOAD_FLAGS flags);
NTSTATUS DeviceControl(_In_ PDEVICE_OBJECT deviceObject, _Inout_ PIRP irp);
NTSTATUS ConnectionNotifyCallback(_In_ PFLT_PORT clientPort, _In_ PVOID serverPortCookie, _In_ PVOID connectionContext, _In_ ULONG size, _Out_ PVOID* connectionPortCookie);
VOID DisconnectionNotifyCallback(_In_ PVOID connectionCookie);
NTSTATUS MessageNotifyCallback(_In_ PVOID portCookie, _In_ PVOID inputBuffer, _In_ ULONG inputBufferLength, _Out_ PVOID outputBuffer, _In_ ULONG outputBufferLength, _Out_ PULONG returnOutputBufferLength);

// callbacks.c (criar um arquivo separado para callbacks)
extern CONST FLT_OPERATION_REGISTRATION Callbacks[];
FLT_PREOP_CALLBACK_STATUS InPreCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
FLT_POSTOP_CALLBACK_STATUS InPostCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS InPreWrite(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
FLT_POSTOP_CALLBACK_STATUS InPostWrite(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);

// Callbacks de gerenciamento de instância
NTSTATUS FLTAPI InstanceConfig(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags, _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);
VOID FLTAPI InstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);
VOID FLTAPI InstanceTeardownStart(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);
VOID FLTAPI InstanceTeardownComplete(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

// detection.c (criar um arquivo separado para detecção)
BOOLEAN ScanBuffer(_In_ PVOID Buffer, _In_ ULONG Length, _In_ PUNICODE_STRING FileName, _In_opt_ PEPROCESS Process);
BOOLEAN ScanFileContent(_In_ PFILE_OBJECT FileObject, _In_opt_ PEPROCESS Process);
NTSTATUS LoadRules(_In_ RULES_DATA RulesData, _In_ ULONG RulesDataLength);

// mitigation.c (criar um arquivo separado para mitigação)
NTSTATUS BackupFile(_In_ PFILE_OBJECT FileObject, _In_ PUNICODE_STRING OriginalFileName);
VOID TerminateProcess(_In_ PEPROCESS Process);

// communication.c (criar um arquivo separado para comunicação com o user mode)
NTSTATUS QueueAlert(_In_ ALERT_DATA AlertData);
NTSTATUS GetAlert(_Out_ PVOID OutputBuffer, _In_ ULONG OutputBufferLength, _Out_ PULONG ReturnOutputBufferLength);

// utils.c (criar um arquivo separado para utilitários)
NTSTATUS GetProcessImageName(_In_ HANDLE ProcessId, _Out_ PUNICODE_STRING ImageName);

#endif