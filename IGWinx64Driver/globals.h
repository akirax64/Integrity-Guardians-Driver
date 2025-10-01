#ifndef GLOBALS_H
#define GLOBALS_H

#pragma once

#include "antirnsm.h"
#include "enum.h"

// variaveis globais
extern volatile LONG g_InitializationState;
extern PFLT_FILTER g_FilterHandle;
extern PDEVICE_OBJECT g_DeviceObject;
extern PFLT_PORT g_ServerPort;
extern DRIVER_CONTEXT g_driverContext;
extern UNICODE_STRING g_DeviceName;
extern UNICODE_STRING g_DosDeviceName;
extern UNICODE_STRING g_CryptoRuleName;

// Configuração de detecção comportamental
extern BEHAVIOR_CONFIG g_BehaviorConfig;
// lista de regras de comportamento
extern LIST_ENTRY g_BehaviorTrackerList;
extern EX_PUSH_LOCK g_BehaviorTrackerLock;

// Processos suspeitos conhecidos
extern const WCHAR* g_SuspiciousProcessNames[];
extern ULONG g_SuspiciousProcessNamesCount;

// definicao da lista de registro de callbacks
extern CONST FLT_OPERATION_REGISTRATION Callbacks[];

// definição do GUID do mini-filter
extern CONST GUID MiniFilterGuid;

NTSTATUS
InitializeDriverStructures(VOID);
NTSTATUS
InitializeLockIfNeeded(_Inout_ PEX_PUSH_LOCK Lock, _In_ PCSTR LockName);
NTSTATUS
InitializeSecondaryStructures(VOID);
BOOLEAN
AreCoreStructuresInitialized(VOID);
BOOLEAN
AreAllStructuresInitialized(VOID);
ULONG
CalculateSuspiciousProcessNamesCount(VOID);

#endif // !GLOBALS_H