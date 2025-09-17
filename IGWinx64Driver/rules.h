#ifndef RULES_H
#define RULES_H
#include <fltKernel.h> 
#include "antirnsm.h"   

// funcao para carregar regras de detecção de ransomware com base em um buffer de dados
NTSTATUS
LoadRules(
    _In_ PVOID SerializedBuffer,
    _In_ ULONG BufferLength
);

// limpar a memoria usada para as regras carregadas
VOID
FreeRulesList(VOID);

// Funções para gerenciar listas de caminhos monitorados/excluídos (opcional, pode ser implementado mais tarde)
// NTSTATUS ArLoadMonitoredPaths(_In_ PTR_PATH_MONITOR_INFO PathsData, _In_ ULONG PathsDataLength);
// NTSTATUS ArLoadExcludedPaths(_In_ PTR_PATH_MONITOR_INFO PathsData, _In_ ULONG PathsDataLength);
// VOID ArFreePathsList(_Inout_ PLIST_ENTRY ListHead, _In_ PEX_PUSH_LOCK Lock);

#endif // RULES_H
