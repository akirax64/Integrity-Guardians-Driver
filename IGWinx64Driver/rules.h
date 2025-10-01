#ifndef RULES_H
#define RULES_H

#pragma once
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
VOID
FreeRulesListInternal(VOID);
#endif // RULES_H
