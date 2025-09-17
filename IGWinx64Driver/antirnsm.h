#ifndef _ANTI_RANSOMWARE_H_
#define _ANTI_RANSOMWARE_H_

#pragma once

#include <fltKernel.h>

// Estrutura para regra de detecção
typedef struct RULE_INFO {
    LIST_ENTRY  ListEntry;
    ULONG       Id;
    UNICODE_STRING RuleName;
    ULONG       Flags;
    ULONG       PatternLength;
    PVOID       PatternData;
    // adicionar outros campos conforme necessário, como expressões regulares, etc.
} RULE_INFO, * PTR_RULE_INFO;


// Estrutura para cabeçalho serializado (deve corresponder ao user-mode)
#pragma pack(push, 1)
typedef struct SERIALIZED_RULE_HEADER {
    ULONG   Id;
    ULONG  Flags;
    USHORT RuleNameLength;
    ULONG  PatternLength;
} SERIALIZED_RULE_HEADER, * PTR_SERIALIZED_RULE_HEADER;
#pragma pack(pop)

// Estrutura do cabeçalho dos dados
typedef struct RULES_DATA_HEADER {
    ULONG NumberOfRules;
} RULES_DATA_HEADER, * PTR_RULES_DATA_HEADER;

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

// contexto do driver, contendo todos os recursos necessários
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

typedef enum DETECTION_MODE {
    DetectionModePassive = 0,   
    DetectionModeActive = 1,    
    DetectionModeMonitorOnly = 2,
} DETECTION_MODE, * PTR_DETECTION_MODE;

typedef struct MONITORING_CONFIG {
    BOOLEAN         EnableMonitoring;   // TRUE para habilitar, FALSE para desabilitar o monitoramento
    DETECTION_MODE  Mode;               // Modo de detecção (Passive, Active, etc.)
    BOOLEAN         BackupOnDetection;  // TRUE para fazer backup do arquivo em caso de detecção
} MONITORING_CONFIG, * PTR_MONITORING_CONFIG;
#endif