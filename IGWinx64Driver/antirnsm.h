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

// Array de regras pré-definidas usando a estrutura existente
typedef struct RULE_DEFINITION {
    CHAR* RuleName;
    UCHAR* Pattern;
    ULONG PatternLength;
    ULONG Flags;
} RULE_DEFINITION, * PTR_RULE_DEFINITION;

// struct para tracking de comportamento
typedef struct _BEHAVIOR_TRACKER {
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;
    PEPROCESS ProcessObject;
    UNICODE_STRING ProcessName;

    // Métricas de comportamento
    ULONG FilesModified;
    ULONG FilesRenamed;
    ULONG FilesDeleted;
    ULONG TotalBytesWritten;
    ULONG HighEntropyWrites;

    // Timestamps
    LARGE_INTEGER FirstDetectionTime;
    LARGE_INTEGER LastDetectionTime;
    LARGE_INTEGER LastAlertTime;

    // Estados
    BOOLEAN AlertTriggered;
    BOOLEAN ProcessTerminated;
    ULONG AlertCount;

    // Pontuação de risco
    ULONG RiskScore;

} BEHAVIOR_TRACKER, * PTR_BEHAVIOR_TRACKER;

// struct de detecção comportamental
typedef struct _BEHAVIOR_CONFIG {
    ULONG MaxFilesPerMinute;
    ULONG MaxBytesPerMinute;
    ULONG EntropyThreshold;
    ULONG RiskScoreThreshold;
    ULONG MaxAlertsPerProcess;
    ULONG FileExtensionChangesThreshold;
} BEHAVIOR_CONFIG, * PBEHAVIOR_CONFIG;

// Estrutura para cabeçalho serializado
#pragma pack(push, 1)
typedef struct SERIALIZED_RULE_HEADER {
    ULONG   Id;                 
    ULONG   Type;                
    ULONG   Flags;               
    USHORT  RuleNameLength;     
    USHORT  TargetPathLength;    
    ULONG   PatternLength;       
    ULONG   MinFileSize;        
    ULONG   MaxFileSize;         
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

// struct para criacao do contexto do cliente
typedef struct _CLIENT_CONTEXT {
    PFLT_PORT ClientPort;
    LIST_ENTRY ListEntry;
    BOOLEAN IsActive;
} CLIENT_CONTEXT, * PTR_CLIENT_CONTEXT;

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

    LIST_ENTRY  ClientList;           // Lista de clientes conectados
    EX_PUSH_LOCK ClientListLock;      // Lock para lista de clientes

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

// struct para resposta de caminhos excluídos
typedef struct EXCLUDED_PATHS_RESPONSE {
    ULONG NumberOfPaths;
    ULONG TotalBufferSize;
    WCHAR PathsBuffer[1];
} EXCLUDED_PATHS_RESPONSE, * PTR_EXCLUDED_PATHS_RESPONSE;
#endif