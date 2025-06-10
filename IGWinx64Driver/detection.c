#include "antirnsm.h"

BOOLEAN
ScanBuffer(
    _In_ PVOID buffer,
    _In_ ULONG length,
    _In_ PUNICODE_STRING fileName,
    _In_opt_ PEPROCESS process
)
{
    UNREFERENCED_PARAMETER(process);

	// se nao houver buffer ou comprimento, retorna FALSE
    if (!buffer || length == 0) {
        return FALSE;
    }

    DbgPrint("Detection: Scanning buffer for %wZ...\n", fileName);

    // Proteger o acesso à lista de regras enquanto escaneia
    ExAcquirePushLockShared(&g_driverContext.RulesListLock);

	// variáveis para iteração e detecção
    PLIST_ENTRY listEntry = NULL;
    PTR_RULE_INFO rule = NULL;
    BOOLEAN detected = FALSE;

    // Iterar sobre as regras de detecção carregadas
    listEntry = g_driverContext.RulesList.Flink;
    while (listEntry != &g_driverContext.RulesList) {
        rule = CONTAINING_RECORD(listEntry, RULE_INFO, ListEntry);

        // TODO: Implementar a lógica de busca de padrões mais sofisticada (Boyer-Moore, Aho-Corasick)
        // Por enquanto, um simples RtlCompareMemory (como a string "RANSOM")
        if (rule->PatternData && rule->PatternLength > 0 && length >= rule->PatternLength) {
            for (ULONG i = 0; i <= length - rule->PatternLength; ++i) {
                if (RtlCompareMemory((PUCHAR)buffer + i, rule->PatternData, rule->PatternLength) == rule->PatternLength) {
                    DbgPrint("!!! Detection: Rule '%wZ' detected in %wZ !!!\n", &rule->RuleName, fileName);

                    // Notificar o user mode sobre a detecção
                    PTR_ALERT_DATA alert = (PTR_ALERT_DATA)ExAllocatePoolWithTag(
                        NonPagedPool, sizeof(ALERT_DATA), 'ALRT'); // Alocar no NonPagedPool para alerts
                    if (alert) {
                        RtlZeroMemory(alert, sizeof(ALERT_DATA));
                        alert->Timestamp.QuadPart = KeQueryPerformanceCounter(NULL).QuadPart;
                        alert->ProcessId = HandleToUlong(PsGetCurrentProcessId());
                        alert->ThreadId = HandleToUlong(PsGetCurrentThreadId());
                        RtlStringCchCopyW(alert->FilePath, UNICODE_STRING_MAX_CHARS, fileName->Buffer);
                        alert->DetectionType = rule->Id; // Usar o RuleId como tipo de detecção
                        RtlStringCchPrintfW(alert->AlertMessage, 256, L"Rule '%wZ' matched.", &rule->RuleName);
						//QueueAlert(alert); criar QueueAlert em communication.c para enviar alertas ao user mode
                        // A memória do alert será liberada por ArGetAlert quando o user mode o consumir
                    }
                    detected = TRUE;
                    break; // Regra detectada, pode parar de procurar por esta regra
                }
            }
        }
        if (detected && (rule->Flags & 0x01)) { // Exemplo: Flag para parar após primeira detecção
            break;
        }

        listEntry = listEntry->Flink;
    }

    ExReleasePushLockShared(&g_driverContext.RulesListLock);

    return detected;
}

// Exemplo: Função para escanear o conteúdo completo de um arquivo (requer mais implementação)
BOOLEAN
ScanFileContent(
    _In_ PFILE_OBJECT fileObject,
    _In_opt_ PEPROCESS process
)
{
    UNREFERENCED_PARAMETER(fileObject);
    UNREFERENCED_PARAMETER(process);
    DbgPrint("Detection: ScanFileContent - Not fully implemented yet. Reads file content for full scan.\n");
    // Implementar leitura do arquivo em chunks e passar para ArScanBuffer
    return FALSE;
}

// Função para carregar as regras de detecção do user mode
NTSTATUS
LoadRules(
    _In_ PTR_RULES_DATA rulesData,
    _In_ ULONG rulesDataLength
)
{
    if (!rulesData || rulesDataLength < sizeof(RULES_DATA) || rulesData->NumberOfRules == 0) {
        DbgPrint("Detection: ArLoadRules - Invalid input data.\n");
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrint("Detection: ArLoadRules - Received %lu rules.\n", rulesData->NumberOfRules);

    ExAcquirePushLockExclusive(&g_driverContext.RulesListLock);

    // TODO: Primeiramente, limpar as regras existentes (se houver) para evitar vazamentos
    // ArFreeRulesList(&g_AntiRansomwareContext.YaraRulesList);

    // Iterar sobre os dados recebidos e adicionar as novas regras
    PUCHAR currentRulePtr = (PUCHAR)rulesData->Rules;
    for (ULONG i = 0; i < rulesData->NumberOfRules; i++) {
        PTR_RULE_INFO newRule = (PTR_RULE_INFO)ExAllocatePoolWithTag(
            PagedPool, sizeof(RULE_INFO), 'YRLR');
        if (!newRule) {
            DbgPrint("Detection: ArLoadRules - Failed to allocate memory for new rule.\n");
            // TODO: Tratar falha, talvez reverter regras adicionadas
            ExReleasePushLockExclusive(&g_driverContext.RulesListLock);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(newRule, sizeof(RULE_INFO));

        // Copiar os dados da regra do buffer de entrada
        RtlCopyMemory(newRule, currentRulePtr, sizeof(RULE_INFO));

        // Se o padrão de dados está em um buffer separado, alocá-lo e copiá-lo
        // NOTA: Para esta demonstração, assumimos que PatternData é um offset ou que já está no lugar certo.
        // Em um sistema real, você alocaria newRule->PatternData e copiaria de RulesData->Rules + offset.
        // newRule->PatternData = (PCHAR)ExAllocatePoolWithTag(PagedPool, newRule->PatternLength, 'PATT');
        // if (newRule->PatternData) {
        //     RtlCopyMemory(newRule->PatternData, currentRulePtr + sizeof(AR_YARA_RULE_INFO), newRule->PatternLength);
        // }


        InsertTailList(&g_driverContext.RulesList, &newRule->ListEntry);

        // Mover para a próxima regra no buffer de entrada
        currentRulePtr += sizeof(RULE_INFO) + newRule->PatternLength; // Ajustar conforme a estrutura real
    }

    ExReleasePushLockExclusive(&g_driverContext.RulesListLock);

    g_driverContext.MonitoringEnabled = TRUE; // Habilita o monitoramento ao carregar regras
    DbgPrint("Detection: Rules loaded successfully. Monitoring Enabled.\n");

    return STATUS_SUCCESS;
}