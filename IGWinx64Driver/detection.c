#include "antirnsm.h"
#include "enum.h"

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

	// iteraçao sobre a lista de regras
    listEntry = g_driverContext.RulesList.Flink;
    while (listEntry != &g_driverContext.RulesList) {
        rule = CONTAINING_RECORD(listEntry, RULE_INFO, ListEntry);

		// implementar logicas mais complexas de detecção aqui
        
        if (rule->PatternData && rule->PatternLength > 0 && length >= rule->PatternLength) {
            for (ULONG i = 0; i <= length - rule->PatternLength; ++i) {
                if (RtlCompareMemory((PUCHAR)buffer + i, rule->PatternData, rule->PatternLength) == rule->PatternLength) {
                    DbgPrint("!!! Detection: Rule '%wZ' detected in %wZ !!!\n", &rule->RuleName, fileName);

					// vai notificar o user mode sobre a detecção
                    PTR_ALERT_DATA alert = (PTR_ALERT_DATA)ExAllocatePool2(
                        POOL_FLAG_PAGED, sizeof(ALERT_DATA), TAG_ALERT);
					// se o alert for alocado com sucesso, preenche os dados
                    if (alert) {
                        RtlZeroMemory(alert, sizeof(ALERT_DATA));
                        alert->Timestamp.QuadPart = KeQueryPerformanceCounter(NULL).QuadPart;
                        alert->ProcessId = HandleToUlong(PsGetCurrentProcessId());
                        alert->ThreadId = HandleToUlong(PsGetCurrentThreadId());
                        RtlStringCchCopyW(alert->FilePath, UNICODE_STRING_MAX_CHARS, fileName->Buffer);
						alert->DetectionType = rule->Id; // o id da regra é usado como tipo de detecção
                        RtlStringCchPrintfW(alert->AlertMessage, 256, L"Rule '%wZ' matched.", &rule->RuleName);
						//QueueAlert(alert); criar QueueAlert em communication.c para enviar alertas ao user mode
                        
						//vai liberar a memória do alerta após o envio
                    }
                    detected = TRUE;
                    if (detected && (rule->Flags & RULE_FLAG_MATCH)) { // se for detectado algo e a flag ser acionada, interrompe o loop
                        break;
                    }
                }
            }
        }
		listEntry = listEntry->Flink;
    }
    ExReleasePushLockShared(&g_driverContext.RulesListLock);

    return detected;
}

// função para escanear o conteúdo de um arquivo (precisa de implementação completa)
BOOLEAN
ScanFileContent(
    _In_ PFILE_OBJECT fileObject,
    _In_opt_ PEPROCESS process
)
{
    UNREFERENCED_PARAMETER(fileObject);
    UNREFERENCED_PARAMETER(process);
    DbgPrint("Detection: ScanFileContent - Not fully implemented yet. Reads file content for full scan.\n");
	// implementar a leitura do conteúdo do arquivo em buffers e chamar ScanBuffer
    return FALSE;
}

// funçao de carregamento de regras
NTSTATUS
LoadRules(
    _In_ PTR_RULES_DATA rulesData,
    _In_ ULONG rulesDataLength
)
{
    NTSTATUS status = STATUS_SUCCESS;

    // se os dados de regras forem nulos ou inválidos, retorna erro
    if (!rulesData || rulesDataLength < sizeof(RULES_DATA) || rulesData->NumberOfRules == 0) {
        DbgPrint("Detection: LoadRules - Invalid input data (rulesData or length or NumberOfRules).\n");
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrint("Detection: LoadRules - Received %lu rules.\n", rulesData->NumberOfRules);

    ExAcquirePushLockExclusive(&g_driverContext.RulesListLock);

    // implementar FreeRulesList para liberar toda a memória (PatternData, RuleName.Buffer e a própria RULE_INFO)
    // para cada item na g_driverContext.RulesList.
    // FreeRulesList(&g_AntiRansomwareContext.YaraRulesList);

	// iteração dos dados de regras recebidos 
    
	PUCHAR ptr_currentRuleRawData = (PUCHAR)rulesData->Rules; // apontando para o início dos dados de regras

    for (ULONG i = 0; i < rulesData->NumberOfRules; i++) {
        PTR_RULE_INFO sourceRule = (PTR_RULE_INFO)ptr_currentRuleRawData; // A regra como ela é no buffer de entrada

		// verifica se a regra serializaeda é válida (não nula, comprimento do padrão válido, etc.)
        if (rulesDataLength < (ptr_currentRuleRawData - (PUCHAR)rulesData) + sizeof(RULE_INFO) + sourceRule->PatternLength + sourceRule->RuleName.MaximumLength) {
            DbgPrint("Detection: LoadRules - Buffer too small for rule %lu.\n", i);
            status = STATUS_INVALID_PARAMETER;
            break; 
        }


		// alocaçao de memória para a nova regra
        PTR_RULE_INFO newRule = (PTR_RULE_INFO)ExAllocatePool2(
            POOL_FLAG_PAGED, sizeof(RULE_INFO), TAG_DATA_RULE); // Tag 'DTRL' para Data Rule
        if (!newRule) {
            DbgPrint("Detection: LoadRules - Failed to allocate memory for new rule.\n");
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        RtlZeroMemory(newRule, sizeof(RULE_INFO)); // Limpa a nova estrutura

		// copiando os dados da regra serializada para a nova estrutura
        newRule->Id = sourceRule->Id;
        newRule->Flags = sourceRule->Flags;
        newRule->PatternLength = sourceRule->PatternLength;


		// alocacao e cópia do nome da regra (RuleName)
        if (sourceRule->RuleName.Length > 0 && sourceRule->RuleName.Buffer) {
            PUCHAR pRuleNameData = (PUCHAR)sourceRule->RuleName.Buffer; // Aponta para onde a string está no buffer de entrada

            newRule->RuleName.Length = sourceRule->RuleName.Length;
            newRule->RuleName.MaximumLength = sourceRule->RuleName.MaximumLength + sizeof(WCHAR); 

            // Aloca memória para a string da RuleName
            newRule->RuleName.Buffer = (PWSTR)ExAllocatePool2(
                POOL_FLAG_PAGED, newRule->RuleName.MaximumLength, TAG_RULE_NAME);
            if (!newRule->RuleName.Buffer) {
                DbgPrint("Detection: LoadRules - Failed to allocate memory for RuleName buffer.\n");
				ExFreePoolWithTag(newRule, TAG_RULE_ERROR); // vai liberar a RULE_INFO se falhar
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }
           
            RtlCopyMemory(newRule->RuleName.Buffer, pRuleNameData, newRule->RuleName.Length);
            
			// sempre garantir que a string esteja terminada em nulo
            if (newRule->RuleName.Length < newRule->RuleName.MaximumLength) {
                newRule->RuleName.Buffer[newRule->RuleName.Length / sizeof(WCHAR)] = L'\0';
            }
        }
        else {
            RtlInitUnicodeString(&newRule->RuleName, NULL); // inicializa com string nula se não houver nome
        }

		// alocação e cópia dos dados do padrão (PatternData)
        if (newRule->PatternLength > 0) {
			// inicializa o ponteiro para os dados do padrão
            PUCHAR ptr_PatternDataRaw = (PUCHAR)sourceRule + sizeof(RULE_INFO);

            newRule->PatternData = ExAllocatePool2(
                POOL_FLAG_PAGED, newRule->PatternLength, TAG_PATTERN);
            if (!newRule->PatternData) {
                DbgPrint("Detection: LoadRules - Failed to allocate memory for PatternData.\n");
                if (newRule->RuleName.Buffer) {
                    ExFreePoolWithTag(newRule->RuleName.Buffer, TAG_RULE_NAME); // Libera RuleName se alocada
                }
				ExFreePoolWithTag(newRule, 'RERR'); // Libera a RULE_INFO se falhar
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }
			// vai copiar os dados do padrão para a nova memória alocada
            RtlCopyMemory(newRule->PatternData, ptr_PatternDataRaw, newRule->PatternLength);
        }
        else {
            newRule->PatternData = NULL;
        }

        // adicionando a nova regra à lista global
        InsertTailList(&g_driverContext.RulesList, &newRule->ListEntry);

		// calcula o tamanho da regra serializada para avançar o ponteiro
        ULONG currentRuleSerializedSize = sizeof(RULE_INFO) + sourceRule->PatternLength + sourceRule->RuleName.Length;
        ptr_currentRuleRawData += currentRuleSerializedSize;
    }

    // se houve algum erro no loop, liberar as regras que foram adicionadas
    if (!NT_SUCCESS(status)) {
        // implementar uma função que percorra RulesList e libere todas as RULE_INFO,
        // seus PatternData e RuleName.Buffer.
    }

    ExReleasePushLockExclusive(&g_driverContext.RulesListLock);

    if (NT_SUCCESS(status)) {
        g_driverContext.MonitoringEnabled = TRUE;
        DbgPrint("Detection: Rules loaded successfully. Monitoring Enabled.\n");
    }
    else {
        DbgPrint("Detection: Rules loading failed with status 0x%X.\n", status);
    }

    return status;
}