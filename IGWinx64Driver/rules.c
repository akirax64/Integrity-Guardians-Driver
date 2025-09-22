#include "precompiled.h"   

// vai liberar a memória de todas as regras carregadas
VOID
FreeRulesList(VOID)
{
	PAGED_CODE(); // vai rodar em PASSIVE_LEVEL

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: Freeing all loaded rules...\n");

    
    ExAcquirePushLockExclusive(&g_driverContext.RulesListLock);

    // percorre a lista e libera cada entrada
    while (!IsListEmpty(&g_driverContext.RulesList)) {
        PLIST_ENTRY listEntry = RemoveHeadList(&g_driverContext.RulesList);
        PTR_RULE_INFO rule = CONTAINING_RECORD(listEntry, RULE_INFO, ListEntry);

        // libera a memória do PatternData, se alocada
        if (rule->PatternData) {
            ExFreePoolWithTag(rule->PatternData, TAG_PATTERN);
            rule->PatternData = NULL;
        }

        // libera a memória do RuleName.Buffer, se alocada
        if (rule->RuleName.Buffer) {
            ExFreePoolWithTag(rule->RuleName.Buffer, TAG_RULE_NAME);
            rule->RuleName.Buffer = NULL;
        }

        // libera a própria estrutura RULE_INFO
        ExFreePoolWithTag(rule, TAG_DATA_RULE);
    }

    // libera o lock
    ExReleasePushLockExclusive(&g_driverContext.RulesListLock);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"PolicyManager: All rules freed.\n");
}


// funcao para carregar as regras no kernel
NTSTATUS
LoadRules(
    _In_ PVOID SerializedBuffer,
    _In_ ULONG BufferLength
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUCHAR currentPos = (PUCHAR)SerializedBuffer;
    ULONG bytesProcessed = 0;
    ULONG numRules = 0;

    PAGED_CODE();

    ExAcquirePushLockExclusive(&g_driverContext.RulesListLock);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "=== LoadRules INICIADA ===\n");
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Buffer: %p, Length: %lu\n", SerializedBuffer, BufferLength);

    if (!SerializedBuffer || BufferLength < sizeof(RULES_DATA_HEADER)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "LoadRules: Invalid input (Buffer: %p, Length: %lu)\n",
            SerializedBuffer, BufferLength);
        return STATUS_INVALID_PARAMETER;
    }

    // Lê o número de regras do cabeçalho
    PTR_RULES_DATA_HEADER header = (PTR_RULES_DATA_HEADER)currentPos;
    numRules = header->NumberOfRules;
    currentPos += sizeof(RULES_DATA_HEADER);
    bytesProcessed += sizeof(RULES_DATA_HEADER);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "LoadRules: Processing %lu rules from %lu bytes\n", numRules, BufferLength);

    if (numRules == 0 || numRules > 1000) { // Limite de sanidade
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "LoadRules: Invalid number of rules: %lu\n", numRules);
        return STATUS_INVALID_PARAMETER;
    }

    // Limpa regras existentes
    FreeRulesList();

    // Processa cada regra
    for (ULONG i = 0; i < numRules; i++) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "Processando regra %lu/%lu\n", i + 1, numRules);
        // Verifica se ainda há espaço para o cabeçalho da regra
        if (bytesProcessed + sizeof(SERIALIZED_RULE_HEADER) > BufferLength) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "LoadRules: Buffer too small for rule %lu header\n", i);
            status = STATUS_INVALID_PARAMETER;
            goto LoadRulesCleanup;
        }

        // Lê o cabeçalho da regra serializada
        PTR_SERIALIZED_RULE_HEADER ruleHeader = (PTR_SERIALIZED_RULE_HEADER)currentPos;
        currentPos += sizeof(SERIALIZED_RULE_HEADER);
        bytesProcessed += sizeof(SERIALIZED_RULE_HEADER);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "LoadRules: Rule %lu - NameLen: %u, PatternLen: %lu\n",
            i, ruleHeader->RuleNameLength, ruleHeader->PatternLength);

        // Validações de sanidade
        if (ruleHeader->RuleNameLength > 1024 || ruleHeader->PatternLength > 4096) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "LoadRules: Rule %lu has invalid lengths\n", i);
            status = STATUS_INVALID_PARAMETER;
            goto LoadRulesCleanup;
        }

        // Verifica se há espaço para os dados da regra
        ULONG ruleDataSize = ruleHeader->RuleNameLength + ruleHeader->PatternLength;
        if (bytesProcessed + ruleDataSize > BufferLength) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "LoadRules: Buffer too small for rule %lu data\n", i);
            status = STATUS_INVALID_PARAMETER;
            goto LoadRulesCleanup;
        }

        // Aloca nova regra no kernel
        PTR_RULE_INFO newRule = (PTR_RULE_INFO)ExAllocatePool2(
            POOL_FLAG_PAGED, sizeof(RULE_INFO), TAG_DATA_RULE);
        if (!newRule) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "LoadRules: Failed to allocate memory for rule %lu\n", i);
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto LoadRulesCleanup;
        }

        RtlZeroMemory(newRule, sizeof(RULE_INFO));

        // Copia dados básicos
        newRule->Id = ruleHeader->Id;
        newRule->Flags = ruleHeader->Flags;
        newRule->PatternLength = ruleHeader->PatternLength;

        // Processa o nome da regra
        if (ruleHeader->RuleNameLength > 0) {
            newRule->RuleName.Length = ruleHeader->RuleNameLength;
            newRule->RuleName.MaximumLength = ruleHeader->RuleNameLength + sizeof(WCHAR);

            newRule->RuleName.Buffer = (PWSTR)ExAllocatePool2(
                POOL_FLAG_PAGED, newRule->RuleName.MaximumLength, TAG_RULE_NAME);
            if (!newRule->RuleName.Buffer) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "LoadRules: Failed to allocate RuleName buffer for rule %lu\n", i);
                ExFreePoolWithTag(newRule, TAG_DATA_RULE);
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto LoadRulesCleanup;
            }

            // Copia o nome da regra
            RtlCopyMemory(newRule->RuleName.Buffer, currentPos, ruleHeader->RuleNameLength);
            // Garante terminação nula
            if (newRule->RuleName.Length < newRule->RuleName.MaximumLength) {
                newRule->RuleName.Buffer[newRule->RuleName.Length / sizeof(WCHAR)] = L'\0';
            }

            currentPos += ruleHeader->RuleNameLength;
            bytesProcessed += ruleHeader->RuleNameLength;
        }
        else {
            RtlInitUnicodeString(&newRule->RuleName, NULL);
        }

        // Processa o padrão
        if (ruleHeader->PatternLength > 0) {
            newRule->PatternData = ExAllocatePool2(
                POOL_FLAG_PAGED, ruleHeader->PatternLength, TAG_PATTERN);
            if (!newRule->PatternData) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "LoadRules: Failed to allocate PatternData for rule %lu\n", i);
                if (newRule->RuleName.Buffer) {
                    ExFreePoolWithTag(newRule->RuleName.Buffer, TAG_RULE_NAME);
                }
                ExFreePoolWithTag(newRule, TAG_DATA_RULE);
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto LoadRulesCleanup;
            }

            RtlCopyMemory(newRule->PatternData, currentPos, ruleHeader->PatternLength);
            currentPos += ruleHeader->PatternLength;
            bytesProcessed += ruleHeader->PatternLength;
        }
        else {
            newRule->PatternData = NULL;
        }

        // Adiciona à lista
        InsertTailList(&g_driverContext.RulesList, &newRule->ListEntry);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "LoadRules: Successfully loaded rule %lu: %wZ\n", i, &newRule->RuleName);
    }

LoadRulesCleanup:
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "LoadRules failed (0x%X), cleaning up\n", status);
        FreeRulesList();
    }
    else {
        g_driverContext.MonitoringEnabled = TRUE;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "LoadRules: Successfully loaded %lu rules\n", numRules);
    }

    ExReleasePushLockExclusive(&g_driverContext.RulesListLock);
    return status;
}