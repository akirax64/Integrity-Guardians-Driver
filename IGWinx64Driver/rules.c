#include "precompiled.h"   

VOID FreeRulesListInternal(VOID)
{
    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "FreeRulesListInternal: Freeing rules (lock already held)\n");  

    while (!IsListEmpty(&g_driverContext.RulesList)) {
        PLIST_ENTRY listEntry = RemoveHeadList(&g_driverContext.RulesList);
        PTR_RULE_INFO rule = CONTAINING_RECORD(listEntry, RULE_INFO, ListEntry);

        if (rule->PatternData) {
            ExFreePoolWithTag(rule->PatternData, TAG_PATTERN);
            rule->PatternData = NULL;
        }

        if (rule->RuleName.Buffer) {
            ExFreePoolWithTag(rule->RuleName.Buffer, TAG_RULE_NAME);
            rule->RuleName.Buffer = NULL;
        }

        ExFreePoolWithTag(rule, TAG_DATA_RULE);
    }
}

// vai liberar a memória de todas as regras carregadas
VOID
FreeRulesList(VOID)
{
    KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql > PASSIVE_LEVEL) {
        return;
    }

    PAGED_CODE(); // vai rodar em PASSIVE_LEVEL

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Freeing all loaded rules...\n");


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

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PolicyManager: All rules freed.\n");
}

// funcao para carregar as regras no kernel
NTSTATUS
LoadRules(
    _In_ PVOID SerializedBuffer,
    _In_ ULONG BufferLength
)
{
    KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql > PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    NTSTATUS status = STATUS_SUCCESS;
    PUCHAR currentPos = (PUCHAR)SerializedBuffer;
    ULONG bytesProcessed = 0;
    ULONG numRules = 0;

    PAGED_CODE();

    if (!SerializedBuffer || BufferLength < sizeof(ULONG)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "LoadRules: Buffer invalid - Size: %lu, Required: %lu\n",
            BufferLength, sizeof(ULONG));
        return STATUS_INVALID_PARAMETER;
    }

    LIST_ENTRY tempRulesList;
    InitializeListHead(&tempRulesList);

    __try {
        PULONG header = (PULONG)currentPos;
        numRules = *header;
        currentPos += sizeof(ULONG);
        bytesProcessed += sizeof(ULONG);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "LoadRules: Starting to load %lu rules, BufferLength=%lu\n",
            numRules, BufferLength);

        if (numRules == 0) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "LoadRules: No rules to load\n");
            return STATUS_SUCCESS;
        }

        if (numRules > 1000) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "LoadRules: Too many rules: %lu\n", numRules);
            return STATUS_INVALID_PARAMETER;
        }

        for (ULONG i = 0; i < numRules; i++) {
            if (bytesProcessed + sizeof(SERIALIZED_RULE_HEADER) > BufferLength) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "LoadRules: Buffer overflow at rule %lu (header)\n", i);
                status = STATUS_INVALID_PARAMETER;
                goto CleanupTemp;
            }

            PTR_SERIALIZED_RULE_HEADER ruleHeader = (PTR_SERIALIZED_RULE_HEADER)currentPos;
            currentPos += sizeof(SERIALIZED_RULE_HEADER);
            bytesProcessed += sizeof(SERIALIZED_RULE_HEADER);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                "Rule %lu: ID=%u, Type=%u, Flags=0x%X, NameLen=%u, TargetPathLen=%u, PatternLen=%lu\n",
                i, ruleHeader->Id, ruleHeader->Type, ruleHeader->Flags,
                ruleHeader->RuleNameLength, ruleHeader->TargetPathLength,
                ruleHeader->PatternLength);

            if (ruleHeader->RuleNameLength > 1024 || ruleHeader->PatternLength > 4096) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "LoadRules: Rule %lu has invalid lengths\n", i);
                status = STATUS_INVALID_PARAMETER;
                goto CleanupTemp;
            }

            // Calcular tamanho total dos dados
            ULONG ruleDataSize = ruleHeader->RuleNameLength +
                ruleHeader->TargetPathLength +
                ruleHeader->PatternLength;

            if (bytesProcessed + ruleDataSize > BufferLength) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "LoadRules: Buffer overflow at rule %lu (data)\n", i);
                status = STATUS_INVALID_PARAMETER;
                goto CleanupTemp;
            }

            PTR_RULE_INFO newRule = (PTR_RULE_INFO)ExAllocatePool2(
                POOL_FLAG_PAGED, sizeof(RULE_INFO), TAG_DATA_RULE);
            if (!newRule) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "LoadRules: Failed to allocate rule %lu\n", i);
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto CleanupTemp;
            }

            RtlZeroMemory(newRule, sizeof(RULE_INFO));
            InitializeListHead(&newRule->ListEntry);
            newRule->Id = ruleHeader->Id;
            newRule->Flags = ruleHeader->Flags;
            newRule->PatternLength = ruleHeader->PatternLength;

            // Processar nome da regra
            if (ruleHeader->RuleNameLength > 0) {
                newRule->RuleName.Length = ruleHeader->RuleNameLength;
                newRule->RuleName.MaximumLength = ruleHeader->RuleNameLength + sizeof(WCHAR);
                newRule->RuleName.Buffer = (PWSTR)ExAllocatePool2(
                    POOL_FLAG_PAGED, newRule->RuleName.MaximumLength, TAG_RULE_NAME);

                if (!newRule->RuleName.Buffer) {
                    ExFreePoolWithTag(newRule, TAG_DATA_RULE);
                    status = STATUS_INSUFFICIENT_RESOURCES;
                    goto CleanupTemp;
                }

                RtlCopyMemory(newRule->RuleName.Buffer, currentPos, ruleHeader->RuleNameLength);
                newRule->RuleName.Buffer[ruleHeader->RuleNameLength / sizeof(WCHAR)] = L'\0';
                currentPos += ruleHeader->RuleNameLength;
                bytesProcessed += ruleHeader->RuleNameLength;
            }

            // Pular TargetPath
            if (ruleHeader->TargetPathLength > 0) {
                currentPos += ruleHeader->TargetPathLength;
                bytesProcessed += ruleHeader->TargetPathLength;
            }

            // Processar pattern
            if (ruleHeader->PatternLength > 0) {
                newRule->PatternData = ExAllocatePool2(
                    POOL_FLAG_PAGED, ruleHeader->PatternLength, TAG_PATTERN);
                if (!newRule->PatternData) {
                    if (newRule->RuleName.Buffer) {
                        ExFreePoolWithTag(newRule->RuleName.Buffer, TAG_RULE_NAME);
                    }
                    ExFreePoolWithTag(newRule, TAG_DATA_RULE);
                    status = STATUS_INSUFFICIENT_RESOURCES;
                    goto CleanupTemp;
                }

                RtlCopyMemory(newRule->PatternData, currentPos, ruleHeader->PatternLength);
                currentPos += ruleHeader->PatternLength;
                bytesProcessed += ruleHeader->PatternLength;

                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                    "Rule pattern: %.*S\n",
                    ruleHeader->PatternLength / sizeof(WCHAR),
                    (PWSTR)newRule->PatternData);
            }

            InsertTailList(&tempRulesList, &newRule->ListEntry);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "Loaded rule: %wZ (%lu bytes pattern)\n",
                &newRule->RuleName, ruleHeader->PatternLength);
        }

        NTSTATUS lockStatus = AcquirePushLockExclusiveWithTimeout(
            &g_driverContext.RulesListLock, 100);

        if (!NT_SUCCESS(lockStatus)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "LoadRules: Failed to acquire lock for swap: 0x%X\n", lockStatus);
            status = STATUS_TIMEOUT;
            goto CleanupTemp;
        }

        FreeRulesListInternal();

        // Mover lista temporária para lista global
        if (!IsListEmpty(&tempRulesList)) {
            g_driverContext.RulesList.Flink = tempRulesList.Flink;
            g_driverContext.RulesList.Blink = tempRulesList.Blink;
            tempRulesList.Flink->Blink = &g_driverContext.RulesList;
            tempRulesList.Blink->Flink = &g_driverContext.RulesList;

            InitializeListHead(&tempRulesList);
        }

        g_driverContext.MonitoringEnabled = TRUE;

        ExReleasePushLockExclusive(&g_driverContext.RulesListLock);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "LoadRules: Successfully loaded %lu rules, total bytes: %lu\n",
            numRules, bytesProcessed);

        return STATUS_SUCCESS;

    CleanupTemp:
        // Limpar lista temporária em caso de erro
        while (!IsListEmpty(&tempRulesList)) {
            PLIST_ENTRY entry = RemoveHeadList(&tempRulesList);
            PTR_RULE_INFO rule = CONTAINING_RECORD(entry, RULE_INFO, ListEntry);

            if (rule->PatternData) {
                ExFreePoolWithTag(rule->PatternData, TAG_PATTERN);
            }
            if (rule->RuleName.Buffer) {
                ExFreePoolWithTag(rule->RuleName.Buffer, TAG_RULE_NAME);
            }
            ExFreePoolWithTag(rule, TAG_DATA_RULE);
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "LoadRules: Failed with status 0x%X\n", status);
        return status;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "LoadRules: Exception 0x%X\n", GetExceptionCode());
        return GetExceptionCode();
    }
}