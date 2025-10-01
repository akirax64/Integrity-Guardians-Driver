#include "precompiled.h"

RULE_DEFINITION g_PredefinedRules[] = {
    // LockBit Family
    {
        "LockBit_Ransomware",
        (UCHAR*)"\x4C\x6F\x63\x6B\x42\x69\x74\x20",
        8,
        RULE_FLAG_MATCH
    },
    {
        "LockBit_Extension",
        (UCHAR*)"\x2E\x6C\x6F\x63\x6B\x62\x69\x74",
        8,
        RULE_FLAG_MATCH
    },

    // Conti Family
    {
        "Conti_Ransomware",
        (UCHAR*)"\x43\x6F\x6E\x74\x69\x20\x52\x61",
        8,
        RULE_FLAG_MATCH
    },
    {
        "Conti_Note",
        (UCHAR*)"\x57\x65\x6C\x63\x6F\x6D\x65\x20\x74\x6F\x20\x43\x6F\x6E\x74\x69",
        16,
        RULE_FLAG_MATCH
    },

    // Ryuk Family
    {
        "Ryuk_Ransomware",
        (UCHAR*)"\x52\x79\x75\x6B\x20",
        5,
        RULE_FLAG_MATCH
    },
    {
        "Ryuk_Note",
        (UCHAR*)"\x52\x59\x55\x4B\x5F\x52\x41\x4E\x53\x4F\x4D",
        11,
        RULE_FLAG_MATCH
    },

    // Phobos Family
    {
        "Phobos_Ransomware",
        (UCHAR*)"\x50\x68\x6F\x62\x6F\x73",
        6,
        RULE_FLAG_MATCH
    },
    {
        "Phobos_Extension",
        (UCHAR*)"\x2E\x70\x68\x6F\x62\x6F\x73",
        7,
        RULE_FLAG_MATCH
    },

    // Maze Family
    {
        "Maze_Ransomware",
        (UCHAR*)"\x4D\x61\x7A\x65\x20",
        5,
        RULE_FLAG_MATCH
    },

    // REvil Family
    {
        "REvil_Ransomware",
        (UCHAR*)"\x52\x45\x76\x69\x6C",
        5,
        RULE_FLAG_MATCH
    },
    {
        "REvil_Sodinokibi",
        (UCHAR*)"\x53\x6F\x64\x69\x6E\x6F\x6B\x69\x62\x69",
        10,
        RULE_FLAG_MATCH
    },

    // Akira Family
    {
        "Akira_Ransomware",
        (UCHAR*)"\x41\x6B\x69\x72\x61",
        5,
        RULE_FLAG_MATCH
    },
    {
        "Akira_Note",
        (UCHAR*)"\x41\x4B\x49\x52\x41\x5F\x52\x41\x4E\x53\x4F\x4D",
        12,
        RULE_FLAG_MATCH
    },

    // WannaCry Family
    {
        "WannaCry_Ransomware",
        (UCHAR*)"\x57\x61\x6E\x6E\x61\x43\x72\x79",
        8,
        RULE_FLAG_MATCH
    },
    {
        "WannaCry_Note",
        (UCHAR*)"\x57\x41\x4E\x4E\x41\x43\x52\x59\x21",
        9,
        RULE_FLAG_MATCH
    },
    {
        "WannaCry_Contact",
        (UCHAR*)"\x77\x61\x6E\x6E\x61\x5F\x64\x65\x63\x72\x79\x70\x74\x40\x62\x69\x67\x6D\x61\x69\x6C\x2E\x63\x6F\x6D",
        24,
        RULE_FLAG_MATCH
    },

    // EternalBlue/NotPetya
    {
        "EternalBlue_Exploit",
        (UCHAR*)"\x45\x74\x65\x72\x6E\x61\x6C\x42\x6C\x75\x65",
        11,
        RULE_FLAG_MATCH
    },
    {
        "NotPetya_Ransomware",
        (UCHAR*)"\x4E\x6F\x74\x50\x65\x74\x79\x61",
        8,
        RULE_FLAG_MATCH
    },

    // Cerber Family
    {
        "Cerber_Ransomware",
        (UCHAR*)"\x43\x65\x72\x62\x65\x72",
        6,
        RULE_FLAG_MATCH
    },

    // GandCrab Family
    {
        "GandCrab_Ransomware",
        (UCHAR*)"\x47\x61\x6E\x64\x43\x72\x61\x62",
        8,
        RULE_FLAG_MATCH
    },

    // Dharma Family
    {
        "Dharma_Ransomware",
        (UCHAR*)"\x44\x68\x61\x72\x6D\x61",
        6,
        RULE_FLAG_MATCH
    },

    // Clop Family
    {
        "Clop_Ransomware",
        (UCHAR*)"\x43\x6C\x6F\x70",
        4,
        RULE_FLAG_MATCH
    },

    // BlackMatter Family
    {
        "BlackMatter_Ransomware",
        (UCHAR*)"\x42\x6C\x61\x63\x6B\x4D\x61\x74\x74\x65\x72",
        11,
        RULE_FLAG_MATCH
    },

    // Hive Family
    {
        "Hive_Ransomware",
        (UCHAR*)"\x48\x69\x76\x65",
        4,
        RULE_FLAG_MATCH
    },

    // BianLian Family
    {
        "BianLian_Ransomware",
        (UCHAR*)"\x42\x69\x61\x6E\x4C\x69\x61\x6E",
        8,
        RULE_FLAG_MATCH
    },

    // Royal Family
    {
        "Royal_Ransomware",
        (UCHAR*)"\x52\x6F\x79\x61\x6C",
        5,
        RULE_FLAG_MATCH
    },

    // Generic ransomware patterns
    {
        "Generic_Crypto_Indicator",
        (UCHAR*)"\x43\x72\x79\x70\x74\x6F",
        6,
        RULE_FLAG_MATCH
    },
    {
        "Ransom_Note_Indicator",
        (UCHAR*)"\x52\x41\x4E\x53\x4F\x4D",
        6,
        RULE_FLAG_MATCH
    },
    {
        "Decrypt_Instruction",
        (UCHAR*)"\x44\x65\x63\x72\x79\x70\x74",
        7,
        RULE_FLAG_MATCH
    },
    {
        "Bitcoin_Payment",
        (UCHAR*)"\x42\x69\x74\x63\x6F\x69\x6E",
        7,
        RULE_FLAG_MATCH
    },
    {
        "Payment_Demand",
        (UCHAR*)"\x70\x61\x79\x20\x74\x6F\x20\x64\x65\x63\x72\x79\x70\x74",
        14,
        RULE_FLAG_MATCH
    }
};

// Função auxiliar para limpar regras carregadas em caso de erro
VOID
CleanupPartiallyLoadedRules(VOID)
{
    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
        "Cleaning up partially loaded rules\n");

    // Assumindo que RulesListLock já está adquirido
    while (!IsListEmpty(&g_driverContext.RulesList)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_driverContext.RulesList);
        PTR_RULE_INFO rule = CONTAINING_RECORD(entry, RULE_INFO, ListEntry);

        if (rule->PatternData) {
            ExFreePoolWithTag(rule->PatternData, TAG_PATTERN);
        }
        if (rule->RuleName.Buffer) {
            ExFreePoolWithTag(rule->RuleName.Buffer, TAG_RULE_NAME);
        }
        ExFreePoolWithTag(rule, TAG_DATA_RULE);
    }

    InitializeListHead(&g_driverContext.RulesList);
}

NTSTATUS
LoadPredefinedRules(VOID)
{
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "Loading %lu predefined rules\n", ARRAYSIZE(g_PredefinedRules));

    ULONG rulesLoaded = 0;
    NTSTATUS finalStatus = STATUS_SUCCESS;

    if (!IsPushLockInitialized(&g_driverContext.RulesListLock)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "RulesListLock not initialized\n");
        return STATUS_INTERNAL_ERROR;
    }

    NTSTATUS lockStatus = AcquirePushLockExclusiveWithTimeout(
        &g_driverContext.RulesListLock, 100);
    if (!NT_SUCCESS(lockStatus)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "Failed to acquire RulesListLock: 0x%X\n", lockStatus);
        return lockStatus;
    }

    if (!IsListValid(&g_driverContext.RulesList)) {
        InitializeListHead(&g_driverContext.RulesList);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "Initialized RulesList\n");
    }

    __try {
        for (ULONG i = 0; i < ARRAYSIZE(g_PredefinedRules); i++) {
            PTR_RULE_DEFINITION preRule = &g_PredefinedRules[i];

            if (!preRule || !preRule->RuleName || preRule->PatternLength == 0 ||
                preRule->PatternLength > 4096 || !preRule->Pattern) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "Skipping invalid predefined rule %lu\n", i);
                continue;
            }

            // Validação de string ANSI
            __try {
                volatile CHAR testChar = preRule->RuleName[0];
                UNREFERENCED_PARAMETER(testChar);

                ULONG nameLength = 0;
                while (nameLength < 256 && preRule->RuleName[nameLength] != '\0') {
                    nameLength++;
                }
                if (nameLength == 0 || nameLength >= 256) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                        "Invalid rule name length for rule %lu\n", i);
                    continue;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "Exception accessing rule name for rule %lu: 0x%X\n",
                    i, GetExceptionCode());
                continue;
            }

            PTR_RULE_INFO newRule = ExAllocatePool2(POOL_FLAG_PAGED,
                sizeof(RULE_INFO), TAG_DATA_RULE);
            if (!newRule) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "Failed to allocate rule structure for rule %lu\n", i);

                finalStatus = STATUS_INSUFFICIENT_RESOURCES;
                CleanupPartiallyLoadedRules();
                break;
            }

            RtlZeroMemory(newRule, sizeof(RULE_INFO));
            InitializeListHead(&newRule->ListEntry);

            ANSI_STRING ansiName;
            UNICODE_STRING uniName = { 0 };
            BOOLEAN nameAllocated = FALSE;
            BOOLEAN patternAllocated = FALSE;
            BOOLEAN ruleAddedToList = FALSE;

            __try {
                RtlInitAnsiString(&ansiName, preRule->RuleName);

                if (ansiName.Length == 0 || ansiName.Length > 255) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                        "Invalid ANSI name length for rule %lu: %d\n", i, ansiName.Length);
                    __leave;
                }

                uniName.MaximumLength = (USHORT)(ansiName.Length * sizeof(WCHAR) + sizeof(WCHAR));
                uniName.Buffer = ExAllocatePool2(POOL_FLAG_PAGED,
                    uniName.MaximumLength, TAG_RULE_NAME);

                if (!uniName.Buffer) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                        "Failed to allocate Unicode name buffer for rule %lu\n", i);
                    __leave;
                }
                nameAllocated = TRUE;

                NTSTATUS convertStatus = RtlAnsiStringToUnicodeString(&uniName, &ansiName, FALSE);
                if (!NT_SUCCESS(convertStatus)) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                        "Failed to convert ANSI to Unicode for rule %lu: 0x%X\n", i, convertStatus);
                    __leave;
                }

                newRule->RuleName = uniName;

                newRule->PatternData = ExAllocatePool2(POOL_FLAG_PAGED,
                    preRule->PatternLength, TAG_PATTERN);
                if (!newRule->PatternData) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                        "Failed to allocate pattern data for rule %lu\n", i);
                    __leave;
                }
                patternAllocated = TRUE;

                __try {
                    RtlCopyMemory(newRule->PatternData, preRule->Pattern, preRule->PatternLength);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                        "Exception copying pattern data for rule %lu: 0x%X\n",
                        i, GetExceptionCode());
                    __leave;
                }

                newRule->PatternLength = preRule->PatternLength;
                newRule->Id = i + 1;
                newRule->Flags = preRule->Flags;

                if (!IsListEntryValid(&newRule->ListEntry)) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                        "Invalid ListEntry for rule %lu\n", i);
                    __leave;
                }

                InsertTailList(&g_driverContext.RulesList, &newRule->ListEntry);
                ruleAddedToList = TRUE;

                rulesLoaded++;

                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                    "Successfully loaded predefined rule: %wZ (%lu bytes)\n",
                    &newRule->RuleName, preRule->PatternLength);

            }
            __finally {
                if (AbnormalTermination() || !ruleAddedToList) {
                    if (nameAllocated && uniName.Buffer) {
                        ExFreePoolWithTag(uniName.Buffer, TAG_RULE_NAME);
                    }
                    if (patternAllocated && newRule->PatternData) {
                        ExFreePoolWithTag(newRule->PatternData, TAG_PATTERN);
                    }
                    if (newRule && !ruleAddedToList) {
                        ExFreePoolWithTag(newRule, TAG_DATA_RULE);
                    }
                }
            }
        }

        if (rulesLoaded == 0) {
            finalStatus = STATUS_UNSUCCESSFUL;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "No rules were successfully loaded\n");
        }
        else {
            finalStatus = STATUS_SUCCESS;
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "Predefined rules loading completed: %lu/%lu rules loaded\n",
            rulesLoaded, ARRAYSIZE(g_PredefinedRules));

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        finalStatus = GetExceptionCode();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "Exception in LoadPredefinedRules: 0x%X\n", finalStatus);

        CleanupPartiallyLoadedRules();
    }

    ExReleasePushLockExclusive(&g_driverContext.RulesListLock);

    return finalStatus;
}