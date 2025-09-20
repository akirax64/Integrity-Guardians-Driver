#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include "whitelist.h"
#include "globals.h"
#include "safechk.h"

// whitelist paths
static UNICODE_STRING g_DefaultWhitelist[] = {
    RTL_CONSTANT_STRING(L"C:\\Windows\\"),
    RTL_CONSTANT_STRING(L"C:\\Program Files\\"),
    RTL_CONSTANT_STRING(L"C:\\Program Files (x86)\\"),
    RTL_CONSTANT_STRING(L"C:\\ProgramData\\"),
    RTL_CONSTANT_STRING(L"C:\\Temp\\"),
    RTL_CONSTANT_STRING(L"C:\\$Recycle.Bin\\")
};

NTSTATUS InitializeWhitelist(VOID)
{
    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "Whitelist: Initializing default entries\n");

    ExAcquirePushLockExclusive(&g_driverContext.ExcludedPathsLock);

    __try {
        for (ULONG i = 0; i < ARRAYSIZE(g_DefaultWhitelist); i++) {
            PTR_IS_MONITORED_PATH_INFO entry = (PTR_IS_MONITORED_PATH_INFO)ExAllocatePool2(
                POOL_FLAG_PAGED, sizeof(IS_MONITORED_PATH_INFO), TAG_PATTERN);

            if (!entry) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "Whitelist: Failed to allocate entry\n");
                continue;
            }

            RtlZeroMemory(entry, sizeof(IS_MONITORED_PATH_INFO));

            entry->Path.Buffer = (PWSTR)ExAllocatePool2(
                POOL_FLAG_PAGED, g_DefaultWhitelist[i].Length + sizeof(WCHAR), TAG_RULE_NAME);

            if (!entry->Path.Buffer) {
                ExFreePoolWithTag(entry, TAG_PATTERN);
                continue;
            }

            SAFE_COPY(entry->Path.Buffer, g_DefaultWhitelist[i].Buffer, g_DefaultWhitelist[i].Length);

            entry->Path.Length = g_DefaultWhitelist[i].Length;
            entry->Path.MaximumLength = g_DefaultWhitelist[i].Length + sizeof(WCHAR);
            entry->IsExcluded = TRUE;

            InsertTailList(&g_driverContext.ExcludedPathsList, &entry->ListEntry);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "Whitelist: Added %wZ\n", &entry->Path);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "Whitelist: Exception during init: 0x%X\n", GetExceptionCode());
    }

    ExReleasePushLockExclusive(&g_driverContext.ExcludedPathsLock);

    return STATUS_SUCCESS;
}

BOOLEAN IsPathExcluded(_In_ PUNICODE_STRING PathName)
{
    PAGED_CODE();

    if (!PathName || !PathName->Buffer || PathName->Length == 0) {
        return FALSE;
    }

    BOOLEAN isExcluded = FALSE;
    PLIST_ENTRY listEntry;
    PTR_IS_MONITORED_PATH_INFO entry;

    ExAcquirePushLockShared(&g_driverContext.ExcludedPathsLock);

    __try {
        for (listEntry = g_driverContext.ExcludedPathsList.Flink;
            listEntry != &g_driverContext.ExcludedPathsList;
            listEntry = listEntry->Flink) {

            entry = CONTAINING_RECORD(listEntry, IS_MONITORED_PATH_INFO, ListEntry);

            if (!entry->IsExcluded) continue;

            if (!MmIsAddressValid(entry) || !MmIsAddressValid(entry->Path.Buffer)) {
                continue;
            }

            if (PathName->Length >= entry->Path.Length) {
                UNICODE_STRING prefix;
                prefix.Buffer = PathName->Buffer;
                prefix.Length = entry->Path.Length;
                prefix.MaximumLength = entry->Path.Length;

                LONG comparison = -1;

				// comparando o prefixo do path com o entry->Path de forma case insensitive
                SAFE_UNICODE_COMPARE_CASE_INSENSITIVE(prefix, entry->Path, comparison);

                if (comparison == 0) {
                    isExcluded = TRUE;
                    break;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "IsPathExcluded: Exception 0x%X\n", GetExceptionCode());
        isExcluded = FALSE;
    }

    ExReleasePushLockShared(&g_driverContext.ExcludedPathsLock);

    return isExcluded;
}

// adiciona um path na whitelist
NTSTATUS AddExcludedPath(_In_ PUNICODE_STRING Path)
{
    PAGED_CODE();

    if (!Path || !Path->Buffer || Path->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = STATUS_SUCCESS;
    PTR_IS_MONITORED_PATH_INFO entry = (PTR_IS_MONITORED_PATH_INFO)ExAllocatePool2(
        POOL_FLAG_PAGED, sizeof(IS_MONITORED_PATH_INFO), TAG_PATTERN);

    if (!entry) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(entry, sizeof(IS_MONITORED_PATH_INFO));

    __try {
        entry->Path.Buffer = (PWSTR)ExAllocatePool2(
            POOL_FLAG_PAGED, Path->Length + sizeof(WCHAR), TAG_RULE_NAME);

        if (!entry->Path.Buffer) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        SAFE_COPY(entry->Path.Buffer, Path->Buffer, Path->Length);

        entry->Path.Length = Path->Length;
        entry->Path.MaximumLength = Path->Length + sizeof(WCHAR);
        entry->IsExcluded = TRUE;

        ExAcquirePushLockExclusive(&g_driverContext.ExcludedPathsLock);
        InsertTailList(&g_driverContext.ExcludedPathsList, &entry->ListEntry);
        ExReleasePushLockExclusive(&g_driverContext.ExcludedPathsLock);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "Whitelist: Added user path %wZ\n", Path);

        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AddExcludedPath: Exception 0x%X\n", status);
    }

Cleanup:
    if (entry->Path.Buffer) {
        ExFreePoolWithTag(entry->Path.Buffer, TAG_RULE_NAME);
    }
    ExFreePoolWithTag(entry, TAG_PATTERN);

    return status;
}

// remove um path da whitelist
NTSTATUS RemoveExcludedPath(_In_ PUNICODE_STRING Path)
{
    PAGED_CODE();

    if (!Path || !Path->Buffer || Path->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = STATUS_NOT_FOUND;
    PLIST_ENTRY listEntry, nextEntry;
    PTR_IS_MONITORED_PATH_INFO entry;

    ExAcquirePushLockExclusive(&g_driverContext.ExcludedPathsLock);

    __try {
        for (listEntry = g_driverContext.ExcludedPathsList.Flink;
            listEntry != &g_driverContext.ExcludedPathsList;
            listEntry = nextEntry) {

            nextEntry = listEntry->Flink;
            entry = CONTAINING_RECORD(listEntry, IS_MONITORED_PATH_INFO, ListEntry);

            if (!entry->IsExcluded) continue;

            if (!MmIsAddressValid(entry) || !MmIsAddressValid(entry->Path.Buffer)) {
                continue;
            }

            
            if (Path->Length != entry->Path.Length) {
                continue;
            }

            LONG comparison;
            SAFE_UNICODE_COMPARE_CASE_INSENSITIVE(*Path, entry->Path, comparison);

            if (comparison == 0) {
                RemoveEntryList(listEntry);
                ExFreePoolWithTag(entry->Path.Buffer, TAG_RULE_NAME);
                ExFreePoolWithTag(entry, TAG_PATTERN);
                status = STATUS_SUCCESS;
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "RemoveExcludedPath: Exception 0x%X\n", status);
    }

    ExReleasePushLockExclusive(&g_driverContext.ExcludedPathsLock);

    return status;
}

// limpa todas as entradas da whitelist (usadas na desinstalação do driver)
NTSTATUS ClearExcludedPaths(VOID)
{
    PAGED_CODE();

    PLIST_ENTRY listEntry, nextEntry;
    PTR_IS_MONITORED_PATH_INFO entry;

    ExAcquirePushLockExclusive(&g_driverContext.ExcludedPathsLock);

    __try {
        for (listEntry = g_driverContext.ExcludedPathsList.Flink;
            listEntry != &g_driverContext.ExcludedPathsList;
            listEntry = nextEntry) {

            nextEntry = listEntry->Flink;
            entry = CONTAINING_RECORD(listEntry, IS_MONITORED_PATH_INFO, ListEntry);

            if (entry->IsExcluded) {
                RemoveEntryList(listEntry);
                if (entry->Path.Buffer) {
                    ExFreePoolWithTag(entry->Path.Buffer, TAG_RULE_NAME);
                }
                ExFreePoolWithTag(entry, TAG_PATTERN);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "ClearExcludedPaths: Exception 0x%X\n", GetExceptionCode());
    }

    ExReleasePushLockExclusive(&g_driverContext.ExcludedPathsLock);

    return STATUS_SUCCESS;
}

ULONG GetExcludedPathsCount(VOID)
{
    PAGED_CODE();

    ULONG count = 0;
    PLIST_ENTRY listEntry;
    PTR_IS_MONITORED_PATH_INFO entry;

    ExAcquirePushLockShared(&g_driverContext.ExcludedPathsLock);

    __try {
        for (listEntry = g_driverContext.ExcludedPathsList.Flink;
            listEntry != &g_driverContext.ExcludedPathsList;
            listEntry = listEntry->Flink) {

            entry = CONTAINING_RECORD(listEntry, IS_MONITORED_PATH_INFO, ListEntry);
            if (entry->IsExcluded) {
                count++;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "GetExcludedPathsCount: Exception 0x%X\n", GetExceptionCode());
    }

    ExReleasePushLockShared(&g_driverContext.ExcludedPathsLock);

    return count;
}