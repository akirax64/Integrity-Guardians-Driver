#include "precompiled.h"

static UNICODE_STRING g_DefaultWhitelist[] = {
    RTL_CONSTANT_STRING(L"\\Windows\\"),
    RTL_CONSTANT_STRING(L"\\Program Files\\"),
    RTL_CONSTANT_STRING(L"\\Program Files (x86)\\"),
    RTL_CONSTANT_STRING(L"\\ProgramData\\"),
    RTL_CONSTANT_STRING(L"\\Temp\\"),
    RTL_CONSTANT_STRING(L"\\$Recycle.Bin\\")
};

NTSTATUS InitializeWhitelist(VOID)
{
    KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql > PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "Whitelist: Initializing default entries\n");

    // CORRE플O: Usar timeout
    NTSTATUS lockStatus = AcquirePushLockExclusiveWithTimeout(
        &g_driverContext.ExcludedPathsLock, 100);
    if (!NT_SUCCESS(lockStatus)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "InitializeWhitelist: Failed to acquire lock: 0x%X\n", lockStatus);
        return lockStatus;
    }

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

            RtlCopyMemory(entry->Path.Buffer, g_DefaultWhitelist[i].Buffer,
                g_DefaultWhitelist[i].Length);
            entry->Path.Length = g_DefaultWhitelist[i].Length;
            entry->Path.MaximumLength = g_DefaultWhitelist[i].Length + sizeof(WCHAR);
            entry->Path.Buffer[entry->Path.Length / sizeof(WCHAR)] = L'\0';
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
    KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql > PASSIVE_LEVEL) {
        return FALSE;
    }

    PAGED_CODE();

    if (!PathName || !PathName->Buffer || PathName->Length == 0) {
        return FALSE;
    }

    BOOLEAN isExcluded = FALSE;
    PLIST_ENTRY listEntry;
    PTR_IS_MONITORED_PATH_INFO entry;

    NTSTATUS lockStatus = AcquirePushLockSharedWithTimeout(
        &g_driverContext.ExcludedPathsLock, 50);
    if (!NT_SUCCESS(lockStatus)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "IsPathExcluded: Failed to acquire lock: 0x%X\n", lockStatus);
        return FALSE;
    }

    __try {
        for (listEntry = g_driverContext.ExcludedPathsList.Flink;
            listEntry != &g_driverContext.ExcludedPathsList;
            listEntry = listEntry->Flink) {

            entry = CONTAINING_RECORD(listEntry, IS_MONITORED_PATH_INFO, ListEntry);

            if (!entry->IsExcluded) continue;

            if (PathName->Length >= entry->Path.Length) {
                UNICODE_STRING prefix;
                prefix.Buffer = PathName->Buffer;
                prefix.Length = entry->Path.Length;
                prefix.MaximumLength = entry->Path.Length;

                LONG comparison = -1;
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

NTSTATUS AddExcludedPath(_In_ PUNICODE_STRING UserPath)
{
    UNICODE_STRING KernelPath = { 0 };
    NTSTATUS status;

    if (!UserPath || !UserPath->Buffer) {
        return STATUS_INVALID_PARAMETER;
    }

    status = ConvertUserPathToKernelPath(UserPath, &KernelPath);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PTR_IS_MONITORED_PATH_INFO entry = ExAllocatePool2(
        POOL_FLAG_PAGED, sizeof(IS_MONITORED_PATH_INFO), TAG_PATTERN);

    if (!entry) {
        if (KernelPath.Buffer) {
            ExFreePoolWithTag(KernelPath.Buffer, TAG_RULE_NAME);
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(entry, sizeof(IS_MONITORED_PATH_INFO));
    entry->Path = KernelPath;
    entry->IsExcluded = TRUE;

    // CORRE플O: Usar timeout
    NTSTATUS lockStatus = AcquirePushLockExclusiveWithTimeout(
        &g_driverContext.ExcludedPathsLock, 100);
    if (!NT_SUCCESS(lockStatus)) {
        if (KernelPath.Buffer) {
            ExFreePoolWithTag(KernelPath.Buffer, TAG_RULE_NAME);
        }
        ExFreePoolWithTag(entry, TAG_PATTERN);
        return lockStatus;
    }

    InsertTailList(&g_driverContext.ExcludedPathsList, &entry->ListEntry);
    ExReleasePushLockExclusive(&g_driverContext.ExcludedPathsLock);

    return STATUS_SUCCESS;
}

NTSTATUS
ConvertUserPathToKernelPath(
    _In_ PUNICODE_STRING UserPath,
    _Out_ PUNICODE_STRING KernelPath
)
{
    KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql > PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    PAGED_CODE();

    if (!UserPath || !KernelPath || !UserPath->Buffer || UserPath->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = STATUS_SUCCESS;
    KernelPath->Buffer = NULL;
    KernelPath->Length = 0;
    KernelPath->MaximumLength = 0;

    __try {
        BOOLEAN isDrivePath = (UserPath->Length >= 3 * sizeof(WCHAR)) &&
            (UserPath->Buffer[1] == L':') &&
            (UserPath->Buffer[2] == L'\\');

        USHORT newLength = UserPath->Length;
        USHORT sourceOffset = 0;

        if (isDrivePath) {
            sourceOffset = 2 * sizeof(WCHAR);
            newLength = UserPath->Length - sourceOffset;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "ConvertUserPath: Drive path detected, offset: %u, new length: %u\n",
                sourceOffset, newLength);
        }

        USHORT allocSize = newLength + sizeof(WCHAR);
        KernelPath->Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, allocSize, TAG_RULE_NAME);

        if (!KernelPath->Buffer) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (newLength > 0) {
            RtlCopyMemory(KernelPath->Buffer,
                (PUCHAR)UserPath->Buffer + sourceOffset,
                newLength);
        }

        KernelPath->Length = newLength;
        KernelPath->MaximumLength = allocSize;
        KernelPath->Buffer[newLength / sizeof(WCHAR)] = L'\0';

        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        if (KernelPath->Buffer) {
            ExFreePoolWithTag(KernelPath->Buffer, TAG_RULE_NAME);
            KernelPath->Buffer = NULL;
        }
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "ConvertUserPath: Exception 0x%X\n", status);
        return status;
    }
}

NTSTATUS
RemoveExcludedPath(
    _In_ PUNICODE_STRING Path
)
{
    KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql > PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    PAGED_CODE();

    if (!Path || !Path->Buffer || Path->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = STATUS_NOT_FOUND;

    // CORRE플O: Usar timeout
    NTSTATUS lockStatus = AcquirePushLockExclusiveWithTimeout(
        &g_driverContext.ExcludedPathsLock, 100);
    if (!NT_SUCCESS(lockStatus)) {
        return lockStatus;
    }

    __try {
        PLIST_ENTRY listEntry, nextEntry;

        for (listEntry = g_driverContext.ExcludedPathsList.Flink;
            listEntry != &g_driverContext.ExcludedPathsList;
            listEntry = nextEntry) {

            nextEntry = listEntry->Flink;
            PTR_IS_MONITORED_PATH_INFO entry = CONTAINING_RECORD(
                listEntry, IS_MONITORED_PATH_INFO, ListEntry);

            if (!entry->IsExcluded) continue;

            if (Path->Length == entry->Path.Length) {
                LONG comparison;
                SAFE_UNICODE_COMPARE_CASE_INSENSITIVE(*Path, entry->Path, comparison);

                if (comparison == 0) {
                    if (IsListEntryValid(listEntry)) {
                        RemoveEntryList(listEntry);
                        if (entry->Path.Buffer) {
                            ExFreePoolWithTag(entry->Path.Buffer, TAG_RULE_NAME);
                        }
                        ExFreePoolWithTag(entry, TAG_PATTERN);
                        status = STATUS_SUCCESS;
                    }
                    break;
                }
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

NTSTATUS ClearExcludedPaths(VOID)
{
    KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql > PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    PAGED_CODE();

    PLIST_ENTRY listEntry, nextEntry;
    PTR_IS_MONITORED_PATH_INFO entry;

    // CORRE플O: Usar timeout
    NTSTATUS lockStatus = AcquirePushLockExclusiveWithTimeout(
        &g_driverContext.ExcludedPathsLock, 100);
    if (!NT_SUCCESS(lockStatus)) {
        return lockStatus;
    }

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
    KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql > PASSIVE_LEVEL) {
        return 0;
    }

    PAGED_CODE();

    ULONG count = 0;
    PLIST_ENTRY listEntry;
    PTR_IS_MONITORED_PATH_INFO entry;

    NTSTATUS lockStatus = AcquirePushLockSharedWithTimeout(
        &g_driverContext.ExcludedPathsLock, 50);
    if (!NT_SUCCESS(lockStatus)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "GetExcludedPathsCount: Failed to acquire lock: 0x%X\n", lockStatus);
        return 0;
    }

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

NTSTATUS
GetExcludedPathsList(
    _Out_ PTR_EXCLUDED_PATHS_RESPONSE Response,
    _In_ ULONG ResponseBufferSize,
    _Out_ PULONG BytesReturned
)
{
    KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql > PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    PAGED_CODE();

    if (!Response || !BytesReturned) {
        return STATUS_INVALID_PARAMETER;
    }

    return SerializeExcludedPaths(Response, ResponseBufferSize, BytesReturned);
}

NTSTATUS
SerializeExcludedPaths(
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql > PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    PAGED_CODE();

    if (!OutputBuffer || !BytesReturned) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = STATUS_SUCCESS;
    PUCHAR currentPos = (PUCHAR)OutputBuffer;
    ULONG bytesUsed = 0;
    ULONG pathsSerialized = 0;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SerializeExcludedPaths: Buffer size: %lu bytes\n", OutputBufferLength);

    if (bytesUsed + sizeof(ULONG) > OutputBufferLength) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PULONG pathCountHeader = (PULONG)currentPos;
    *pathCountHeader = 0;
    currentPos += sizeof(ULONG);
    bytesUsed += sizeof(ULONG);

    NTSTATUS lockStatus = AcquirePushLockSharedWithTimeout(
        &g_driverContext.ExcludedPathsLock, 50);
    if (!NT_SUCCESS(lockStatus)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "SerializeExcludedPaths: Failed to acquire lock: 0x%X\n", lockStatus);
        return lockStatus;
    }

    __try
    {
        PLIST_ENTRY listEntry;
        PTR_IS_MONITORED_PATH_INFO entry;
        ULONG maxPaths = 1000;

        for (listEntry = g_driverContext.ExcludedPathsList.Flink;
            listEntry != &g_driverContext.ExcludedPathsList && pathsSerialized < maxPaths;
            listEntry = listEntry->Flink)
        {
            entry = CONTAINING_RECORD(listEntry, IS_MONITORED_PATH_INFO, ListEntry);

            if (!entry->IsExcluded || !entry->Path.Buffer ||
                entry->Path.Length == 0 || entry->Path.Length > 4096) {
                continue;
            }

            ULONG pathDataSize = entry->Path.Length + sizeof(WCHAR);
            ULONG totalEntrySize = sizeof(ULONG) + pathDataSize;

            if (bytesUsed + totalEntrySize > OutputBufferLength) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "SerializeExcludedPaths: Buffer full after %lu paths\n", pathsSerialized);
                break;
            }

            PULONG sizeField = (PULONG)currentPos;
            *sizeField = totalEntrySize;
            currentPos += sizeof(ULONG);
            bytesUsed += sizeof(ULONG);

            RtlCopyMemory(currentPos, entry->Path.Buffer, entry->Path.Length);

            PWSTR stringEnd = (PWSTR)((PUCHAR)currentPos + entry->Path.Length);
            *stringEnd = L'\0';

            currentPos += pathDataSize;
            bytesUsed += pathDataSize;
            pathsSerialized++;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                "SerializeExcludedPaths: Path %lu: %wZ\n", pathsSerialized, &entry->Path);
        }

        *pathCountHeader = pathsSerialized;
        *BytesReturned = bytesUsed;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "SerializeExcludedPaths: %lu paths, %lu bytes\n", pathsSerialized, bytesUsed);

        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SerializeExcludedPaths: Exception 0x%X\n", status);

        if (bytesUsed == 0) {
            *pathCountHeader = 0;
            *BytesReturned = sizeof(ULONG);
        }
    }

    ExReleasePushLockShared(&g_driverContext.ExcludedPathsLock);

    return status;
}

ULONG
CalculateExcludedPathsSize(VOID)
{
    KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql > PASSIVE_LEVEL) {
        return 0;
    }

    PAGED_CODE();

    ULONG totalSize = sizeof(ULONG);
    ULONG pathCount = 0;
    PLIST_ENTRY listEntry;
    PTR_IS_MONITORED_PATH_INFO entry;
    ULONG maxPaths = 1000;

    // CORRE플O: Usar timeout
    NTSTATUS lockStatus = AcquirePushLockSharedWithTimeout(
        &g_driverContext.ExcludedPathsLock, 50);
    if (!NT_SUCCESS(lockStatus)) {
        return sizeof(ULONG);
    }

    __try {
        for (listEntry = g_driverContext.ExcludedPathsList.Flink;
            listEntry != &g_driverContext.ExcludedPathsList && pathCount < maxPaths;
            listEntry = listEntry->Flink) {

            entry = CONTAINING_RECORD(listEntry, IS_MONITORED_PATH_INFO, ListEntry);

            if (entry->IsExcluded && entry->Path.Buffer &&
                entry->Path.Length > 0 && entry->Path.Length <= 4096) {

                totalSize += sizeof(ULONG) + entry->Path.Length + sizeof(WCHAR);
                pathCount++;
            }
        }
    }
    __finally {
        ExReleasePushLockShared(&g_driverContext.ExcludedPathsLock);
    }

    return totalSize;
}

BOOLEAN
ValidateUnicodeString(
    _In_ PUNICODE_STRING UserModeString,
    _In_ ULONG MaxLength
)
{
    KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql > PASSIVE_LEVEL) {
        return FALSE;
    }

    PAGED_CODE();

    if (!UserModeString) {
        return FALSE;
    }

    __try {
        if (UserModeString->Length > MaxLength ||
            UserModeString->Length % sizeof(WCHAR) != 0) {
            return FALSE;
        }

        if (UserModeString->Buffer && UserModeString->Length > 0) {
            volatile WCHAR testChar = UserModeString->Buffer[0];
            UNREFERENCED_PARAMETER(testChar);
        }

        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "ValidateUnicodeString: Exception 0x%X\n", GetExceptionCode());
        return FALSE;
    }
}

NTSTATUS
CopyUnicodeStringFromUserMode(
    _In_ PUNICODE_STRING UserModeString,
    _Out_ PUNICODE_STRING KernelModeString
)
{
    KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql > PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    PAGED_CODE();

    if (!UserModeString || !KernelModeString) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = STATUS_SUCCESS;
    KernelModeString->Buffer = NULL;

    __try {
        if (!ValidateUnicodeString(UserModeString, 4096)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (UserModeString->Length == 0) {
            RtlInitUnicodeString(KernelModeString, NULL);
            return STATUS_SUCCESS;
        }

        KernelModeString->Buffer = (PWSTR)ExAllocatePool2(
            POOL_FLAG_PAGED, UserModeString->Length + sizeof(WCHAR), TAG_RULE_NAME);

        if (!KernelModeString->Buffer) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(KernelModeString->Buffer, UserModeString->Buffer, UserModeString->Length);
        KernelModeString->Length = UserModeString->Length;
        KernelModeString->MaximumLength = UserModeString->Length + sizeof(WCHAR);
        KernelModeString->Buffer[UserModeString->Length / sizeof(WCHAR)] = L'\0';

        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "CopyUnicodeStringFromUserMode: Exception 0x%X\n", status);

        if (KernelModeString->Buffer) {
            ExFreePoolWithTag(KernelModeString->Buffer, TAG_RULE_NAME);
            KernelModeString->Buffer = NULL;
        }

        return status;
    }
}