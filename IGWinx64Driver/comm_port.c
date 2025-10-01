#include "precompiled.h"

// inicializacao da porta de comunicacao do driver
NTSTATUS
InitializeCommunicationPort(
    _In_ PFLT_FILTER filterHandle,
    _In_ PUNICODE_STRING portName
)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttributes;
    PSECURITY_DESCRIPTOR secDescriptor;

    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    PAGED_CODE();

    if (g_driverContext.ClientListLock == 0) {
        ExInitializePushLock(&g_driverContext.ClientListLock);
    }
    InitializeListHead(&g_driverContext.ClientList);

    status = InitializeSecondaryStructures();
    if (!NT_SUCCESS(status)) {

    }

    status = FltBuildDefaultSecurityDescriptor(&secDescriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    InitializeObjectAttributes(
        &objAttributes,
        portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        secDescriptor
    );

    status = FltCreateCommunicationPort(
        filterHandle,
        &g_ServerPort,
        &objAttributes,
        NULL,
        ConnectionNotify,
        DisconnectionNotify,
        MessageNotify,
        1
    );

    FltFreeSecurityDescriptor(secDescriptor);

    if (!NT_SUCCESS(status)) {
        g_ServerPort = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}

// notificacao de conexao do modo de usuario
NTSTATUS
ConnectionNotify(
    _In_ PFLT_PORT clientPort,
    _In_ PVOID serverPortCookie,
    _In_ PVOID connectionContext,
    _In_ ULONG size,
    _Out_ PVOID* connectionPortCookie
)
{
    UNREFERENCED_PARAMETER(serverPortCookie);
    UNREFERENCED_PARAMETER(connectionContext);
    UNREFERENCED_PARAMETER(size);

    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    PAGED_CODE();

    if (clientPort == NULL || connectionPortCookie == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    PTR_CLIENT_CONTEXT clientContext = (PTR_CLIENT_CONTEXT)ExAllocatePool2(
        POOL_FLAG_PAGED, sizeof(CLIENT_CONTEXT), TAG_CLIENT);

    if (!clientContext) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(clientContext, sizeof(CLIENT_CONTEXT));
    clientContext->ClientPort = clientPort;
    clientContext->IsActive = TRUE;

    NTSTATUS lockStatus = AcquirePushLockExclusiveWithTimeout(&g_driverContext.ClientListLock, 100);
    if (!NT_SUCCESS(lockStatus)) {
        ExFreePoolWithTag(clientContext, TAG_CLIENT);
        return lockStatus;
    }

    if (!IsListValid(&g_driverContext.ClientList)) {
        InitializeListHead(&g_driverContext.ClientList);
    }

    InsertTailList(&g_driverContext.ClientList, &clientContext->ListEntry);
    ExReleasePushLockExclusive(&g_driverContext.ClientListLock);

    *connectionPortCookie = clientContext;

    return STATUS_SUCCESS;
}

// notificacao de desconexao do modo de usuario
VOID
DisconnectionNotify(
    _In_ PVOID connectionCookie
)
{
    PTR_CLIENT_CONTEXT clientContext = (PTR_CLIENT_CONTEXT)connectionCookie;

    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return;
    }

    PAGED_CODE();

    if (clientContext == NULL) {
        return;
    }

    NTSTATUS lockStatus = AcquirePushLockExclusiveWithTimeout(&g_driverContext.ClientListLock, 50);
    if (NT_SUCCESS(lockStatus)) {
        if (IsListEntryValid(&clientContext->ListEntry)) {
            PLIST_ENTRY current;
            BOOLEAN found = FALSE;

            // Verificar se ainda está na lista
            for (current = g_driverContext.ClientList.Flink;
                current != &g_driverContext.ClientList;
                current = current->Flink) {
                if (current == &clientContext->ListEntry) {
                    found = TRUE;
                    break;
                }
            }

            if (found) {
                RemoveEntryList(&clientContext->ListEntry);
            }
        }
        ExReleasePushLockExclusive(&g_driverContext.ClientListLock);
    }

    ExFreePoolWithTag(clientContext, TAG_CLIENT);
}

// broadcast de alertas para todos os clientes conectados
NTSTATUS
BroadcastAlertToClients(_In_ PTR_ALERT_DATA AlertData)
{
    KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql > PASSIVE_LEVEL) {
        return QueueAlertDataForLaterProcessing(AlertData);
    }

    PAGED_CODE();

    if (!AlertData) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS lockStatus = AcquirePushLockSharedWithTimeout(&g_driverContext.ClientListLock, 100);
    if (!NT_SUCCESS(lockStatus)) {
        return lockStatus;
    }

    if (!IsListValid(&g_driverContext.ClientList) || IsListEmpty(&g_driverContext.ClientList)) {
        ExReleasePushLockShared(&g_driverContext.ClientListLock);
        return STATUS_SUCCESS;
    }

    NTSTATUS finalStatus = STATUS_SUCCESS;
    ULONG clientsNotified = 0;

    __try {
        PLIST_ENTRY entry;

        for (entry = g_driverContext.ClientList.Flink;
            entry != &g_driverContext.ClientList;
            entry = entry->Flink) {

            if (!IsListEntryValid(entry)) {
                continue;
            }

            PTR_CLIENT_CONTEXT clientContext = CONTAINING_RECORD(entry, CLIENT_CONTEXT, ListEntry);

            if (!clientContext->IsActive || !clientContext->ClientPort) {
                continue;
            }

            __try {
                NTSTATUS sendStatus = FltSendMessage(
                    g_FilterHandle,
                    &clientContext->ClientPort,
                    AlertData,
                    sizeof(ALERT_DATA),
                    NULL,
                    NULL,
                    NULL
                );

                if (NT_SUCCESS(sendStatus)) {
                    clientsNotified++;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                clientContext->IsActive = FALSE;
            }
        }

        finalStatus = clientsNotified > 0 ? STATUS_SUCCESS : STATUS_NO_SUCH_DEVICE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        finalStatus = GetExceptionCode();
    }

    ExReleasePushLockShared(&g_driverContext.ClientListLock);
    return finalStatus;
}

// notificacao de mensagem do modo de usuario
NTSTATUS
MessageNotify(
    _In_ PVOID portCookie,
    _In_ PVOID inputBuffer,
    _In_ ULONG inputBufferLength,
    _Out_ PVOID outputBuffer,
    _In_ ULONG outputBufferLength,
    _Out_ PULONG returnOutputBufferLength
)
{
    UNREFERENCED_PARAMETER(portCookie);
    UNREFERENCED_PARAMETER(inputBuffer);
    UNREFERENCED_PARAMETER(inputBufferLength);

    KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql > PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    PAGED_CODE();

    NTSTATUS status = STATUS_SUCCESS;
    *returnOutputBufferLength = 0;

    if (outputBuffer && outputBufferLength >= sizeof(ALERT_DATA))
    {
        ExAcquirePushLockExclusive(&g_driverContext.AlertQueueLock);

        __try {
            if (!IsListEmpty(&g_driverContext.AlertQueue))
            {
                PLIST_ENTRY listEntry = RemoveHeadList(&g_driverContext.AlertQueue);
                PTR_ALERT_DATA_ENTRY alertEntry = CONTAINING_RECORD(listEntry, ALERT_DATA_ENTRY, ListEntry);

                if (alertEntry && outputBufferLength >= sizeof(ALERT_DATA))
                {
                    RtlCopyMemory(outputBuffer, &alertEntry->Alert, sizeof(ALERT_DATA));
                    *returnOutputBufferLength = sizeof(ALERT_DATA);
                    ExFreePoolWithTag(alertEntry, TAG_ALERT);
                }
                else
                {
                    status = STATUS_BUFFER_TOO_SMALL;
                    if (alertEntry) {
                        InsertHeadList(&g_driverContext.AlertQueue, &alertEntry->ListEntry);
                    }
                }
            }
            else
            {
                status = STATUS_NO_MORE_ENTRIES;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }

        ExReleasePushLockExclusive(&g_driverContext.AlertQueueLock);
    }
    else
    {
        status = STATUS_INVALID_PARAMETER;
    }

    return status;
}

NTSTATUS
GetAlert(
    _Out_ PVOID outputBuffer,
    _In_ ULONG outputBufferLength,
    _Out_ PULONG bytesReturned
)
{
    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    PAGED_CODE();

    NTSTATUS status = STATUS_SUCCESS;
    PTR_ALERT_DATA_ENTRY alertEntry = NULL;
    *bytesReturned = 0;

    if (outputBuffer == NULL || bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(outputBuffer, min(outputBufferLength, sizeof(ALERT_DATA)));

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (outputBufferLength < sizeof(ALERT_DATA)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    __try {
        ProbeForWrite(outputBuffer, sizeof(ALERT_DATA), sizeof(ULONG));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    ExAcquirePushLockExclusive(&g_driverContext.AlertQueueLock);

    __try {
        if (!IsListValid(&g_driverContext.AlertQueue) || IsListEmpty(&g_driverContext.AlertQueue)) {
            RtlZeroMemory(outputBuffer, sizeof(ALERT_DATA));
            *bytesReturned = 0;
            status = STATUS_NO_MORE_ENTRIES;
            __leave;
        }

        PLIST_ENTRY listEntry = g_driverContext.AlertQueue.Flink;

        if (!IsListEntryValid(listEntry) || listEntry == &g_driverContext.AlertQueue) {
            status = STATUS_INTERNAL_ERROR;
            __leave;
        }

        alertEntry = CONTAINING_RECORD(listEntry, ALERT_DATA_ENTRY, ListEntry);

        if (!alertEntry) {
            status = STATUS_INTERNAL_ERROR;
            __leave;
        }

        RemoveEntryList(listEntry);

        ALERT_DATA localAlert;
        RtlZeroMemory(&localAlert, sizeof(ALERT_DATA));

        __try {
            RtlCopyMemory(&localAlert, &alertEntry->Alert, sizeof(ALERT_DATA));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            if (alertEntry) {
                ExFreePoolWithTag(alertEntry, TAG_ALERT);
            }
            status = STATUS_INTERNAL_ERROR;
            __leave;
        }

        if (alertEntry) {
            ExFreePoolWithTag(alertEntry, TAG_ALERT);
        }

        __try {
            RtlCopyMemory(outputBuffer, &localAlert, sizeof(ALERT_DATA));
            *bytesReturned = sizeof(ALERT_DATA);
            status = STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }
    }
    __finally {
        ExReleasePushLockExclusive(&g_driverContext.AlertQueueLock);
    }

    return status;
}

// Funcao para enviar alertas ao modo de usuario
NTSTATUS
AlertToUserMode(
    _In_ PUNICODE_STRING fileName,
    _In_ HANDLE processId,
    _In_ HANDLE threadId,
    _In_ ULONG detectionType,
    _In_ PUNICODE_STRING ruleName
)
{
    KIRQL currentIrql = KeGetCurrentIrql();

    if (currentIrql > PASSIVE_LEVEL) {
        return QueueAlertForLaterProcessing(fileName, processId, threadId, detectionType, ruleName);
    }

    PAGED_CODE();

    if (fileName == NULL || ruleName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    PTR_ALERT_DATA_ENTRY alertEntry = (PTR_ALERT_DATA_ENTRY)ExAllocatePool2(
        POOL_FLAG_PAGED, sizeof(ALERT_DATA_ENTRY), TAG_ALERT);

    if (!alertEntry) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(alertEntry, sizeof(ALERT_DATA_ENTRY));
    InitializeListHead(&alertEntry->ListEntry);

    __try {
        alertEntry->Alert.Timestamp.QuadPart = KeQueryPerformanceCounter(NULL).QuadPart;
        alertEntry->Alert.ProcessId = HandleToUlong(processId);
        alertEntry->Alert.ThreadId = HandleToUlong(threadId);
        alertEntry->Alert.DetectionType = detectionType;

        if (fileName->Buffer != NULL && fileName->Length > 0) {
            RtlStringCchCopyNW(alertEntry->Alert.FilePath,
                ARRAYSIZE(alertEntry->Alert.FilePath),
                fileName->Buffer,
                min(fileName->Length / sizeof(WCHAR), ARRAYSIZE(alertEntry->Alert.FilePath) - 1));
        }

        if (ruleName->Buffer != NULL && ruleName->Length > 0) {
            RtlStringCchPrintfW(alertEntry->Alert.AlertMessage,
                ARRAYSIZE(alertEntry->Alert.AlertMessage),
                L"Rule '%wZ' detected. File: %wS",
                ruleName,
                alertEntry->Alert.FilePath);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ExFreePoolWithTag(alertEntry, TAG_ALERT);
        return GetExceptionCode();
    }

    NTSTATUS status = BroadcastAlertToClients(&alertEntry->Alert);

    if (NT_SUCCESS(status)) {
        ExFreePoolWithTag(alertEntry, TAG_ALERT);
        return STATUS_SUCCESS;
    }

    NTSTATUS lockStatus = AcquirePushLockExclusiveWithTimeout(&g_driverContext.AlertQueueLock, 50);
    if (NT_SUCCESS(lockStatus)) {
        if (!IsListValid(&g_driverContext.AlertQueue)) {
            InitializeListHead(&g_driverContext.AlertQueue);
        }
        InsertTailList(&g_driverContext.AlertQueue, &alertEntry->ListEntry);
        ExReleasePushLockExclusive(&g_driverContext.AlertQueueLock);
    }
    else {
        ExFreePoolWithTag(alertEntry, TAG_ALERT);
    }
    return status;
}

// limpando a porta de comunicacao do driver
VOID
CleanCommunicationPort(VOID)
{
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
    {
        return;
    }

    PAGED_CODE();

    if (g_driverContext.ClientListLock) {
        __try {
            ExAcquirePushLockExclusive(&g_driverContext.ClientListLock);

            while (!IsListEmpty(&g_driverContext.ClientList)) {
                PLIST_ENTRY entry = RemoveHeadList(&g_driverContext.ClientList);
                PTR_CLIENT_CONTEXT clientContext = CONTAINING_RECORD(entry, CLIENT_CONTEXT, ListEntry);

                if (clientContext) {
                    clientContext->ClientPort = NULL;
                    ExFreePoolWithTag(clientContext, TAG_CLIENT);
                }
            }

            InitializeListHead(&g_driverContext.ClientList);
            ExReleasePushLockExclusive(&g_driverContext.ClientListLock);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {

        }
    }

    if (g_driverContext.AlertQueueLock) {
        __try {
            ExAcquirePushLockExclusive(&g_driverContext.AlertQueueLock);

            while (!IsListEmpty(&g_driverContext.AlertQueue)) {
                PLIST_ENTRY entry = RemoveHeadList(&g_driverContext.AlertQueue);
                PTR_ALERT_DATA_ENTRY alertEntry = CONTAINING_RECORD(entry, ALERT_DATA_ENTRY, ListEntry);

                if (alertEntry) {
                    ExFreePoolWithTag(alertEntry, TAG_ALERT);
                }
            }

            InitializeListHead(&g_driverContext.AlertQueue);
            ExReleasePushLockExclusive(&g_driverContext.AlertQueueLock);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {

        }
    }

    if (g_ServerPort) {
        __try {
            FltCloseCommunicationPort(g_ServerPort);
            g_ServerPort = NULL;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            g_ServerPort = NULL;
        }
    }
}

NTSTATUS
QueueAlertDataForLaterProcessing(_In_ PTR_ALERT_DATA AlertData)
{
    NTSTATUS status = STATUS_SUCCESS;
    PTR_ALERT_DATA_ENTRY alertEntry = NULL;

    ULONG poolFlags = (KeGetCurrentIrql() <= APC_LEVEL) ?
        POOL_FLAG_PAGED : POOL_FLAG_NON_PAGED;

    alertEntry = (PTR_ALERT_DATA_ENTRY)ExAllocatePool2(
        poolFlags, sizeof(ALERT_DATA_ENTRY), TAG_ALERT);

    if (!alertEntry) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(alertEntry, sizeof(ALERT_DATA_ENTRY));

    __try {
        RtlCopyMemory(&alertEntry->Alert, AlertData, sizeof(ALERT_DATA));

        if (IsPushLockInitialized(&g_driverContext.AlertQueueLock)) {
            NTSTATUS lockStatus = AcquirePushLockExclusiveWithTimeout(&g_driverContext.AlertQueueLock, 50);

            if (NT_SUCCESS(lockStatus)) {
                if (!IsListValid(&g_driverContext.AlertQueue)) {
                    InitializeListHead(&g_driverContext.AlertQueue);
                }

                InsertTailList(&g_driverContext.AlertQueue, &alertEntry->ListEntry);
                ExReleasePushLockExclusive(&g_driverContext.AlertQueueLock);

                status = STATUS_SUCCESS;
            }
            else {
                ExFreePoolWithTag(alertEntry, TAG_ALERT);
                status = lockStatus;
            }
        }
        else {
            ExFreePoolWithTag(alertEntry, TAG_ALERT);
            status = STATUS_DEVICE_NOT_READY;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (alertEntry) {
            ExFreePoolWithTag(alertEntry, TAG_ALERT);
        }
        status = GetExceptionCode();
    }

    return status;
}

NTSTATUS
QueueAlertForLaterProcessing(
    _In_ PUNICODE_STRING fileName,
    _In_ HANDLE processId,
    _In_ HANDLE threadId,
    _In_ ULONG detectionType,
    _In_ PUNICODE_STRING ruleName
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PTR_ALERT_DATA_ENTRY alertEntry = NULL;

    ULONG poolFlags = (KeGetCurrentIrql() <= APC_LEVEL) ?
        POOL_FLAG_PAGED : POOL_FLAG_NON_PAGED;

    alertEntry = (PTR_ALERT_DATA_ENTRY)ExAllocatePool2(
        poolFlags, sizeof(ALERT_DATA_ENTRY), TAG_ALERT);

    if (!alertEntry) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(alertEntry, sizeof(ALERT_DATA_ENTRY));

    __try {
        alertEntry->Alert.Timestamp = KeQueryPerformanceCounter(NULL);
        alertEntry->Alert.ProcessId = HandleToUlong(processId);
        alertEntry->Alert.ThreadId = HandleToUlong(threadId);
        alertEntry->Alert.DetectionType = detectionType;

        if (fileName && fileName->Buffer && fileName->Length > 0) {
            USHORT copyLength = (USHORT)min((ULONG)fileName->Length,
                sizeof(alertEntry->Alert.FilePath) - sizeof(WCHAR));
            RtlCopyMemory(alertEntry->Alert.FilePath, fileName->Buffer, copyLength);
            alertEntry->Alert.FilePath[copyLength / sizeof(WCHAR)] = L'\0';
        }

        if (ruleName && ruleName->Buffer && ruleName->Length > 0) {
            RtlStringCchPrintfW(alertEntry->Alert.AlertMessage,
                ARRAYSIZE(alertEntry->Alert.AlertMessage),
                L"Detection: %wZ", ruleName);
        }
        else {
            RtlStringCchCopyW(alertEntry->Alert.AlertMessage,
                ARRAYSIZE(alertEntry->Alert.AlertMessage),
                L"Ransomware pattern detected");
        }

        if (IsPushLockInitialized(&g_driverContext.AlertQueueLock)) {
            NTSTATUS lockStatus = AcquirePushLockExclusiveWithTimeout(&g_driverContext.AlertQueueLock, 50);

            if (NT_SUCCESS(lockStatus)) {
                if (!IsListValid(&g_driverContext.AlertQueue)) {
                    InitializeListHead(&g_driverContext.AlertQueue);
                }

                InsertTailList(&g_driverContext.AlertQueue, &alertEntry->ListEntry);
                ExReleasePushLockExclusive(&g_driverContext.AlertQueueLock);

                status = STATUS_SUCCESS;
            }
            else {
                ExFreePoolWithTag(alertEntry, TAG_ALERT);
                status = lockStatus;
            }
        }
        else {
            ExFreePoolWithTag(alertEntry, TAG_ALERT);
            status = STATUS_DEVICE_NOT_READY;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (alertEntry) {
            ExFreePoolWithTag(alertEntry, TAG_ALERT);
        }
        status = GetExceptionCode();
    }

    return status;
}