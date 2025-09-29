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

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Initializing communication port...\n");

    if (g_driverContext.ClientListLock == 0) {
        ExInitializePushLock(&g_driverContext.ClientListLock);
    }
    InitializeListHead(&g_driverContext.ClientList);

    status = InitializeSecondaryStructures();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Secondary structures not ready. (0x%X)\n", status);
    }

    status = FltBuildDefaultSecurityDescriptor(&secDescriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Failed to build security descriptor: (0x%X)\n", status);
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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Failed to create the security descriptor. (0x%X)\n", status);
        g_ServerPort = NULL;
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Communication port initialized with success!\n");
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

    if (KeGetCurrentIrql > PASSIVE_LEVEL) {
		return STATUS_INVALID_DEVICE_STATE;
    }

    PAGED_CODE();

    if (clientPort == NULL || connectionPortCookie == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ConnectionNotify: Parametros invalidos\n");
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: User mode connected! ClientPort: %p\n", clientPort);

    PTR_CLIENT_CONTEXT clientContext = (PTR_CLIENT_CONTEXT)ExAllocatePool2(
        POOL_FLAG_PAGED, sizeof(CLIENT_CONTEXT), TAG_CLIENT);

    if (!clientContext) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ConnectionNotify: Failed to allocate client context\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(clientContext, sizeof(CLIENT_CONTEXT));
    clientContext->ClientPort = clientPort;
    clientContext->IsActive = TRUE;
    if (!IsListValid(&g_driverContext.ClientList)) {
        InitializeListHead(&g_driverContext.ClientList);
    }


    NTSTATUS lockStatus = AcquirePushLockExclusiveWithTimeout(&g_driverContext.ClientListLock, 100);
    if (!NT_SUCCESS(lockStatus)) {
        ExFreePoolWithTag(clientContext, TAG_CLIENT);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to acquire client list lock: 0x%X\n", lockStatus);
        return lockStatus;
    }
    InsertTailList(&g_driverContext.ClientList, &clientContext->ListEntry);
    ExReleasePushLockExclusive(&g_driverContext.ClientListLock);

    *connectionPortCookie = clientContext;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Client added to broadcast list: %p\n", clientPort);

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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "DisconnectionNotify: Null context\n");
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: User mode disconnected. ClientPort: %p\n", clientContext->ClientPort);

    NTSTATUS lockStatus = AcquirePushLockExclusiveWithTimeout(&g_driverContext.ClientListLock, 50);
    if (NT_SUCCESS(lockStatus)) {
        if (IsListEntryValid(&clientContext->ListEntry)) {
            // Verificar se ainda está na lista
            PLIST_ENTRY current;
            BOOLEAN found = FALSE;
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
}

// broadcast de alertas para todos os clientes conectados
NTSTATUS
BroadcastAlertToClients(
    _In_ PTR_ALERT_DATA AlertData
)
{
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    PAGED_CODE();

    if (AlertData == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BroadcastAlertToClients: AlertData is NULL\n");
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS acquireStatus = AcquirePushLockSharedWithTimeout(&g_driverContext.ClientListLock, 100);
    if (!NT_SUCCESS(acquireStatus)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "BroadcastAlertToClients: Failed to acquire client list lock: 0x%X\n", acquireStatus);
        return acquireStatus;
    }

    // Verificar se há clientes conectados
    if (IsListEmpty(&g_driverContext.ClientList) ||
        !IsListValid(&g_driverContext.ClientList)) {
        ExReleasePushLockShared(&g_driverContext.ClientListLock);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BroadcastAlertToClients: No clients connected\n");
        return STATUS_SUCCESS;
    }

    ULONG activeClients = 0;
    PLIST_ENTRY entry;
    for (entry = g_driverContext.ClientList.Flink;
        entry != &g_driverContext.ClientList;
        entry = entry->Flink) {

        if (!IsListEntryValid(entry)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Invalid list entry during client count\n");
            break;
        }

        PTR_CLIENT_CONTEXT client = CONTAINING_RECORD(entry, CLIENT_CONTEXT, ListEntry);
        if (client && client->IsActive && client->ClientPort) {
            activeClients++;
        }
    }

    if (activeClients == 0) {
        ExReleasePushLockShared(&g_driverContext.ClientListLock);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BroadcastAlertToClients: No active clients\n");
        return STATUS_SUCCESS;
    }

    // Alocar buffer para mensagem
    PVOID messageBuffer = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(ALERT_DATA), TAG_MESSAGE);
    if (!messageBuffer) {
        ExReleasePushLockShared(&g_driverContext.ClientListLock);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BroadcastAlertToClients: Failed to allocate message buffer\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        RtlCopyMemory(messageBuffer, AlertData, sizeof(ALERT_DATA));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ExReleasePushLockShared(&g_driverContext.ClientListLock);
        ExFreePoolWithTag(messageBuffer, TAG_MESSAGE);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BroadcastAlertToClients: Exception copying alert data\n");
        return GetExceptionCode();
    }

    ULONG clientsNotified = 0;
    ULONG clientsTotal = 0;

    for (entry = g_driverContext.ClientList.Flink;
        entry != &g_driverContext.ClientList;
        entry = entry->Flink) {

        if (!IsListEntryValid(entry)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Invalid list entry during broadcast\n");
            continue;
        }

        PTR_CLIENT_CONTEXT clientContext = CONTAINING_RECORD(entry, CLIENT_CONTEXT, ListEntry);
        clientsTotal++;

        if (!clientContext || !clientContext->IsActive || !clientContext->ClientPort) {
            continue;
        }

        __try {
            NTSTATUS sendStatus = FltSendMessage(
                g_FilterHandle,
                &clientContext->ClientPort,
                messageBuffer,
                sizeof(ALERT_DATA),
                NULL,
                NULL,
                NULL
            );

            if (NT_SUCCESS(sendStatus)) {
                clientsNotified++;
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                    "BroadcastAlertToClients: Successfully notified client %p\n", clientContext->ClientPort);
            }
            else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "BroadcastAlertToClients: Failed to notify client %p: 0x%X\n",
                    clientContext->ClientPort, sendStatus);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "BroadcastAlertToClients: Exception notifying client %p\n", clientContext->ClientPort);
        }
    }

    ExReleasePushLockShared(&g_driverContext.ClientListLock);
    ExFreePoolWithTag(messageBuffer, TAG_MESSAGE);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "BroadcastAlertToClients: Notified %lu of %lu clients (total active: %lu)\n",
        clientsNotified, clientsTotal, activeClients);

    return clientsNotified > 0 ? STATUS_SUCCESS : STATUS_NO_SUCH_DEVICE;
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

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Message received from user mode! Length: %lu\n", inputBufferLength);

    NTSTATUS status = STATUS_SUCCESS;
    *returnOutputBufferLength = 0;

    if (outputBuffer && outputBufferLength >= sizeof(ALERT_DATA))
    {
        ExAcquirePushLockExclusive(&g_driverContext.AlertQueueLock);

        if (!IsListEmpty(&g_driverContext.AlertQueue))
        {
            PLIST_ENTRY listEntry = RemoveHeadList(&g_driverContext.AlertQueue);
            PTR_ALERT_DATA_ENTRY alertEntry = CONTAINING_RECORD(listEntry, ALERT_DATA_ENTRY, ListEntry);

            if (alertEntry && outputBufferLength >= sizeof(ALERT_DATA))
            {
                RtlCopyMemory(outputBuffer, &alertEntry->Alert, sizeof(ALERT_DATA));
                *returnOutputBufferLength = sizeof(ALERT_DATA);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Send alert to user mode. File: %wS\n", alertEntry->Alert.FilePath);
                ExFreePoolWithTag(alertEntry, TAG_ALERT);
            }
            else
            {
                status = STATUS_BUFFER_TOO_SMALL;
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Output buffer too small for alert.\n");
                if (alertEntry) {
                    InsertHeadList(&g_driverContext.AlertQueue, &alertEntry->ListEntry);
                }
            }
        }
        else
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Alert queue empty.\n");
            status = STATUS_NO_MORE_ENTRIES;
        }

        ExReleasePushLockExclusive(&g_driverContext.AlertQueueLock);
    }
    else
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Output buffer invalid for MessageNotifyCallback.\n");
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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "GetAlert: Parâmetros de saída inválidos\n");
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(outputBuffer, min(outputBufferLength, sizeof(ALERT_DATA)));

    if (KeGetCurrentIrql() > APC_LEVEL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "GetAlert: IRQL muito alto (%d) - requer PASSIVE_LEVEL\n",
            KeGetCurrentIrql());
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (outputBufferLength < sizeof(ALERT_DATA)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    __try {
        ProbeForWrite(outputBuffer, sizeof(ALERT_DATA), sizeof(ULONG));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "GetAlert: Buffer user-mode inacessível\n");
        return GetExceptionCode();
    }

    ExAcquirePushLockExclusive(&g_driverContext.AlertQueueLock);

    if (!MmIsAddressValid(&g_driverContext.AlertQueue) ||
        !MmIsAddressValid(g_driverContext.AlertQueue.Flink) ||
        !MmIsAddressValid(g_driverContext.AlertQueue.Blink)) {

        ExReleasePushLockExclusive(&g_driverContext.AlertQueueLock);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "GetAlert: Estrutura da fila corrompida\n");
        return STATUS_INTERNAL_ERROR;
    }

    if (IsListEmpty(&g_driverContext.AlertQueue)) {
        ExReleasePushLockExclusive(&g_driverContext.AlertQueueLock);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "GetAlert: Fila de alertas vazia\n");
        RtlZeroMemory(outputBuffer, sizeof(ALERT_DATA));
        *bytesReturned = 0;
        return STATUS_NO_MORE_ENTRIES;
    }

    PLIST_ENTRY listEntry = g_driverContext.AlertQueue.Flink;

    if (!MmIsAddressValid(listEntry) ||
        listEntry == &g_driverContext.AlertQueue) {
        ExReleasePushLockExclusive(&g_driverContext.AlertQueueLock);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "GetAlert: Entry da lista inválido\n");
        return STATUS_INTERNAL_ERROR;
    }

    alertEntry = CONTAINING_RECORD(listEntry, ALERT_DATA_ENTRY, ListEntry);

    if (!MmIsAddressValid(alertEntry) ||
        !MmIsAddressValid(&alertEntry->ListEntry) ||
        !MmIsAddressValid(&alertEntry->Alert) ||
        alertEntry->ListEntry.Flink == NULL ||
        alertEntry->ListEntry.Blink == NULL) {

        ExReleasePushLockExclusive(&g_driverContext.AlertQueueLock);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "GetAlert: Estrutura do alerta corrompida\n");

        if (MmIsAddressValid(alertEntry)) {
            RemoveEntryList(listEntry);
            ExFreePoolWithTag(alertEntry, TAG_ALERT);
        }

        return STATUS_INTERNAL_ERROR;
    }

    RemoveEntryList(listEntry);

    ALERT_DATA localAlert;
    RtlZeroMemory(&localAlert, sizeof(ALERT_DATA));

    __try {
        RtlCopyMemory(&localAlert, &alertEntry->Alert, sizeof(ALERT_DATA));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ExReleasePushLockExclusive(&g_driverContext.AlertQueueLock);
        if (alertEntry) {
            ExFreePoolWithTag(alertEntry, TAG_ALERT);
        }
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "GetAlert: Dados do alerta corrompidos\n");
        return STATUS_INTERNAL_ERROR;
    }

    if (alertEntry) {
        ExFreePoolWithTag(alertEntry, TAG_ALERT);
    }

    ExReleasePushLockExclusive(&g_driverContext.AlertQueueLock);

    __try {
        RtlCopyMemory(outputBuffer, &localAlert, sizeof(ALERT_DATA));
        *bytesReturned = sizeof(ALERT_DATA);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "GetAlert: Alerta entregue com sucesso\n");
        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "GetAlert: Falha ao copiar para user-mode: 0x%X\n", status);
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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "AlertToUserMode: Invalid parameters\n");
        return STATUS_INVALID_PARAMETER;
    }

    PTR_ALERT_DATA_ENTRY alertEntry = (PTR_ALERT_DATA_ENTRY)ExAllocatePool2(
        POOL_FLAG_PAGED, sizeof(ALERT_DATA_ENTRY), TAG_ALERT);

    if (!alertEntry) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Failed to allocate memory for alert.\n");
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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "AlertToUserMode: Exception filling alert data\n");
        return GetExceptionCode();
    }

    NTSTATUS status = BroadcastAlertToClients(&alertEntry->Alert);

    if (NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "AlertToUserMode: Alert sent via PUSH to clients\n");
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
        return ;
    }

    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Cleaning communication port...\n");

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
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "CleanCommunicationPort: Exception cleaning client list: 0x%X\n", GetExceptionCode());
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
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "CleanCommunicationPort: Exception cleaning alert queue: 0x%X\n", GetExceptionCode());
        }
    }

    if (g_ServerPort) {
        __try {
            FltCloseCommunicationPort(g_ServerPort);
            g_ServerPort = NULL;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "CleanCommunicationPort: Exception closing communication port: 0x%X\n", GetExceptionCode());
            g_ServerPort = NULL;
        }
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Communication port closed.\n");
}

// NOVA FUNÇÃO: Alert queue segura para IRQL alto
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
                // Verificar se a lista é válida
                if (!IsListValid(&g_driverContext.AlertQueue)) {
                    InitializeListHead(&g_driverContext.AlertQueue);
                }

                // Inserir na fila
                InsertTailList(&g_driverContext.AlertQueue, &alertEntry->ListEntry);
                ExReleasePushLockExclusive(&g_driverContext.AlertQueueLock);

                status = STATUS_SUCCESS;
            }
            else {
                // Não conseguiu adquirir o lock? liberar memória
                ExFreePoolWithTag(alertEntry, TAG_ALERT);
                status = lockStatus;
            }
        }
        else {
            // Lock não inicializado - liberar memória
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