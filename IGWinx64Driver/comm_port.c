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

    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Initializing communication port...\n");

    ExInitializePushLock(&g_driverContext.ClientListLock);
    InitializeListHead(&g_driverContext.ClientList);

    PAGED_CODE(); // Garantir PASSIVE_LEVEL

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Initializing communication port...\n");

    // Inicializar lista de clientes com verificacao
    if ((PVOID)g_driverContext.ClientListLock == NULL) {
        ExInitializePushLock(&g_driverContext.ClientListLock);
    }
    InitializeListHead(&g_driverContext.ClientList);

    // criando o descritor de seguranca para a porta de comunicacao
    status = FltBuildDefaultSecurityDescriptor(&secDescriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Failed to build the security descriptor. (0x%X)\n", status);
        return status;
    }

    // inicializando atributos do objeto para a porta de comunicacao
    InitializeObjectAttributes(
        &objAttributes,
        portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        secDescriptor
    );

    // criando a porta de comunicacao
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

    // se falhar ao criar a porta, loga o erro e retorna o status
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

    PAGED_CODE();

    // verifica se os parametros sao validos
    if (clientPort == NULL || connectionPortCookie == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ConnectionNotify: Parametros invalidos\n");
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: User mode connected! ClientPort: %p\n", clientPort);

    // alocando contexto do cliente com verificacao
    PTR_CLIENT_CONTEXT clientContext = (PTR_CLIENT_CONTEXT)ExAllocatePool2(
        POOL_FLAG_PAGED, sizeof(CLIENT_CONTEXT), TAG_CLIENT);

    if (!clientContext) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ConnectionNotify: Failed to allocate client context\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(clientContext, sizeof(CLIENT_CONTEXT));
    clientContext->ClientPort = clientPort;
    clientContext->IsActive = TRUE;
    InitializeListHead(&clientContext->ListEntry);

    ExAcquirePushLockExclusive(&g_driverContext.ClientListLock);

    // verifica se a lista foi inicializada
    if (g_driverContext.ClientList.Flink == NULL) {
        InitializeListHead(&g_driverContext.ClientList);
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

    PAGED_CODE();

    if (clientContext == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "DisconnectionNotify: Null context\n");
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: User mode disconnected. ClientPort: %p\n", clientContext->ClientPort);

    // retirando o cliente da lista com verificacao
    ExAcquirePushLockExclusive(&g_driverContext.ClientListLock);

    // verificacao rigorosa da integridade da lista antes de remover
    if (clientContext->ListEntry.Flink != NULL &&
        clientContext->ListEntry.Blink != NULL &&
        !IsListEmpty(&g_driverContext.ClientList) &&
        clientContext->ListEntry.Flink != &clientContext->ListEntry &&
        clientContext->ListEntry.Blink != &clientContext->ListEntry) {

        PLIST_ENTRY currentEntry;
        BOOLEAN found = FALSE;
        for (currentEntry = g_driverContext.ClientList.Flink;
            currentEntry != &g_driverContext.ClientList;
            currentEntry = currentEntry->Flink) {
            if (currentEntry == &clientContext->ListEntry) {
                found = TRUE;
                break;
            }
        }

        if (found) {
            RemoveEntryList(&clientContext->ListEntry);
        }
        else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "DisconnectionNotify: Entry not found in list\n");
        }
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "DisconnectionNotify: Invalid list entry\n");
    }

    ExReleasePushLockExclusive(&g_driverContext.ClientListLock);

    if (clientContext != NULL) {
        clientContext->ClientPort = NULL;
        clientContext->IsActive = FALSE;

        ExFreePoolWithTag(clientContext, TAG_CLIENT);
        clientContext = NULL;
    }
}

// broadcast de alertas para todos os clientes conectados
NTSTATUS
BroadcastAlertToClients(
    _In_ PTR_ALERT_DATA AlertData
) {
    PAGED_CODE();


    if (AlertData == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BroadcastAlertToClients: AlertData is NULL\n");
        return STATUS_INVALID_PARAMETER;
    }

    // verificar IRQL
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "BroadcastAlertToClients: IRQL too high (%d)\n", KeGetCurrentIrql());
        return STATUS_INVALID_DEVICE_STATE;
    }

    PLIST_ENTRY entry, nextEntry;
    PTR_CLIENT_CONTEXT clientContext;
    ULONG clientsNotified = 0;
    ULONG clientsTotal = 0;

    // alocar buffer para a mensagem
    PVOID messageBuffer = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(ALERT_DATA), TAG_MESSAGE);
    if (!messageBuffer) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BroadcastAlertToClients: Failed to allocate message buffer\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // copiando dados para o buffer com verificação
    __try {
        RtlCopyMemory(messageBuffer, AlertData, sizeof(ALERT_DATA));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ExFreePoolWithTag(messageBuffer, TAG_MESSAGE);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BroadcastAlertToClients: Exception copying alert data\n");
        return GetExceptionCode();
    }

    ExAcquirePushLockShared(&g_driverContext.ClientListLock);

    // verificar se a lista é válida e não vazia
    if (g_driverContext.ClientList.Flink == NULL ||
        g_driverContext.ClientList.Blink == NULL ||
        IsListEmpty(&g_driverContext.ClientList)) {
        ExReleasePushLockShared(&g_driverContext.ClientListLock);
        ExFreePoolWithTag(messageBuffer, TAG_MESSAGE);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BroadcastAlertToClients: No clients connected\n");
        return STATUS_SUCCESS;
    }

    entry = g_driverContext.ClientList.Flink;
    while (entry != NULL && entry != &g_driverContext.ClientList)
    {
        nextEntry = entry->Flink;

        if (entry == NULL || entry->Flink == NULL || entry->Blink == NULL) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BroadcastAlertToClients: Invalid list entry\n");
            break;
        }

        clientContext = CONTAINING_RECORD(entry, CLIENT_CONTEXT, ListEntry);
        clientsTotal++;

        if (clientContext == NULL ||
            !clientContext->IsActive ||
            clientContext->ClientPort == NULL) {
            entry = nextEntry;
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
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "Alert sent to client %p successfully\n", clientContext->ClientPort);
            }
            else {
                clientContext->IsActive = FALSE;
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "Failed to send alert to client %p: 0x%X\n", clientContext->ClientPort, sendStatus);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "Exception sending to client %p: 0x%X\n",
                clientContext->ClientPort, GetExceptionCode());
            clientContext->IsActive = FALSE;
        }

        entry = nextEntry;
    }

    ExReleasePushLockShared(&g_driverContext.ClientListLock);
    ExFreePoolWithTag(messageBuffer, TAG_MESSAGE);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "BroadcastAlertToClients: Notified %lu of %lu clients\n", clientsNotified, clientsTotal);

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

    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Message received from user mode! Length: %lu\n", inputBufferLength);

    NTSTATUS status = STATUS_SUCCESS;
    *returnOutputBufferLength = 0;

    // Modo PULL: ainda suportar obtencao de alertas via IOCTL
    if (outputBuffer && outputBufferLength >= sizeof(ALERT_DATA))
    {
        ExAcquirePushLockExclusive(&g_driverContext.AlertQueueLock);

        if (!IsListEmpty(&g_driverContext.AlertQueue))
        {
            PLIST_ENTRY listEntry = RemoveHeadList(&g_driverContext.AlertQueue);
            PTR_ALERT_DATA_ENTRY alertEntry = CONTAINING_RECORD(listEntry, ALERT_DATA_ENTRY, ListEntry);

            if (outputBufferLength >= sizeof(ALERT_DATA))
            {
                RtlCopyMemory(outputBuffer, &alertEntry->Alert, sizeof(ALERT_DATA));
                *returnOutputBufferLength = sizeof(ALERT_DATA);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Send alert to user mode. File: %wS\n", alertEntry->Alert.FilePath);
            }
            else
            {
                status = STATUS_BUFFER_TOO_SMALL;
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Output buffer too small for alert.\n");
            }

            ExFreePoolWithTag(alertEntry, TAG_ALERT);
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
    PAGED_CODE();

    NTSTATUS status = STATUS_SUCCESS;
    PTR_ALERT_DATA_ENTRY alertEntry = NULL;
    *bytesReturned = 0;

    if (outputBuffer == NULL || bytesReturned == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "GetAlert: Parâmetros de saída inválidos\n");
        return STATUS_INVALID_PARAMETER;
    }

    // inicializa o buffer de saída com zeros
    RtlZeroMemory(outputBuffer, min(outputBufferLength, sizeof(ALERT_DATA)));

    // verificaçao do irql
    if (KeGetCurrentIrql() > APC_LEVEL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "GetAlert: IRQL muito alto (%d) - requer PASSIVE_LEVEL\n",
            KeGetCurrentIrql());
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (outputBufferLength < sizeof(ALERT_DATA)) {
        //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            //"GetAlert: Buffer de saída muito pequeno (size: %lu, necessário: %lu)\n",
            //outputBufferLength, sizeof(ALERT_DATA));
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

    // verifica se a queue está corrompida
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

        // retorna estrutura vazia mas inicializada
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

        // tenta limpar a entrada corrompida
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
        ExFreePoolWithTag(alertEntry, TAG_ALERT);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "GetAlert: Dados do alerta corrompidos\n");
        return STATUS_INTERNAL_ERROR;
    }

    ExFreePoolWithTag(alertEntry, TAG_ALERT);
    alertEntry = NULL;

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
    PAGED_CODE();

    if (fileName == NULL || ruleName == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "AlertToUserMode: Invalid parameters\n");
        return STATUS_INVALID_PARAMETER;
    }


    PTR_ALERT_DATA_ENTRY alertEntry = (PTR_ALERT_DATA_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(ALERT_DATA_ENTRY), TAG_ALERT);

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
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "AlertToUserMode: PUSH failed (0x%X), using PULL fallback\n", status);

        ExAcquirePushLockExclusive(&g_driverContext.AlertQueueLock);

        if (g_driverContext.AlertQueue.Flink == NULL) {
            InitializeListHead(&g_driverContext.AlertQueue);
        }

        InsertTailList(&g_driverContext.AlertQueue, &alertEntry->ListEntry);
        ExReleasePushLockExclusive(&g_driverContext.AlertQueueLock);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Alert queued for %wS.\n", fileName->Buffer);
        return status;
    }
}

// limpando a porta de comunicacao do driver
VOID
CleanCommunicationPort(VOID)
{
    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Cleaning communication port...\n");

    // Limpeza da lista de clientes
    if (g_driverContext.ClientListLock) {
        __try {
            ExAcquirePushLockExclusive(&g_driverContext.ClientListLock);

            if (g_driverContext.ClientList.Flink && g_driverContext.ClientList.Blink) {
                PLIST_ENTRY entry;

                while ((entry = g_driverContext.ClientList.Flink) &&
                    entry != &g_driverContext.ClientList &&
                    !IsListEmpty(&g_driverContext.ClientList)) {

                    PLIST_ENTRY nextEntry = entry->Flink;

                    if (entry->Flink && entry->Blink) {
                        RemoveEntryList(entry);

                        PTR_CLIENT_CONTEXT clientContext = CONTAINING_RECORD(entry, CLIENT_CONTEXT, ListEntry);

                        if (clientContext) {
                            clientContext->ClientPort = NULL;
                            ExFreePoolWithTag(clientContext, TAG_CLIENT);
                        }
                    }

                    if (nextEntry == g_driverContext.ClientList.Flink) {
                        break;
                    }
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

    // Limpeza da fila de alertas
    if (g_driverContext.AlertQueueLock) {
        __try {
            ExAcquirePushLockExclusive(&g_driverContext.AlertQueueLock);

            if (g_driverContext.AlertQueue.Flink && g_driverContext.AlertQueue.Blink) {
                while (!IsListEmpty(&g_driverContext.AlertQueue)) {
                    PLIST_ENTRY entry = g_driverContext.AlertQueue.Flink;

                    if (entry == &g_driverContext.AlertQueue) {
                        break;
                    }

                    if (entry && entry->Flink && entry->Blink) {
                        RemoveEntryList(entry);

                        PTR_ALERT_DATA_ENTRY alertEntry = CONTAINING_RECORD(entry, ALERT_DATA_ENTRY, ListEntry);

                        if (alertEntry) {
                            ExFreePoolWithTag(alertEntry, TAG_ALERT);
                        }
                    }
                    else {
                        InitializeListHead(&g_driverContext.AlertQueue);
                        break;
                    }
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