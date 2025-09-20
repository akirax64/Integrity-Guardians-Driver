#include "globals.h"
#include "cport.h"
#include "enum.h"

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

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: Initializing communication port...\n");

	// criando o descritor de segurança para a porta de comunicação
    status = FltBuildDefaultSecurityDescriptor(&secDescriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: Failed to build the security descriptor. (0x%X)\n", status);
        return status;
    }

    // inicializando atributos do objeto para a porta de comunicação
    InitializeObjectAttributes(
        &objAttributes,
        portName, // g_DosDeviceName
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, // flags para controle de acesso e case insensitivity
        NULL,     
        secDescriptor    
    );

    // criando a porta de comunicação
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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: Failed to create the security descriptor. (0x%X)\n", status);
        g_ServerPort = NULL; 
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: Communication port initialized with success!\n");
    return STATUS_SUCCESS;
}

// limpando a porta de comunicacao do driver
VOID
CleanCommunicationPort(VOID)
{
    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: Cleaning communication port...\n");

	// fechando a porta de comunicação do driver se ela estiver aberta
    if (g_ServerPort) {
        FltCloseCommunicationPort(g_ServerPort);
        g_ServerPort = NULL;
    }

	// limpeza da fila de alertas
    ExAcquirePushLockExclusive(&g_driverContext.AlertQueueLock);
    while (!IsListEmpty(&g_driverContext.AlertQueue)) {
        PLIST_ENTRY listEntry = RemoveHeadList(&g_driverContext.AlertQueue);
        PTR_ALERT_DATA_ENTRY alertEntry = CONTAINING_RECORD(listEntry, ALERT_DATA_ENTRY, ListEntry);
        ExFreePoolWithTag(alertEntry, TAG_ALERT); // Libera a memória do alerta
    }
    ExReleasePushLockExclusive(&g_driverContext.AlertQueueLock);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: Communication port closed.\n");
}

// notificaçao de conexao do modo de usuario
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

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: User mode connected! ClientPort: %p\n", clientPort);
	g_driverContext.ClientPort = clientPort; // handle para a porta do cliente
    *connectionPortCookie = NULL; 
    return STATUS_SUCCESS;
}

// notificaçao de desconexao do modo de usuario
VOID
DisconnectionNotify(
    _In_ PVOID connectionCookie
)
{
    UNREFERENCED_PARAMETER(connectionCookie);

    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: User mode disconnected.\n");
    g_driverContext.ClientPort = NULL; 
}

// notificaçao de mensagem do modo de usuario
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

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: Message received from user mode! Length: %lu\n", inputBufferLength);

	// logica para enviar alertas ao modo de usuário
	// OBSERVACAO: a logica esta com uma implementaçao pull (user mode solicita alertas)
	// se for possivel, implementarei um modelo push (driver envia alertas automaticamente)
    // para prevenir problemas de desempenho
    NTSTATUS status = STATUS_SUCCESS;
    *returnOutputBufferLength = 0; // Inicializa o tamanho de retorno

    if (outputBuffer && outputBufferLength >= sizeof(ALERT_DATA)) {
        ExAcquirePushLockExclusive(&g_driverContext.AlertQueueLock);

        if (!IsListEmpty(&g_driverContext.AlertQueue)) {
            
            PLIST_ENTRY listEntry = RemoveHeadList(&g_driverContext.AlertQueue);
            PTR_ALERT_DATA_ENTRY alertEntry = CONTAINING_RECORD(listEntry, ALERT_DATA_ENTRY, ListEntry);

            // Copia os dados do alerta para o buffer de saída fornecido pelo user-mode
            if (outputBufferLength >= sizeof(ALERT_DATA)) {
                RtlCopyMemory(outputBuffer, &alertEntry->Alert, sizeof(ALERT_DATA));
                *returnOutputBufferLength = sizeof(ALERT_DATA);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: Send alert to user mode. File: %wS\n", alertEntry->Alert.FilePath);
            }
            else {
                status = STATUS_BUFFER_TOO_SMALL;
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: Output buffer too small for alert.\n");
            }

            ExFreePoolWithTag(alertEntry, TAG_ALERT); 
        }
        else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: Alert queue empty.\n");
            status = STATUS_NO_MORE_ENTRIES; 
        }

        ExReleasePushLockExclusive(&g_driverContext.AlertQueueLock);
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: Output buffer invalid for MessageNotifyCallback.\n");
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

	// verificaçao do irql
    if (KeGetCurrentIrql() > APC_LEVEL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "GetAlert: IRQL muito alto (%d) - requer PASSIVE_LEVEL\n",
            KeGetCurrentIrql());
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (!outputBuffer || outputBufferLength < sizeof(ALERT_DATA)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "GetAlert: Buffer de saída inválido (ptr: %p, size: %lu)\n",
            outputBuffer, outputBufferLength);
        return STATUS_INVALID_PARAMETER;
    }

	// verifica se o buffer é escrevível no contexto do usuário
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
// funcao para enviar alertas ao modo de usuario
NTSTATUS
AlertToUserMode(
    _In_ PUNICODE_STRING fileName,
    _In_ HANDLE processId,
    _In_ HANDLE threadId,
    _In_ ULONG detectionType,
    _In_ PUNICODE_STRING ruleName
)
{
	// alocacao de memoria para o alerta
    PTR_ALERT_DATA_ENTRY alertEntry = (PTR_ALERT_DATA_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(ALERT_DATA_ENTRY), TAG_ALERT);

    if (!alertEntry) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: Failed to allocate memory for alert.\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(alertEntry, sizeof(ALERT_DATA_ENTRY)); 

	// dados do alerta
    alertEntry->Alert.Timestamp.QuadPart = KeQueryPerformanceCounter(NULL).QuadPart; 
    alertEntry->Alert.ProcessId = HandleToUlong(processId);
    alertEntry->Alert.ThreadId = HandleToUlong(threadId);
    alertEntry->Alert.DetectionType = detectionType;
        
    RtlStringCchCopyW(alertEntry->Alert.FilePath, ARRAYSIZE(alertEntry->Alert.FilePath), fileName->Buffer);

    RtlStringCchPrintfW(alertEntry->Alert.AlertMessage, ARRAYSIZE(alertEntry->Alert.AlertMessage),
        L"Rule '%wZ' detected. File: %wS", ruleName, alertEntry->Alert.FilePath);


	// lista de alertas com push lock
    ExAcquirePushLockExclusive(&g_driverContext.AlertQueueLock);
    InsertTailList(&g_driverContext.AlertQueue, &alertEntry->ListEntry);
    ExReleasePushLockExclusive(&g_driverContext.AlertQueueLock);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: Alert queued for %wS.\n", fileName->Buffer);

    // se for possivel, irei criar uma logica com envio assincrono ou talvez uma thread de worker
	// para envio imediato ao modo de usuario
    return STATUS_SUCCESS;
}