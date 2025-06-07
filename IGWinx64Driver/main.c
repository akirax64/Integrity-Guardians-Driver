#include "antirnsm.h"
#include <wdm.h>
#include <fltKernel.h>
#include <ntddk.h>

// variaveis globais do driver
PFLT_FILTER g_FilterHandle = NULL;
PDEVICE_OBJECT g_DeviceObject = NULL;
UNICODE_STRING g_DosDeviceName = RTL_CONSTANT_STRING(DOS_DEVICE_NAME);
PFLT_PORT g_ServerPort = NULL;
DRIVER_CONTEXT g_driverContext;

// Declaração do array de callbacks para o Filter Manager (implementar quando criar callbacks.c)
extern CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	// depois criar a definição dos callbacks de operações do mini-filter driver
    // Exemplo: { IRP_MJ_CREATE, 0, PreCreateCallback, PostCreateCallback },
    //          { IRP_MJ_READ, 0, PreReadCallback, PostReadCallback },
    //          { IRP_MJ_WRITE, 0, PreWriteCallback, PostWriteCallback },
    { IRP_MJ_OPERATION_END } // Termina a lista de callbacks
};

// criação do registro do mini-filter driver
CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0, // flags

    NULL, // ContextRegistration
    Callbacks, // OperationCallbacks

    Unload,

    //criar estes callbacks
    //InstanceSetup, // InstanceSetup
    //InstanceQueryTeardown, // InstanceQueryTeardown
    //, // InstanceTeardownStart
    //InstanceTeardownComplete, // InstanceTeardownComplete

    NULL, // GenerateFileName
    NULL, // GenerateFileNameCallback
    NULL, // NormalizeNameComponent
    NULL, // NormalizeNameComponentEx
    NULL, // SectionNotificationCallback
    NULL // SectionNotificationCallbackEx
};

// Inicialização do driver
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT d_Object,
    _In_ PUNICODE_STRING r_Path
)
{
    UNREFERENCED_PARAMETER(d_Object);
    UNREFERENCED_PARAMETER(r_Path);
    NTSTATUS status;
    OBJECT_ATTRIBUTES obj_a;
    PSECURITY_DESCRIPTOR sec_d;

    PAGED_CODE();

    DbgPrint("Integrity Guardians AntiRansomware: DriverEntry\n");

    // Inicializar o contexto global do driver
    RtlZeroMemory(&g_driverContext, sizeof(DRIVER_CONTEXT));
    InitializeListHead(&g_driverContext.AlertQueue);
    ExInitializePushLock(&g_driverContext.AlertQueueLock);
    InitializeListHead(&g_driverContext.RulesList);
    ExInitializePushLock(&g_driverContext.RulesListLock);
    InitializeListHead(&g_driverContext.MonitoredPathsList);
    InitializeListHead(&g_driverContext.ExcludedPathsList);
    ExInitializePushLock(&g_driverContext.ExcludedPathsLock);
    g_driverContext.MonitoringEnabled = FALSE; // Desabilita por padrão
    g_driverContext.DetectionMode = 0;         // Modo passivo por padrão
    g_driverContext.BackupOnDetection = FALSE; // Backup desativado por padrão

    // criando o objeto de dispositivo
    status = IoCreateDevice(
        d_Object,
        0,
        &g_DosDeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject
    );
    // se nao conseguir criar o objeto de dispositivo, retorna erro
    if (!NT_SUCCESS(status)) {
        DbgPrint("Integrity Guardians AntiRansomware: Failed to create device object (0x%X)\n", status);
        return status;
    }

    // Configurações para o dispositivo: o DeviceIoControl será o ArDeviceControl
    d_Object->MajorFunction[IRP_MJ_CREATE] = d_Object->MajorFunction[IRP_MJ_CLOSE] =
        d_Object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;

    // criando o link simbólico
    status = IoCreateSymbolicLink(&g_DosDeviceName, &g_DeviceObject->DriverObject->DriverName);
    // se nao conseguir criar o link simbólico, retorna erro
    if (!NT_SUCCESS(status)) {
        DbgPrint("Integrity Guardians AntiRansomware: Failed to create symbolic link (0x%X)\n", status);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // registrando o mini-filter driver
    status = FltRegisterFilter(d_Object, &FilterRegistration, &g_FilterHandle);
    // se nao conseguir registrar o mini-filter, retorna erro
    if (!NT_SUCCESS(status)) {
        DbgPrint("Integrity Guardians Antiransomware: Failed to register filter (0x%X)\n", status);
        IoDeleteSymbolicLink(&g_DosDeviceName);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // criando a porta de comunicação para o user mode
    status = FltBuildDefaultSecurityDescriptor(&sec_d, FLT_PORT_ALL_ACCESS);
    // se nao conseguir construir o security descriptor, retorna erro
    if (!NT_SUCCESS(status)) {
        DbgPrint("Integrity Guardians Antiransomware: Failed to build security descriptor (0x%X)\n", status);
        FltUnregisterFilter(g_FilterHandle);
        IoDeleteSymbolicLink(&g_DosDeviceName);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    InitializeObjectAttributes(
        &obj_a,
        &g_DosDeviceName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        sec_d
    );

    status = FltCreateCommunicationPort(
        g_FilterHandle,
        &g_ServerPort,
        &obj_a,
        NULL, // ServerPortCookie
        ConnectionNotifyCallback,
        DisconnectionNotifyCallback,
        MessageNotifyCallback,
        1   // nº máximo de conexões simultâneas
    );
    FltFreeSecurityDescriptor(sec_d);
    // se falhar em criar o descritor de segurança ou a porta de comunicação, retorna erro
    if (!NT_SUCCESS(status)) {
        DbgPrint("Integrity Guardians AntiRansomware: Failed to create communication port (0x%X)\n", status);
        FltUnregisterFilter(g_FilterHandle);
        IoDeleteSymbolicLink(&g_DosDeviceName);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // monitoramento de eventos de arquivo (registrando o mini-filter driver)
    status = FltStartFiltering(g_FilterHandle);
    // se falhar em iniciar o filtro, retorna erro
    if (!NT_SUCCESS(status)) {
        DbgPrint("Integrity Guardians AntiRansomware: Failed to start filtering (0x%X)\n", status);
        FltCloseCommunicationPort(g_ServerPort);
        FltUnregisterFilter(g_FilterHandle);
        IoDeleteSymbolicLink(&g_DosDeviceName);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    DbgPrint("Integrity Guardians AntiRansomware: DriverEntry successful!\n");
    return STATUS_SUCCESS;
}

// funçao de descarregamento do driver
NTSTATUS
Unload(
    _In_ FLT_FILTER_UNLOAD_FLAGS flags
)
{
    UNREFERENCED_PARAMETER(flags);
    PAGED_CODE();

    DbgPrint("Integrity Guardians AntiRansomware: Driver Unload\n");

    // Desregistra o mini-filter driver
    if (g_FilterHandle) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }

    // Fecha a porta de comunicação
    if (g_ServerPort) {
        FltCloseCommunicationPort(g_ServerPort);
        g_ServerPort = NULL;
    }

    // Deleta o link simbólico
    IoDeleteSymbolicLink(&g_DosDeviceName);

    // Deleta o objeto de dispositivo
    IoDeleteDevice(g_DeviceObject);
    g_DeviceObject = NULL;

    DbgPrint("Integrity Guardians AntiRansomware: Driver unloaded successfully!\n");

    // criar mais funções de limpeza, se necessário
    // exemplo: limpar listas, liberar memória alocada, etc.
    return STATUS_SUCCESS;
}

// funções de controle do dispositivo
NTSTATUS
DeviceControl(
    _In_ PDEVICE_OBJECT d_obj,
    _Inout_ PIRP irp
)
{
    UNREFERENCED_PARAMETER(d_obj);
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpStack;
    ULONG ioControlCode;
    PVOID inputBuffer;
    ULONG inputBufferLength;
    PVOID outputBuffer;
    ULONG outputBufferLength;
    ULONG_PTR byte_infos = 0; // Bytes escritos/lidos

    PAGED_CODE();

    irpStack = IoGetCurrentIrpStackLocation(irp);
    ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
    inputBuffer = irp->AssociatedIrp.SystemBuffer;
    inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    outputBuffer = irp->AssociatedIrp.SystemBuffer;
    outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

    DbgPrint("Integrity Guardians AntiRansomware: DeviceControl - IOCTL 0x%X received\n", ioControlCode);

    switch (ioControlCode)
    {
    case IOCTL_LOAD_RULES:
    //    status = LoadRules(*(PTR_RULES_DATA)inputBuffer, inputBufferLength);
        break;

    case IOCTL_GET_ALERT:
    //    status = GetAlert(outputBuffer, outputBufferLength, (PULONG)&byte_infos);
        break;

    case IOCTL_CONFIGURE_MONITORING:
        // implementar configuração de monitoramento
        status = STATUS_NOT_IMPLEMENTED;
        break;

    case IOCTL_STATUS:
        // implementar status do driver
        status = STATUS_NOT_IMPLEMENTED;
        break;

    default:
        DbgPrint("Integrity Guardians AntiRansomwrare: Unknown IOCTL 0x%X\n", ioControlCode);
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = byte_infos;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    DbgPrint("Integrity Guardians AntiRansomware: DeviceControl completed with status 0x%X\n", status);
    return status;
}

// funçoes de callback
NTSTATUS
ConnectionNotifyCallback(
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

    DbgPrint("Integrity Guardians AntiRansomware: User mode connected to port! ClientPort: %p\n", clientPort);
    g_driverContext.ClientPort = clientPort;
    *connectionPortCookie = NULL; // Nenhum cookie de conexão específico por enquanto
    return STATUS_SUCCESS;
}

VOID
DisconnectionNotifyCallback(
    _In_ PVOID connectionCookie
)
{
    UNREFERENCED_PARAMETER(connectionCookie);

    DbgPrint("Integrity Guardians AntiRansomware: User mode disconnected from port.\n");
    g_driverContext.ClientPort = NULL; // limpa o cookie do cliente
}

NTSTATUS
MessageNotifyCallback(
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

    DbgPrint("Integrity Guardians AntiRansomware: Message received from user mode! Length: %lu\n", inputBufferLength);

    // criar lógica para processar a mensagem recebida

    if (outputBuffer && outputBufferLength >= sizeof(ULONG)) {
        *(PULONG)outputBuffer = STATUS_SUCCESS;
        *returnOutputBufferLength = sizeof(ULONG);
    }
    else {
        if (outputBuffer) {
            RtlZeroMemory(outputBuffer, outputBufferLength);
        }
        *returnOutputBufferLength = 0;
    }
    return STATUS_SUCCESS;
}