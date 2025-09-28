#include "precompiled.h"

CONST GUID MiniFilterGuid = {
    0x5b3d6048, 0xf852, 0x4fe2, { 0x9a, 0xb6, 0x5a, 0xdd, 0xa8, 0x5d, 0xaf, 0x55 }
};

// estrutura que registra o minifiltro e seus callbacks
const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,

    NULL,                              // ContextRegistration
	Callbacks,                              // lista que carrega os callbacks
	FilterUnload,                           // funcao que sera chamada quando o filtro for descarregado

	InstanceConfig,                         // funcao para configurar instancias
	InstanceQueryTeardown,                  // funcao para consultar se a instancia pode ser desmontada
	InstanceTeardownStart,                  // funcao para iniciar o desmontagem da instancia
	InstanceTeardownComplete,               // funcao para completar o desmontagem da instancia

    NULL,
    NULL,
    NULL // NormalizeNameComponentCallback
};

// ponto de entrada do driver
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    UNICODE_STRING portName;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "DriverEntry called - Initializing all components\n");

	// inicializar estruturas principais
    status = InitializeDriverStructures();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to initialize structures: 0x%X\n", status);
        return status;
    }

    DriverObject->DriverUnload = DriverUnload;

    status = InitializeFilter(DriverObject, &FilterRegistration);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVBUS_ID, DPFLTR_ERROR_LEVEL, "InitializeFilter failed: 0x%X\n", status);
        return status;
    }

	// inicializar estruturas secundárias
    status = InitializeSecondaryStructures();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Some secondary structures failed: 0x%X\n", status);
    }

    RtlInitUnicodeString(&portName, L"\\IGAntiRansomwarePort");
    status = InitializeCommunicationPort(g_FilterHandle, &portName);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "InitializeCommunicationPort failed: 0x%X\n", status);
        CleanFilter();
        return status;
    }

    status = InitializeDeviceControl(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "InitializeDeviceControl failed: 0x%X\n", status);
        CleanCommunicationPort();
        CleanFilter();
        return status;
    }

    status = InitializeWhitelist();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Whitelist init warning: 0x%X\n", status);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Driver loaded successfully\n");
    return STATUS_SUCCESS;
}


// descarrega o driver e limpa os recursos alocados
VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "DriverUnload - Cleaning all resources\n");

    // ordem inversa da inicialização
    CleanDeviceControl();
    CleanCommunicationPort();
    CleanFilter();
    FreeRulesList();
    ClearExcludedPaths();

    // marcar estruturas como não inicializadas
    InterlockedExchange(&g_InitializationState, 0);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID,DPFLTR_INFO_LEVEL, "DriverUnload completed\n");
}