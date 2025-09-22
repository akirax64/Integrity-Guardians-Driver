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

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: DriverEntry called.\n");

    DriverObject->DriverUnload = DriverUnload;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: DriverObject->DriverUnload set.\n");

    RtlZeroMemory(&g_driverContext, sizeof(DRIVER_CONTEXT));
    ExInitializePushLock(&g_driverContext.AlertQueueLock);
    InitializeListHead(&g_driverContext.AlertQueue);
    ExInitializePushLock(&g_driverContext.RulesListLock);
    InitializeListHead(&g_driverContext.RulesList);
    ExInitializePushLock(&g_driverContext.MonitoredPathsLock);
    InitializeListHead(&g_driverContext.MonitoredPathsList);
    ExInitializePushLock(&g_driverContext.ExcludedPathsLock);
    InitializeListHead(&g_driverContext.ExcludedPathsList);
    g_driverContext.MonitoringEnabled = TRUE;
    g_driverContext.DetectionMode = DetectionModeActive;
    g_driverContext.BackupOnDetection = FALSE;
    g_driverContext.ClientPort = NULL;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: Global driver context initialized.\n");

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: Initializing Minifilter components.\n");

    status = InitializeFilter(DriverObject, &FilterRegistration);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: InitializeFilter returned status 0x%X\n", status); // <--- Adicione esta linha
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: InitializeFilter failed with status 0x%X\n", status);
        return status;
    }

    RtlInitUnicodeString(&portName, L"\\IGAntiRansomwarePort");
    status = InitializeCommunicationPort(g_FilterHandle, &portName);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: InitializeCommunicationPort returned status 0x%X\n", status); // <--- Adicione esta linha
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: InitializeCommunicationPort failed with status 0x%X\n", status);
        return status;
    }

    status = InitializeDeviceControl(DriverObject);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: InitializeDeviceControl returned status 0x%X\n", status); // <--- Adicione esta linha
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: InitializeDeviceControl failed with status 0x%X\n", status);
        return status;
    }

    status = InitializeWhitelist();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "Warning: Whitelist initialization failed: 0x%X\n", status);
        // não vai falhar o driver, continua sem whitelist
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "Driver loaded successfully with whitelist support\n");
    return STATUS_SUCCESS;
}

// descarrega o driver e limpa os recursos alocados
VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: DriverUnload called. Initiating cleanup.\n");

    // A ordem da limpeza é importante para evitar problemas de referência.

    // 1. Limpar as partes do Device Control tradicional.
    CleanDeviceControl();

    // 2. Limpar as partes do Minifilter e da porta de comunicação.
    CleanCommunicationPort();

    // CleanFilter (de filter_callbacks.c) cuida de FltUnregisterFilter.
    CleanFilter();

    FreeRulesList(); // Libera a memória alocada para as regras.
   
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: DriverUnload finished.\n");
}