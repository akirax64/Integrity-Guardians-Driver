#include "globals.h"

// estado de inicialização do driver
volatile LONG g_InitializationState = 0; 

// variáveis globais
PFLT_FILTER g_FilterHandle = NULL;
PDEVICE_OBJECT g_DeviceObject = NULL;
PFLT_PORT g_ServerPort = NULL;
DRIVER_CONTEXT g_driverContext = { 0 };

// inicializando locks principais e listas
NTSTATUS
InitializeDriverStructures(VOID)
{
	// verificação de segurança
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    PAGED_CODE();

    LONG currentState = InterlockedCompareExchange(&g_InitializationState, 1, 0);

	// ja inicializado
    if (currentState == 2) {
        return STATUS_SUCCESS;
    }
	// está incializando
    if (currentState == 1) {
        LARGE_INTEGER smallDelay = { .QuadPart = -10000LL }; // 1ms
        KeDelayExecutionThread(KernelMode, FALSE, &smallDelay);

        // Verificar novamente
        if (g_InitializationState == 2) {
            return STATUS_SUCCESS;
        }
        return STATUS_UNSUCCESSFUL;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Initializing driver structures...\n");

    __try {
        ExInitializePushLock(&g_driverContext.AlertQueueLock);
        InitializeListHead(&g_driverContext.AlertQueue);

        ExInitializePushLock(&g_driverContext.RulesListLock);
        InitializeListHead(&g_driverContext.RulesList);

        // Configurações básicas
        g_driverContext.MonitoringEnabled = TRUE;
        g_driverContext.DetectionMode = DetectionModeActive;
        g_driverContext.BackupOnDetection = FALSE;
        g_driverContext.ClientPort = NULL;

        // Marcar como parcialmente inicializado
        InterlockedExchange(&g_InitializationState, 2);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Core structures initialized successfully\n");
        return STATUS_SUCCESS;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to initialize core structures: 0x%X\n", GetExceptionCode());
        InterlockedExchange(&g_InitializationState, 0);
        return GetExceptionCode();
    }
}

// locks secundarios
NTSTATUS
InitializeLockIfNeeded(_Inout_ PEX_PUSH_LOCK Lock, _In_ PCSTR LockName)
{
    __try {
        if (Lock && *Lock == 0) {
            ExInitializePushLock(Lock);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "Lock %s initialized\n", LockName);
        }
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to initialize lock %s: 0x%X\n", LockName, GetExceptionCode());
        return GetExceptionCode();
    }
}

NTSTATUS
InitializeSecondaryStructures(VOID)
{ 
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    PAGED_CODE();

    if (g_InitializationState != 2) {
        return STATUS_DEVICE_NOT_READY;
    }

    __try {
        NTSTATUS status;

        status = InitializeLockIfNeeded(&g_driverContext.MonitoredPathsLock, "MonitoredPathsLock");
        if (NT_SUCCESS(status)) {
            InitializeListHead(&g_driverContext.MonitoredPathsList);
        }

        status = InitializeLockIfNeeded(&g_driverContext.ExcludedPathsLock, "ExcludedPathsLock");
        if (NT_SUCCESS(status)) {
            InitializeListHead(&g_driverContext.ExcludedPathsList);
        }

        status = InitializeLockIfNeeded(&g_driverContext.ClientListLock, "ClientListLock");
        if (NT_SUCCESS(status)) {
            InitializeListHead(&g_driverContext.ClientList);
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Secondary structures initialized\n");
        return STATUS_SUCCESS;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Failed to initialize some secondary structures: 0x%X\n", GetExceptionCode());
        return STATUS_SUCCESS;
    }
}

BOOLEAN
AreCoreStructuresInitialized(VOID)
{
    return (g_InitializationState == 2);
}

BOOLEAN
AreAllStructuresInitialized(VOID)
{
    return (g_InitializationState == 2);
}

