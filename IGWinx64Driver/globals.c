#include "globals.h"

volatile LONG g_InitializationState = 0;

PFLT_FILTER g_FilterHandle = NULL;
PDEVICE_OBJECT g_DeviceObject = NULL;
PFLT_PORT g_ServerPort = NULL;
DRIVER_CONTEXT g_driverContext = { 0 };

EX_PUSH_LOCK g_BehaviorTrackerLock = { 0 };
LIST_ENTRY g_BehaviorTrackerList = { 0 };

ULONG g_SuspiciousProcessNamesCount = 0;

BEHAVIOR_CONFIG g_BehaviorConfig = {
    .MaxFilesPerMinute = 30,
    .MaxBytesPerMinute = 50 * 1024 * 1024,
    .EntropyThreshold = 75,
    .RiskScoreThreshold = 80,
    .MaxAlertsPerProcess = 3,
    .FileExtensionChangesThreshold = 10
};

NTSTATUS
InitializeDriverStructures(VOID)
{
    LONG previousState = InterlockedCompareExchange(&g_InitializationState, 1, 0);

    if (previousState != 0) {
        ULONG waitCount = 0;
        const ULONG maxWait = 100; // 100ms máximo

        while (waitCount < maxWait) {
            LONG currentState = InterlockedCompareExchange(&g_InitializationState, 2, 2);

            if (currentState == 2) {
                return STATUS_SUCCESS;
            }
            else if (currentState == 0) {
                return STATUS_UNSUCCESSFUL;
            }

            // Ainda inicializando, esperar um pouco
            LARGE_INTEGER timeout;
            timeout.QuadPart = -10000LL; // 1ms
            KeDelayExecutionThread(KernelMode, FALSE, &timeout);
            waitCount++;
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "InitializeDriverStructures: Timeout waiting for initialization\n");
        return STATUS_TIMEOUT;
    }

    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "Initializing driver structures...\n");

    __try {
        ExInitializePushLock(&g_driverContext.AlertQueueLock);
        InitializeListHead(&g_driverContext.AlertQueue);

        ExInitializePushLock(&g_driverContext.RulesListLock);
        InitializeListHead(&g_driverContext.RulesList);

        g_driverContext.MonitoringEnabled = TRUE;
        g_driverContext.DetectionMode = DetectionModeActive;
        g_driverContext.BackupOnDetection = FALSE;
        g_driverContext.ClientPort = NULL;

		// barreira de memória para garantir visibilidade
        MemoryBarrier();

        // Marcar como completamente inicializado
        InterlockedExchange(&g_InitializationState, 2);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "Core structures initialized successfully\n");
        return STATUS_SUCCESS;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "Failed to initialize core structures: 0x%X\n", GetExceptionCode());

        // Reset estado em caso de erro
        InterlockedExchange(&g_InitializationState, 0);
        return GetExceptionCode();
    }
}

NTSTATUS
InitializeLockIfNeeded(_Inout_ PEX_PUSH_LOCK Lock, _In_ PCSTR LockName)
{
    __try {
        if (Lock && *Lock == 0) {
            ExInitializePushLock(Lock);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                "Lock %s initialized\n", LockName);
        }
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "Failed to initialize lock %s: 0x%X\n", LockName, GetExceptionCode());
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

    LONG currentState = InterlockedCompareExchange(&g_InitializationState, 2, 2);
    if (currentState != 2) {
        return STATUS_DEVICE_NOT_READY;
    }

    __try {
        NTSTATUS status;

        status = InitializeLockIfNeeded(&g_driverContext.MonitoredPathsLock,
            "MonitoredPathsLock");
        if (NT_SUCCESS(status)) {
            InitializeListHead(&g_driverContext.MonitoredPathsList);
        }

        status = InitializeLockIfNeeded(&g_driverContext.ExcludedPathsLock,
            "ExcludedPathsLock");
        if (NT_SUCCESS(status)) {
            InitializeListHead(&g_driverContext.ExcludedPathsList);
        }

        status = InitializeLockIfNeeded(&g_driverContext.ClientListLock,
            "ClientListLock");
        if (NT_SUCCESS(status)) {
            InitializeListHead(&g_driverContext.ClientList);
        }

        status = InitializeLockIfNeeded(&g_BehaviorTrackerLock,
            "BehaviorTrackerLock");
        if (NT_SUCCESS(status)) {
            InitializeListHead(&g_BehaviorTrackerList);

            g_SuspiciousProcessNamesCount = CalculateSuspiciousProcessNamesCount();

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "Behavior detection initialized:\n");
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "  - Suspicious processes: %lu names\n", g_SuspiciousProcessNamesCount);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "  - Max files/min: %lu\n", g_BehaviorConfig.MaxFilesPerMinute);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "  - Max bytes/min: %lu MB\n",
                g_BehaviorConfig.MaxBytesPerMinute / (1024 * 1024));
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "  - Entropy threshold: %lu%%\n", g_BehaviorConfig.EntropyThreshold);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "  - Risk threshold: %lu\n", g_BehaviorConfig.RiskScoreThreshold);
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "Secondary structures initialized\n");
        return STATUS_SUCCESS;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "Failed to initialize some secondary structures: 0x%X\n",
            GetExceptionCode());
        return STATUS_SUCCESS;
    }
}

BOOLEAN
AreCoreStructuresInitialized(VOID)
{
    LONG currentState = InterlockedCompareExchange(&g_InitializationState, 2, 2);
    return (currentState == 2);
}

BOOLEAN
AreAllStructuresInitialized(VOID)
{
    LONG currentState = InterlockedCompareExchange(&g_InitializationState, 2, 2);
    return (currentState == 2);
}

CONST WCHAR* g_SuspiciousProcessNames[] = {
    // WannaCry Family
    L"taskhlp.exe",
    L"@WanaDecryptor@.exe",
    L"wncry.exe",
    L"wnry.exe",
    L"wcry.exe",
    L"taskche.exe",
    L"msgmin.exe",

    // LockBit Family
    L"lockbit.exe",
    L"lockbit2.0.exe",
    L"lockbit3.0.exe",
    L"lb.exe",
    L"locker.exe",
    L"abraham.exe",

    // Conti Family
    L"conti.exe",
    L"conty.exe",
    L"conticrypt.exe",

    // Ryuk Family  
    L"ryuk.exe",
    L"ryk.exe",

    // Phobos Family
    L"phobos.exe",
    L"pho.exe",
    L"devos.exe",
    L"elbie.exe",

    // Akira Family
    L"akira.exe",
    L"akr.exe",

    // BlackCat/ALPHV
    L"blackcat.exe",
    L"alphv.exe",

    // Royal Family
    L"royal.exe",
    L"royal4.exe",

    // Clop Family
    L"clop.exe",
    L"cl0p.exe",

    // Hive Family
    L"hive.exe",

    // BianLian Family  
    L"bianlian.exe",

    // Vice Society
    L"v_society.exe",

    // Ransomware históricos
    L"cryptolocker.exe",
    L"cryptowall.exe",
    L"teslacrypt.exe",
    L"cerber.exe",
    L"petya.exe",
    L"notpetya.exe",
    L"badrabbit.exe",
    L"gandcrab.exe",
    L"revil.exe",
    L"sodinokibi.exe",
    L"maze.exe",
    L"egregor.exe",
    L"mountlocker.exe",
    L"babuk.exe",

    // Genéricos
    L"encrypter.exe",
    L"decrypter.exe",
    L"ransomware.exe",
    L"cryptor.exe",
    L"filelocker.exe",
    L"decrypt_tool.exe",
    L"recovery_tool.exe",
    L"pay_decrypt.exe",
    L"unlock_file.exe",
    L"restore_files.exe",

    // Imitações (typosquatting)
    L"svch0st.exe",
    L"csrsss.exe",
    L"lsasss.exe",
    L"smsss.exe",
    L"spoolsvv.exe",
    L"expl0rer.exe",
    L"winl0gon.exe",

    // Crypters/empacotadores
    L"vmprotect.exe",
    L"themida.exe",
    L"enigma.exe",
    L"obsidium.exe",
    L"armadillo.exe",

    NULL 
};

ULONG
CalculateSuspiciousProcessNamesCount(VOID)
{
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return 0;
    }

    PAGED_CODE();

    ULONG count = 0;

    __try {
        // Contar até encontrar o terminador NULL
        while (g_SuspiciousProcessNames[count] != NULL) {
            count++;

            // Limite de segurança
            if (count > 10000) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "Safety limit reached in process names count\n");
                break;
            }
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "Dynamically counted %lu suspicious process names\n", count);

        return count;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "Exception in CalculateSuspiciousProcessNamesCount: 0x%X\n",
            GetExceptionCode());
        return 0;
    }
}