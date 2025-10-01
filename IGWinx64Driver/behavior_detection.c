#include "precompiled.h"

NTSTATUS
InitializeBehaviorDetection(VOID)
{
    KIRQL currentIrql = KeGetCurrentIrql();

    if (currentIrql > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    static volatile LONG initialized = 0;
    if (InterlockedCompareExchange(&initialized, 1, 0) != 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "InitializeBehaviorDetection: Already initialized\n");
        return STATUS_SUCCESS;
    }

    PAGED_CODE();

    __try {
        // Inicializar lock da lista de trackers
        if (!IsPushLockInitialized(&g_BehaviorTrackerLock)) {
            ExInitializePushLock(&g_BehaviorTrackerLock);
        }

        // Inicializar lista de trackers
        if (!IsListValid(&g_BehaviorTrackerList)) {
            InitializeListHead(&g_BehaviorTrackerList);
        }

        // Calcular contagem dinâmica de processos suspeitos
        g_SuspiciousProcessNamesCount = CalculateSuspiciousProcessNamesCount();

        // Verificações de sanidade
        if (g_SuspiciousProcessNamesCount == 0) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "InitializeBehaviorDetection: No suspicious process names loaded\n");
        }
        else if (g_SuspiciousProcessNamesCount > 500) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "InitializeBehaviorDetection: Large suspicious process list: %lu names\n",
                g_SuspiciousProcessNamesCount);
        }

        // Verificar configuração comportamental
        if (g_BehaviorConfig.MaxFilesPerMinute == 0 ||
            g_BehaviorConfig.MaxBytesPerMinute == 0 ||
            g_BehaviorConfig.EntropyThreshold == 0 ||
            g_BehaviorConfig.RiskScoreThreshold == 0) {

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "InitializeBehaviorDetection: Invalid behavior configuration detected\n");

            // Configuração fallback
            g_BehaviorConfig.MaxFilesPerMinute = 30;
            g_BehaviorConfig.MaxBytesPerMinute = 50 * 1024 * 1024;
            g_BehaviorConfig.EntropyThreshold = 75;
            g_BehaviorConfig.RiskScoreThreshold = 80;
            g_BehaviorConfig.MaxAlertsPerProcess = 3;
            g_BehaviorConfig.FileExtensionChangesThreshold = 10;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "InitializeBehaviorDetection: Using fallback configuration\n");
        }

        // Log de inicialização bem-sucedida
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "Behavior detection initialized successfully:\n");
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "  - Suspicious processes: %lu names\n", g_SuspiciousProcessNamesCount);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "  - Max files/min: %lu\n", g_BehaviorConfig.MaxFilesPerMinute);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "  - Max bytes/min: %lu MB\n", g_BehaviorConfig.MaxBytesPerMinute / (1024 * 1024));
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "  - Entropy threshold: %lu%%\n", g_BehaviorConfig.EntropyThreshold);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "  - Risk threshold: %lu\n", g_BehaviorConfig.RiskScoreThreshold);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "  - Max alerts/process: %lu\n", g_BehaviorConfig.MaxAlertsPerProcess);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "  - File extension changes threshold: %lu\n", g_BehaviorConfig.FileExtensionChangesThreshold);

        return STATUS_SUCCESS;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "InitializeBehaviorDetection: Initialization failed - Exception 0x%X\n",
            GetExceptionCode());

        // Reset flag em caso de erro
        InterlockedExchange(&initialized, 0);
        return GetExceptionCode();
    }
}

BOOLEAN
IsBehaviorDetectionInitialized(VOID)
{
    // Verificar se as estruturas principais estão inicializadas
    if (!IsPushLockInitialized(&g_BehaviorTrackerLock)) {
        return FALSE;
    }

    if (!IsListValid(&g_BehaviorTrackerList)) {
        return FALSE;
    }

    if (g_SuspiciousProcessNamesCount == 0) {
        return FALSE;
    }

    return TRUE;
}

NTSTATUS
GetBehaviorDetectionStats(
    _Out_ PULONG ActiveTrackers,
    _Out_ PULONG TotalNamesLoaded
)
{
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    PAGED_CODE();

    if (!ActiveTrackers || !TotalNamesLoaded) {
        return STATUS_INVALID_PARAMETER;
    }

    *ActiveTrackers = 0;
    *TotalNamesLoaded = g_SuspiciousProcessNamesCount;

    __try {
        if (IsPushLockInitialized(&g_BehaviorTrackerLock)) {
            NTSTATUS lockStatus = AcquirePushLockSharedWithTimeout(&g_BehaviorTrackerLock, 50);
            if (NT_SUCCESS(lockStatus)) {
                // Contar trackers ativos
                PLIST_ENTRY entry;
                for (entry = g_BehaviorTrackerList.Flink;
                    entry != &g_BehaviorTrackerList;
                    entry = entry->Flink) {
                    (*ActiveTrackers)++;
                }
                ExReleasePushLockShared(&g_BehaviorTrackerLock);
            }
        }

        return STATUS_SUCCESS;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "GetBehaviorDetectionStats: Exception 0x%X\n", GetExceptionCode());
        return GetExceptionCode();
    }
}

VOID
CleanupBehaviorDetection(VOID)
{
    if (KeGetCurrentIrql() > APC_LEVEL)
    {
        return;
    }

    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "CleanupBehaviorDetection: Cleaning up behavior detection...\n");

    __try {
        // CORREÇÃO: Usar timeout no lock
        if (IsPushLockInitialized(&g_BehaviorTrackerLock)) {
            NTSTATUS lockStatus = AcquirePushLockExclusiveWithTimeout(&g_BehaviorTrackerLock, 100);
            if (!NT_SUCCESS(lockStatus)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "CleanupBehaviorDetection: Failed to acquire lock: 0x%X\n", lockStatus);
                return;
            }

            while (!IsListEmpty(&g_BehaviorTrackerList)) {
                PLIST_ENTRY entry = RemoveHeadList(&g_BehaviorTrackerList);
                PTR_BEHAVIOR_TRACKER tracker = CONTAINING_RECORD(entry, BEHAVIOR_TRACKER, ListEntry);

                // Liberar nome do processo se foi alocado dinamicamente
                if (tracker->ProcessName.Buffer) {
                    ExFreePoolWithTag(tracker->ProcessName.Buffer, TAG_RULE_NAME);
                    tracker->ProcessName.Buffer = NULL;
                }

                ExFreePoolWithTag(tracker, TAG_DATA_RULE);
            }

            InitializeListHead(&g_BehaviorTrackerList);
            ExReleasePushLockExclusive(&g_BehaviorTrackerLock);
        }

        // Resetar contador
        g_SuspiciousProcessNamesCount = 0;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "CleanupBehaviorDetection: Cleanup completed successfully\n");

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "CleanupBehaviorDetection: Exception during cleanup: 0x%X\n", GetExceptionCode());
    }
}

// CORREÇÃO: Função auxiliar segura para calcular comprimento de string
__forceinline
ULONG
SafeStringLength(
    _In_ const WCHAR* String,
    _In_ ULONG MaxLength
)
{
    if (!String) return 0;

    ULONG length = 0;
    __try {
        while (length < MaxLength && String[length] != L'\0') {
            length++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return length;
}

BOOLEAN
IsKnownRansomwareProcess(
    _In_ PTR_BEHAVIOR_TRACKER Tracker
)
{
    if (!Tracker || !Tracker->ProcessName.Buffer) {
        return FALSE;
    }

    // Verificar se a lista foi inicializada
    if (g_SuspiciousProcessNamesCount == 0) {
        return FALSE;
    }

    BOOLEAN found = FALSE;

    __try {
        // CORREÇÃO: Comparação segura sem wcsicmp
        for (ULONG i = 0; i < g_SuspiciousProcessNamesCount; i++) {
            if (g_SuspiciousProcessNames[i] == NULL) {
                continue;
            }

            // Calcular comprimentos de forma segura
            ULONG susLen = SafeStringLength(g_SuspiciousProcessNames[i], 256);
            ULONG trackerLen = Tracker->ProcessName.Length / sizeof(WCHAR);

            if (susLen == 0 || trackerLen == 0 || susLen != trackerLen) {
                continue;
            }

            // Comparação case-insensitive manual
            BOOLEAN match = TRUE;
            for (ULONG j = 0; j < susLen; j++) {
                WCHAR c1 = Tracker->ProcessName.Buffer[j];
                WCHAR c2 = g_SuspiciousProcessNames[i][j];

                // Converter para maiúsculas
                if (c1 >= L'a' && c1 <= L'z') c1 -= (L'a' - L'A');
                if (c2 >= L'a' && c2 <= L'z') c2 -= (L'a' - L'A');

                if (c1 != c2) {
                    match = FALSE;
                    break;
                }
            }

            if (match) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                    "Known ransomware process detected: %wZ\n", &Tracker->ProcessName);
                found = TRUE;
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "IsKnownRansomwareProcess: Exception 0x%X\n", GetExceptionCode());
        found = FALSE;
    }

    return found;
}

ULONG
CalculateEntropy(
    _In_ ULONG Length,
    _In_reads_bytes_(Length) PVOID Buffer
)
{
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return 0;
    }

    if (!Buffer || !MmIsAddressValid(Buffer)) {
        return 0;
    }

    // CORREÇÃO: Proteção contra page fault
    __try {
        ULONG frequency[256] = { 0 };
        PUCHAR data = (PUCHAR)Buffer;
        ULONG safeLength = min(Length, 4096);

        // Verificação de acesso inicial
        volatile UCHAR testByte = data[0];
        UNREFERENCED_PARAMETER(testByte);

        // Contagem de frequências com proteção
        for (ULONG i = 0; i < safeLength; i++) {
            frequency[data[i]]++;
        }

        // Calcular entropia usando matemática inteira
        ULONGLONG entropyScaled = 0;

        for (ULONG i = 0; i < 256; i++) {
            if (frequency[i] > 0) {
                ULONGLONG log2Length = 0;
                ULONGLONG log2Freq = 0;
                ULONG temp;

                // Aproximação de log2(safeLength)
                temp = safeLength;
                while (temp > 1) {
                    log2Length++;
                    temp >>= 1;
                }

                // Aproximação de log2(frequency[i])
                temp = frequency[i];
                while (temp > 1) {
                    log2Freq++;
                    temp >>= 1;
                }

                if (log2Length > log2Freq) {
                    ULONGLONG probabilityTerm = (frequency[i] * 1000) / safeLength;
                    ULONGLONG logTerm = (log2Length - log2Freq) * 1000;

                    entropyScaled += probabilityTerm * logTerm / 1000;
                }
            }
        }

        // Converter para escala 0-800 (equivalente a 0-8.0 bits)
        ULONG entropy = (ULONG)(entropyScaled / 125);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
            "CalculateEntropy: %lu bits (scaled from %I64u)\n", entropy, entropyScaled);

        return entropy;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "CalculateEntropy: Exception 0x%X\n", GetExceptionCode());
        return 0;
    }
}

BOOLEAN
IsLikelyEncrypted(
    _In_ ULONG Length,
    _In_reads_bytes_(Length) PVOID Buffer
)
{
    if (Length < 64) {
        return FALSE;
    }

    ULONG entropy = CalculateEntropy(Length, Buffer);

    // Entropia máxima é ~800 (equivalente a 8.0 bits)
    // Threshold de 75% = 600
    BOOLEAN isEncrypted = (entropy >= 600);

    if (isEncrypted) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "High entropy detected: %lu/800 (threshold: %lu)\n",
            entropy, g_BehaviorConfig.EntropyThreshold);
    }

    return isEncrypted;
}

// CORREÇÃO: Função auxiliar segura para encontrar último ponto
__forceinline
PWSTR
FindLastDotManual(
    _In_ PWSTR Buffer,
    _In_ USHORT MaxLength
)
{
    if (!Buffer || MaxLength == 0) {
        return NULL;
    }

    PWSTR lastDot = NULL;
    USHORT length = min(MaxLength, 256);

    __try {
        for (USHORT i = 0; i < length; i++) {
            if (Buffer[i] == L'\0') {
                break;
            }
            if (Buffer[i] == L'.') {
                lastDot = &Buffer[i];
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }

    return lastDot;
}

BOOLEAN
IsSuspiciousExtensionChange(
    _In_ PUNICODE_STRING OldFileName,
    _In_ PUNICODE_STRING NewFileName
)
{
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FALSE;
    }

    if (!OldFileName || !NewFileName ||
        !OldFileName->Buffer || !NewFileName->Buffer) {
        return FALSE;
    }

    __try {
        // Encontrar extensões manualmente
        PWSTR oldExt = FindLastDotManual(OldFileName->Buffer,
            OldFileName->Length / sizeof(WCHAR));
        PWSTR newExt = FindLastDotManual(NewFileName->Buffer,
            NewFileName->Length / sizeof(WCHAR));

        if (!oldExt || !newExt) {
            return FALSE;
        }

        // Lista de extensões suspeitas
        static const WCHAR* suspiciousExtensions[] = {
            L".crypt", L".locked", L".encrypted", L".ransom",
            L".crypto", L".xtbl", L".zepto", L".cerber",
            L".akira", L".lockbit", L".conti", L".hydra",
            L".clop", L".abyss", L".avdn", L".dharma"
        };

        // CORREÇÃO: Comparação segura sem wcslen
        for (ULONG i = 0; i < ARRAYSIZE(suspiciousExtensions); i++) {
            const WCHAR* susExt = suspiciousExtensions[i];

            // Calcular comprimento da extensão suspeita
            ULONG susExtLen = 0;
            while (susExt[susExtLen] != L'\0' && susExtLen < 20) {
                susExtLen++;
            }

            BOOLEAN match = TRUE;
            ULONG j;

            // Comparação case-insensitive manual
            for (j = 0; j < susExtLen; j++) {
                if (newExt[j] == L'\0') {
                    match = FALSE;
                    break;
                }

                WCHAR c1 = newExt[j];
                WCHAR c2 = susExt[j];

                // Converter para maiúsculas
                if (c1 >= L'a' && c1 <= L'z') c1 -= (L'a' - L'A');
                if (c2 >= L'a' && c2 <= L'z') c2 -= (L'a' - L'A');

                if (c1 != c2) {
                    match = FALSE;
                    break;
                }
            }

            // CORREÇÃO: Verificar terminador sem wcslen
            if (match && newExt[susExtLen] == L'\0') {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                    "Suspicious extension change detected: %wZ -> %wZ\n",
                    OldFileName, NewFileName);
                return TRUE;
            }
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "IsSuspiciousExtensionChange: Exception 0x%X\n", GetExceptionCode());
    }

    return FALSE;
}

VOID
UpdateRiskScore(
    _In_ PTR_BEHAVIOR_TRACKER Tracker,
    _In_ ULONG ScoreIncrement,
    _In_ PCSTR Reason
)
{
    if (!Tracker) {
        return;
    }

    Tracker->RiskScore += ScoreIncrement;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "RISK: PID %lu +%lu points (%s) - Total: %lu\n",
        HandleToUlong(Tracker->ProcessId), ScoreIncrement, Reason, Tracker->RiskScore);
}

VOID
GenerateBehaviorAlert(
    _In_ PTR_BEHAVIOR_TRACKER Tracker,
    _In_ PUNICODE_STRING FileName,
    _In_ PCSTR AlertReason
)
{
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return;
    }

    PAGED_CODE();

    if (!Tracker || Tracker->AlertCount >= g_BehaviorConfig.MaxAlertsPerProcess) {
        return;
    }

    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);

    // Rate limiting - não alertar mais que 1x por 10 segundos
    if ((currentTime.QuadPart - Tracker->LastAlertTime.QuadPart) < (10 * 10000000)) {
        return;
    }

    UNICODE_STRING behaviorRuleName = RTL_CONSTANT_STRING(L"Ransomware_Behavior");

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "BEHAVIOR ALERT: PID %lu, Reason: %s, File: %wZ, Risk: %lu\n",
        HandleToUlong(Tracker->ProcessId), AlertReason, FileName, Tracker->RiskScore);

    // Enviar alerta para user mode
    AlertToUserMode(FileName, Tracker->ProcessId, PsGetCurrentThreadId(),
        RULE_FLAG_MATCH, &behaviorRuleName);

    Tracker->AlertTriggered = TRUE;
    Tracker->AlertCount++;
    Tracker->LastAlertTime = currentTime;

    // Terminar processo se risco muito alto
    if (Tracker->RiskScore >= g_BehaviorConfig.RiskScoreThreshold && !Tracker->ProcessTerminated) {
        TerminateMaliciousProcess(Tracker);
    }
}

VOID
TerminateMaliciousProcess(
    _In_ PTR_BEHAVIOR_TRACKER Tracker
)
{
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return;
    }

    PAGED_CODE();

    if (!Tracker || Tracker->ProcessTerminated || !Tracker->ProcessObject) {
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "TERMINATING malicious process: PID %lu, Name: %wZ, Risk Score: %lu\n",
        HandleToUlong(Tracker->ProcessId), &Tracker->ProcessName, Tracker->RiskScore);

    // Usar função existente de terminação
    NTSTATUS status = KillMaliciousProcess(Tracker->ProcessObject);

    if (NT_SUCCESS(status)) {
        Tracker->ProcessTerminated = TRUE;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "Successfully terminated malicious process: PID %lu\n",
            HandleToUlong(Tracker->ProcessId));
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "Failed to terminate process PID %lu: 0x%X\n",
            HandleToUlong(Tracker->ProcessId), status);
    }
}

PTR_BEHAVIOR_TRACKER
GetOrCreateBehaviorTracker(
    _In_ HANDLE ProcessId,
    _In_ PEPROCESS Process
)
{
    KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql > PASSIVE_LEVEL) {
        return NULL;
    }

    PAGED_CODE();

    PTR_BEHAVIOR_TRACKER tracker = NULL;
    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);

    if (!IsPushLockInitialized(&g_BehaviorTrackerLock)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "BehaviorTrackerLock not initialized\n");
        return NULL;
    }

    // CORREÇÃO: Usar timeout
    NTSTATUS lockStatus = AcquirePushLockExclusiveWithTimeout(&g_BehaviorTrackerLock, 100);
    if (!NT_SUCCESS(lockStatus)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "Failed to acquire BehaviorTrackerLock: 0x%X\n", lockStatus);
        return NULL;
    }

    __try {
        // Procurar tracker existente
        PLIST_ENTRY entry;
        for (entry = g_BehaviorTrackerList.Flink;
            entry != &g_BehaviorTrackerList;
            entry = entry->Flink) {

            if (!IsListEntryValid(entry)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "Invalid list entry in behavior tracker list\n");
                break;
            }

            PTR_BEHAVIOR_TRACKER existing = CONTAINING_RECORD(entry, BEHAVIOR_TRACKER, ListEntry);
            if (existing->ProcessId == ProcessId) {
                tracker = existing;
                break;
            }
        }

        // Criar novo tracker se não encontrado
        if (!tracker) {
            tracker = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(BEHAVIOR_TRACKER), TAG_DATA_RULE);
            if (tracker) {
                RtlZeroMemory(tracker, sizeof(BEHAVIOR_TRACKER));
                tracker->ProcessId = ProcessId;
                tracker->ProcessObject = Process;
                tracker->FirstDetectionTime = currentTime;
                tracker->LastDetectionTime = currentTime;

                // CORREÇÃO: Tratamento seguro de memória paginada
                PUNICODE_STRING processNamePtr = NULL;
                NTSTATUS status = STATUS_UNSUCCESSFUL;

                __try {
                    status = SeLocateProcessImageName(Process, &processNamePtr);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    status = GetExceptionCode();
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                        "Exception calling SeLocateProcessImageName: 0x%X\n", status);
                }

                if (NT_SUCCESS(status) && processNamePtr != NULL) {
                    __try {
                        // Validar ponteiro antes de acessar
                        if (MmIsAddressValid(processNamePtr) &&
                            MmIsAddressValid(processNamePtr->Buffer)) {

                            tracker->ProcessName.Length = processNamePtr->Length;
                            tracker->ProcessName.MaximumLength = processNamePtr->Length + sizeof(WCHAR);
                            tracker->ProcessName.Buffer = ExAllocatePool2(POOL_FLAG_PAGED,
                                tracker->ProcessName.MaximumLength, TAG_RULE_NAME);

                            if (tracker->ProcessName.Buffer) {
                                RtlCopyMemory(tracker->ProcessName.Buffer,
                                    processNamePtr->Buffer,
                                    processNamePtr->Length);
                                tracker->ProcessName.Buffer[processNamePtr->Length / sizeof(WCHAR)] = L'\0';
                            }
                            else {
                                RtlInitUnicodeString(&tracker->ProcessName, NULL);
                            }
                        }

                        // Liberar a string retornada
                        ExFreePool(processNamePtr);
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                            "Exception processing process name: 0x%X\n", GetExceptionCode());
                        RtlInitUnicodeString(&tracker->ProcessName, NULL);
                    }
                }
                else {
                    // Fallback se falhar obter nome
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                        "Failed to get process name for PID %lu: 0x%X\n",
                        HandleToUlong(ProcessId), status);

                    WCHAR fallbackName[64];
                    RtlStringCchPrintfW(fallbackName, ARRAYSIZE(fallbackName),
                        L"Process_%lu", HandleToUlong(ProcessId));

                    RtlInitUnicodeString(&tracker->ProcessName, NULL);
                }

                // Verificar se é um processo de ransomware conhecido
                if (IsKnownRansomwareProcess(tracker)) {
                    tracker->RiskScore = 40;
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                        "Known ransomware process created tracker: %wZ\n", &tracker->ProcessName);
                }

                if (IsListValid(&g_BehaviorTrackerList)) {
                    InsertTailList(&g_BehaviorTrackerList, &tracker->ListEntry);

                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                        "New behavior tracker: PID %lu, Name: %wZ\n",
                        HandleToUlong(ProcessId), &tracker->ProcessName);
                }
                else {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                        "Behavior tracker list is invalid\n");
                    if (tracker->ProcessName.Buffer) {
                        ExFreePoolWithTag(tracker->ProcessName.Buffer, TAG_RULE_NAME);
                    }
                    ExFreePoolWithTag(tracker, TAG_DATA_RULE);
                    tracker = NULL;
                }
            }
        }
        else {
            tracker->LastDetectionTime = currentTime;
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "GetOrCreateBehaviorTracker: Exception 0x%X\n", GetExceptionCode());
        tracker = NULL;
    }

    ExReleasePushLockExclusive(&g_BehaviorTrackerLock);

    return tracker;
}

VOID
CleanupOldTrackers(VOID)
{
    PAGED_CODE();

    LARGE_INTEGER currentTime;
    LARGE_INTEGER timeout;
    timeout.QuadPart = -5LL * 60LL * 10000000LL;

    KeQuerySystemTime(&currentTime);

    // CORREÇÃO: Usar timeout no lock
    NTSTATUS lockStatus = AcquirePushLockExclusiveWithTimeout(&g_BehaviorTrackerLock, 100);
    if (!NT_SUCCESS(lockStatus)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "CleanupOldTrackers: Failed to acquire lock: 0x%X\n", lockStatus);
        return;
    }

    __try {
        PLIST_ENTRY entry = g_BehaviorTrackerList.Flink;
        while (entry != &g_BehaviorTrackerList) {
            PLIST_ENTRY next = entry->Flink;
            PTR_BEHAVIOR_TRACKER tracker = CONTAINING_RECORD(entry, BEHAVIOR_TRACKER, ListEntry);

            if (!tracker->AlertTriggered &&
                (currentTime.QuadPart - tracker->LastDetectionTime.QuadPart) > timeout.QuadPart) {

                RemoveEntryList(entry);
                if (tracker->ProcessName.Buffer &&
                    tracker->ProcessName.Buffer[0] != L'P') {
                    ExFreePoolWithTag(tracker->ProcessName.Buffer, TAG_RULE_NAME);
                }
                ExFreePoolWithTag(tracker, TAG_DATA_RULE);
            }

            entry = next;
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "CleanupOldTrackers: Exception 0x%X\n", GetExceptionCode());
    }

    ExReleasePushLockExclusive(&g_BehaviorTrackerLock);
}

BOOLEAN
DetectRansomwareBehavior(
    _In_ HANDLE ProcessId,
    _In_ PEPROCESS Process,
    _In_ PUNICODE_STRING FileName,
    _In_ PVOID WriteBuffer,
    _In_ ULONG WriteLength,
    _In_ BOOLEAN IsFileRename,
    _In_ BOOLEAN IsFileDelete
)
{
    PAGED_CODE();

    if (ProcessId == NULL || HandleToUlong(ProcessId) <= 100) {
        return FALSE;
    }

    static ULONG cleanupCounter = 0;
    if (++cleanupCounter >= 100) {
        CleanupOldTrackers();
        cleanupCounter = 0;
    }

    PTR_BEHAVIOR_TRACKER tracker = GetOrCreateBehaviorTracker(ProcessId, Process);
    if (!tracker) {
        return FALSE;
    }

    if (IsFileRename) {
        tracker->FilesRenamed++;
        UpdateRiskScore(tracker, 5, "File rename operation");
    }
    else if (IsFileDelete) {
        tracker->FilesDeleted++;
        UpdateRiskScore(tracker, 8, "File delete operation");
    }
    else {
        tracker->FilesModified++;
        tracker->TotalBytesWritten += WriteLength;
    }

    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);

    LONGLONG timeDelta = currentTime.QuadPart - tracker->FirstDetectionTime.QuadPart;
    LONGLONG seconds = timeDelta / 10000000;

    if (seconds == 0) seconds = 1;

    ULONG filesPerMinute = (tracker->FilesModified * 60) / (ULONG)seconds;
    ULONG bytesPerMinute = (tracker->TotalBytesWritten * 60) / (ULONG)seconds;

    BOOLEAN behaviorDetected = FALSE;

    if (filesPerMinute > g_BehaviorConfig.MaxFilesPerMinute) {
        UpdateRiskScore(tracker, 15, "High file modification rate");
        GenerateBehaviorAlert(tracker, FileName, "High file modification rate");
        behaviorDetected = TRUE;
    }

    if (bytesPerMinute > g_BehaviorConfig.MaxBytesPerMinute) {
        UpdateRiskScore(tracker, 20, "High data write rate");
        GenerateBehaviorAlert(tracker, FileName, "High data write rate");
        behaviorDetected = TRUE;
    }

    if (WriteLength >= 256 && IsLikelyEncrypted(WriteLength, WriteBuffer)) {
        tracker->HighEntropyWrites++;
        UpdateRiskScore(tracker, 25, "High entropy data (encrypted)");
        GenerateBehaviorAlert(tracker, FileName, "High entropy data detected");
        behaviorDetected = TRUE;
    }

    if (tracker->FilesRenamed > g_BehaviorConfig.FileExtensionChangesThreshold) {
        UpdateRiskScore(tracker, 30, "Multiple file renames");
        GenerateBehaviorAlert(tracker, FileName, "Multiple file extension changes");
        behaviorDetected = TRUE;
    }

    if (tracker->FilesDeleted > 20) {
        UpdateRiskScore(tracker, 20, "Multiple file deletions");
        GenerateBehaviorAlert(tracker, FileName, "Multiple file deletions");
        behaviorDetected = TRUE;
    }

    if (tracker->HighEntropyWrites > 5 && filesPerMinute > 10) {
        UpdateRiskScore(tracker, 35, "Encryption + high file activity");
        GenerateBehaviorAlert(tracker, FileName, "Mass encryption behavior");
        behaviorDetected = TRUE;
    }

    if (IsKnownRansomwareProcess(tracker) && filesPerMinute > 5) {
        UpdateRiskScore(tracker, 25, "Suspicious process name + file activity");
        GenerateBehaviorAlert(tracker, FileName, "Suspicious process activity");
        behaviorDetected = TRUE;
    }

    return behaviorDetected;
}
