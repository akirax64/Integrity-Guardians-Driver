#include "precompiled.h"

UNICODE_STRING g_CryptoRuleName = RTL_CONSTANT_STRING(ALGORITHM_PATTERN);

__forceinline
BOOLEAN
IsIrqlSafeForOperation(
    _In_ KIRQL CurrentIrql,
    _In_ BOOLEAN RequirePassiveLevel
)
{
    if (RequirePassiveLevel) {
        return (CurrentIrql == PASSIVE_LEVEL);
    }

    return (CurrentIrql <= APC_LEVEL);
}

BOOLEAN
QuickPatternCheckDispatchLevel(
    _In_ PFLT_CALLBACK_DATA data
)
{
    PMDL mdl = data->Iopb->Parameters.Write.MdlAddress;
    if (!mdl) return FALSE;

    PVOID writeBuffer = MmGetSystemAddressForMdlSafe(mdl, HighPagePriority);
    if (!writeBuffer) return FALSE;

    ULONG length = min(data->Iopb->Parameters.Write.Length, 64); // Muito limitado

    return CheckPatternsDispatch(writeBuffer, length);
}

__forceinline
BOOLEAN
QuickExtensionCheckAPC(
    _In_ PUNICODE_STRING fileName
)
{
    if (!fileName || !fileName->Buffer || fileName->Length < 6) {
        return FALSE;
    }

    __try {
        PWCHAR buf = fileName->Buffer;
        USHORT len = fileName->Length / sizeof(WCHAR);
        PWCHAR lastDot = NULL;

        // Encontra o último ponto manualmente (sem wcsrchr)
        for (USHORT i = 0; i < len; i++) {
            if (buf[i] == L'.') {
                lastDot = &buf[i];
            }
        }

        if (!lastDot) return FALSE;

        // Verifica apenas as extensões mais críticas (hardcoded)
        // ".crypt" - 6 caracteres
        if (lastDot[1] == L'c' && lastDot[2] == L'r' && lastDot[3] == L'y' &&
            lastDot[4] == L'p' && lastDot[5] == L't' && lastDot[6] == L'\0') {
            return TRUE;
        }

        // ".locked" - 7 caracteres  
        if (lastDot[1] == L'l' && lastDot[2] == L'o' && lastDot[3] == L'c' &&
            lastDot[4] == L'k' && lastDot[5] == L'e' && lastDot[6] == L'd' &&
            lastDot[7] == L'\0') {
            return TRUE;
        }

        // ".encrypted" - 10 caracteres (apenas verifica início)
        if (lastDot[1] == L'e' && lastDot[2] == L'n' && lastDot[3] == L'c' &&
            lastDot[4] == L'r') {
            return TRUE;
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Silencia exceções em APC_LEVEL
    }

    return FALSE;
}

BOOLEAN
QuickPatternCheckApcLevel(
    _In_ PVOID buffer,
    _In_ ULONG length
)
{
    if (!buffer || length < 8) return FALSE;
    length = min(length, 128); // Muito limitado

    __try {
        volatile UCHAR test = *((volatile PUCHAR)buffer);
        UNREFERENCED_PARAMETER(test);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    return CheckPatternsDispatch(buffer, length);
}
BOOLEAN
CheckPatternsDispatch(
    _In_ PVOID buffer,
    _In_ ULONG length
)
{
    KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql > APC_LEVEL) {
        return FALSE; // Não fazer pattern matching em DISPATCH_LEVEL ou maior
    }

    // Padrões hardcoded para evitar acesso a memória paginada
    const UCHAR lockbitPattern[] = { 0x4C, 0x6F, 0x63, 0x6B, 0x42, 0x69, 0x74, 0x20 };

    if (length < 8) return FALSE;

    PUCHAR scanBuffer = (PUCHAR)buffer;

	// Limitar o escaneamento para evitar longas operações em IRQL alto
    ULONG safeLength = (length >= 8) ? (length - 8) : 0;
    ULONG irqlLimit = (currentIrql == APC_LEVEL) ? 16 : 32;
    ULONG scanLimit = (safeLength < irqlLimit) ? safeLength : irqlLimit;

    for (ULONG i = 0; i <= scanLimit; i++) {
        BOOLEAN match = TRUE;

        for (ULONG j = 0; j < 8; j++) {
            if (scanBuffer[i + j] != lockbitPattern[j]) {
                match = FALSE;
                break;
            }
        }

        if (match) return TRUE;
    }

    return FALSE;
}

// DETECÇÃO DE PADRÕES DE CRIPTOGRAFIA
BOOLEAN
DetectEncryptionPatterns(
    _In_ PVOID buffer,
    _In_ ULONG length
)
{
    KIRQL currentIrql = KeGetCurrentIrql();

    if (!IsIrqlSafeForOperation(currentIrql, FALSE)) {
        return FALSE;
    }

    if (currentIrql == PASSIVE_LEVEL) {
        PAGED_CODE(); 
    }

    if (!buffer || length < 8 || length > MAX_SCAN_LENGTH) {
        return FALSE;
    }

    if (currentIrql == APC_LEVEL) {
        length = min(length, 128);
    }

    // Validação robusta do buffer
    __try {
        volatile UCHAR testByte = *((volatile PUCHAR)buffer);
        UNREFERENCED_PARAMETER(testByte);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    BOOLEAN detected = FALSE;

    __try {
        // Padrões de ransomware conhecidos
        const UCHAR patterns[][8] = {
            {0x4C, 0x6F, 0x63, 0x6B, 0x42, 0x69, 0x74, 0x20}, // "LockBit "
            {0x43, 0x6F, 0x6E, 0x74, 0x69, 0x20, 0x52, 0x61}, // "Conti Ra"
        };

        ULONG scanLimit = min(length, 256);
        if (currentIrql == APC_LEVEL) {
            scanLimit = min(scanLimit, 64);
        }

        for (ULONG p = 0; p < ARRAYSIZE(patterns) && !detected; p++) {
            for (ULONG i = 0; i <= scanLimit - 8 && !detected; i++) {
                SIZE_T matches = 0;

                // Verificação segura
                SAFE_COMPARE((PUCHAR)buffer + i, patterns[p], 8, matches);

                if (matches == 8) {
                    detected = TRUE;
                    if (currentIrql == PASSIVE_LEVEL) {
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Pattern detected at position %lu\n", i);
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        detected = FALSE;
    }

    return detected;
}

// VERIFICAÇÃO RÁPIDA - CORREÇÕES DE IRQL
BOOLEAN
QuickPatternCheck(
    _In_ PVOID buffer,
    _In_ ULONG length
)
{
    KIRQL currentIrql = KeGetCurrentIrql();

    if (currentIrql >= DISPATCH_LEVEL) {
        return FALSE;
    }

    if (!buffer || length < 8) return FALSE;

    // Limitar drasticamente em IRQL alto
    if (currentIrql == APC_LEVEL) {
        return QuickPatternCheckApcLevel(buffer, length);
    }

    PAGED_CODE();
    return DetectEncryptionPatterns(buffer, min(length, 512));
}

BOOLEAN
ScanBuffer(
    _In_ PVOID buffer,
    _In_ ULONG length,
    _In_ PUNICODE_STRING fileName,
    _In_opt_ PEPROCESS process
)
{
    UNREFERENCED_PARAMETER(process);

    KIRQL currentIrql = KeGetCurrentIrql();

    if (!IsIrqlSafeForOperation(currentIrql, FALSE)) {
        return FALSE;
    }

    if (currentIrql == PASSIVE_LEVEL) {
        PAGED_CODE();
    }

    // VALIDAÇÃO MAIS RIGOROSA
    if (!buffer || length == 0 || length > MAX_SCAN_LENGTH) {
        return FALSE;
    }

    if (currentIrql == APC_LEVEL) {
        length = min(length, 1024);
    }

    // verificando se esta na whitelist de paths
    if (IsPathExcludedFromDetection(fileName)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "Detection: Path %wZ is excluded from scanning.\n", fileName);
        return FALSE;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "Detection: Scanning buffer for %wZ (Length: %lu)...\n", fileName, length);

    BOOLEAN detected = FALSE;
    // VERIFICAÇÃO DE CRIPTOGRAFIA
    if (DetectEncryptionPatterns(buffer, min(length, 8192))) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "Detection: CRYPTO PATTERN DETECTED in %wZ\n", fileName);

        AlertToUserMode(
            fileName,
            PsGetCurrentProcessId(),
            PsGetCurrentThreadId(),
            RULE_FLAG_MATCH,
            &g_CryptoRuleName
        );
    }
    detected = TRUE;
    // CORREÇÃO: ExTryAcquirePushLockShared que retorna BOOLEAN

    if (!detected && currentIrql == PASSIVE_LEVEL) {
        if (!IsPushLockInitialized(&g_driverContext.RulesListLock)) {
            return detected;
        }
        NTSTATUS lockStatus = AcquirePushLockSharedWithTimeout(&g_driverContext.RulesListLock, 50);
        if (NT_SUCCESS(lockStatus)) {
            __try {
                if (IsListValid(&g_driverContext.RulesList)) {
                    PLIST_ENTRY listEntry = g_driverContext.RulesList.Flink;
                    ULONG ruleCount = 0;
                    const ULONG maxRules = 1000;

                    while (listEntry != &g_driverContext.RulesList && ruleCount < maxRules && !detected) {
                        if (!IsListEntryValid(listEntry)) break;

                        PTR_RULE_INFO rule = CONTAINING_RECORD(listEntry, RULE_INFO, ListEntry);

                        if (rule && rule->PatternData && rule->PatternLength > 0 &&
                            length >= rule->PatternLength) {

                            ULONG maxScan = min(length - rule->PatternLength, 8192);

                            for (ULONG i = 0; i <= maxScan && !detected; ++i) {
                                SIZE_T bytesEqual = 0;
                                SAFE_COMPARE((PUCHAR)buffer + i, rule->PatternData,
                                    rule->PatternLength, bytesEqual);

                                if (bytesEqual == rule->PatternLength) {
                                    detected = TRUE;
                                    AlertToUserMode(fileName, PsGetCurrentProcessId(),
                                        PsGetCurrentThreadId(), rule->Flags,
                                        &rule->RuleName);
                                }
                            }
                        }
                        listEntry = listEntry->Flink;
                        ruleCount++;
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                detected = FALSE;
            }
            ExReleasePushLockShared(&g_driverContext.RulesListLock);
        }
    }

    return detected;
}

BOOLEAN
IsPathExcludedFromDetection(_In_ PUNICODE_STRING PathName)
{
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FALSE;
    }

    PAGED_CODE();

    if (!PathName || !PathName->Buffer || PathName->Length == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "DEBUG: Path vazio/nulo - permitindo scan\n");
        return FALSE;
    }

    BOOLEAN isExcluded = FALSE;

    __try {
        isExcluded = IsPathExcluded(PathName);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,  //  LOG IMPORTANTE
            "DEBUG: Path %wZ - Excluded: %s\n",
            PathName, isExcluded ? "SIM" : "NÃO");

        if (isExcluded) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "DEBUG: Path EXCLUÍDO da detecção: %wZ\n", PathName);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "DEBUG: Exception em IsPathExcludedFromDetection - allowing scan\n");
        isExcluded = FALSE;
    }

    return isExcluded;
}

BOOLEAN
IsPathMonitored(
    _In_ PUNICODE_STRING pathName
)
{
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return TRUE;
    }

    PAGED_CODE();

    return !IsPathExcludedFromDetection(pathName);
}

BOOLEAN
ScanFileContent(
    _In_ PFILE_OBJECT fileObject,
    _In_ PFLT_INSTANCE initialInstance,
    _In_opt_ PEPROCESS process
)
{
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return FALSE;
    }

    if (!fileObject || !initialInstance) {
        return FALSE;
    }
    
    if (!g_FilterHandle) {
        return FALSE;
    }

    PAGED_CODE();

    // verifica antes se o caminho do arquivo está na whitelist
    if (IsPathExcludedFromDetection(&fileObject->FileName)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "Detection: Path %wZ excluded from full scan.\n", &fileObject->FileName);
        return FALSE;
    }

    NTSTATUS status;
    PVOID readBuffer = NULL;
    ULONG bytesToRead;
    ULONG bytesRead;
    LARGE_INTEGER byteOffset;
    BOOLEAN fileDetected = FALSE;
    ULONG chunkSize = 65536;
    ULONG volumeAlignmentRequirement = 512;

    UNREFERENCED_PARAMETER(process);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "Detection: ScanFileContent - Starting full file scan for %wZ.\n", &fileObject->FileName);

    // obtendo o tamanho do volume
    PFLT_VOLUME volume = NULL;
    FLT_VOLUME_PROPERTIES volumeProperties;
    ULONG returnedLength;

    status = FltGetVolumeFromInstance(initialInstance, &volume);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Detection: Failed to get volume from instance (0x%X) for %wZ.\n", status, &fileObject->FileName);
        return FALSE;
    }

    // pegando propriedades do volume
    status = FltGetVolumeProperties(
        volume,
        &volumeProperties,
        sizeof(volumeProperties),
        &returnedLength
    );
    FltObjectDereference(volume);

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Detection: Failed to get volume properties (0x%X) for %wZ.\n", status, &fileObject->FileName);
        // redefinindo para o padrao novamente apos falha na recuperacao de propriedades
        volumeAlignmentRequirement = 512;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Detection: Defaulting alignment to 512 bytes due to failed properties retrieval.\n");
    }
    else {
        volumeAlignmentRequirement = volumeProperties.SectorSize;

        // se o tamanho do setor do volume for 0, use o valor padrão de 512 bytes
        if (volumeAlignmentRequirement == 0) {
            volumeAlignmentRequirement = 512;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Detection: Volume SectorSize reported as 0, defaulting to 512 bytes.\n");
        }
    }

    // garantindo que o chunkSize seja um múltiplo do alinhamento do volume
    if (chunkSize % volumeAlignmentRequirement != 0) {
        chunkSize = (chunkSize / volumeAlignmentRequirement + 1) * volumeAlignmentRequirement;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Detection: Adjusted chunkSize to %lu for alignment requirement.\n", chunkSize);
    }

    // pegando informações do arquivo para verificar o tamanho
    FILE_STANDARD_INFORMATION fileInfo;
    status = FltQueryInformationFile(
        initialInstance,
        fileObject,
        &fileInfo,
        sizeof(fileInfo),
        FileStandardInformation,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Detection: Failed to get file size for %wZ (0x%X).\n", &fileObject->FileName, status);
        return FALSE;
    }
    ULONGLONG fileSize = fileInfo.EndOfFile.QuadPart;

    if (fileSize == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Detection: File %wZ is empty, no scan needed.\n", &fileObject->FileName);
        return FALSE;
    }

    // vai alocar um buffer temporário para leitura do arquivo
    readBuffer = FltAllocatePoolAlignedWithTag(
        initialInstance,
        POOL_FLAG_PAGED,
        chunkSize,
        TAG_SCAN
    );
    if (readBuffer == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Detection: Failed to allocate aligned buffer for file scan of %wZ.\n", &fileObject->FileName);
        return FALSE;
    }

    byteOffset.QuadPart = 0; // vai começar do início do arquivo

    // loop para ler o arquivo em blocos alinhados
    while ((ULONGLONG)byteOffset.QuadPart < fileSize && !fileDetected) {
        // ira calcular o tamanho do bloco a ser lido ja garantindo que seja alinhado ao tamanho do volume
        bytesToRead = (ULONG)min((ULONGLONG)chunkSize, (ULONGLONG)(fileSize - byteOffset.QuadPart));
        bytesToRead = (bytesToRead / volumeAlignmentRequirement) * volumeAlignmentRequirement; // Round down

        // situacao de controle para evitar ler menos que o alinhamento do volume
        if (bytesToRead == 0) {
            if ((ULONGLONG)byteOffset.QuadPart < fileSize) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Detection: Remaining file bytes less than alignment requirement (%llu bytes left), stopping aligned scan.\n", fileSize - byteOffset.QuadPart);
            }
            break;
        }

        // tendo certeza de que o offset do arquivo está alinhado ao tamanho do volume
        if (byteOffset.QuadPart % volumeAlignmentRequirement != 0) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Detection: Byte offset %llu not aligned (%lu). Critical logic error.\n", byteOffset.QuadPart, volumeAlignmentRequirement);
            fileDetected = FALSE;
            break;
        }

        // leitura do arquivo usando FltReadFile
        status = FltReadFile(
            initialInstance,
            fileObject,
            &byteOffset,
            bytesToRead,
            readBuffer,
            FLTFL_IO_OPERATION_NON_CACHED,
            &bytesRead,
            NULL,
            NULL
        );

        if (!NT_SUCCESS(status) || bytesRead == 0) {
            if (status == STATUS_END_OF_FILE && bytesRead > 0) {
                // vai continuar lendo até acabar o arquivo
            }
            else if (status == STATUS_END_OF_FILE && bytesRead == 0) {
                break;
            }
            else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Detection: FltReadFile failed (0x%X) or read 0 bytes for %wZ.\n", status, &fileObject->FileName);
                break;
            }
        }

        // VERIFICAÇÃO DE CRIPTOGRAFIA NO SCAN DE ARQUIVO
        if (DetectEncryptionPatterns(readBuffer, bytesRead)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "Detection: CRYPTO PATTERN DETECTED during file scan of %wZ\n", &fileObject->FileName);

            AlertToUserMode(
                &fileObject->FileName,
                PsGetCurrentProcessId(),
                PsGetCurrentThreadId(),
                RULE_FLAG_MATCH,
                &g_CryptoRuleName
            );
            fileDetected = TRUE;
            break;
        }

        // se for reconhecido um padrão no buffer lido, vai marcar como detectado
        if (ScanBuffer(readBuffer, bytesRead, &fileObject->FileName, process)) {
            fileDetected = TRUE;
            break;
        }

        byteOffset.QuadPart += bytesRead;
    }

    if (readBuffer) {
        FltFreePoolAlignedWithTag(initialInstance, readBuffer, TAG_SCAN);
    }

    return fileDetected;
}

BOOLEAN
IsSuspiciousExtension(
    _In_ PUNICODE_STRING fileName
)
{
    if (KeGetCurrentIrql() > APC_LEVEL) {
        // Em IRQL alto, fazer verificação muito básica
        __try {
            if (fileName && fileName->Buffer) {
                PWCHAR buf = fileName->Buffer;
                for (USHORT i = 0; i < fileName->Length / sizeof(WCHAR); i++) {
                    if (buf[i] == L'.' && buf[i + 1] == L'c' && buf[i + 2] == L'r' && buf[i + 3] == L'y' && buf[i + 4] == L'p' && buf[i + 5] == L't') {
                        return TRUE;
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        return FALSE;
    }
    
    // verificacao inicial de path
    if (IsPathExcludedFromDetection(fileName)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "Detection: Path %wZ excluded from extension check.\n", fileName);
        return FALSE;
    }

    // extensões comuns de ransomware
    const wchar_t* suspiciousExtensions[] = {
        L".crypt", L".locked", L".encrypted", L".ransom",
        L".crypto", L".xtbl", L".zepto", L".cerber",
        L".akira", L".lockbit", L".conti", L".hydra",
        L".clop", L".ABYSS", L".avdn", L".dharma"
    };

    if (KeGetCurrentIrql() >= DISPATCH_LEVEL) {
        return FALSE;
    }

    if (KeGetCurrentIrql() == APC_LEVEL) {
        return QuickExtensionCheckAPC(fileName);
    }

    PAGED_CODE();

    __try {
        // procurando a última ocorrência do ponto na string
        PWSTR lastDot = wcsrchr(fileName->Buffer, L'.');
        if (!lastDot) {
            return FALSE;
        }

        // verificando se é uma extensão suspeita
        for (int i = 0; i < ARRAYSIZE(suspiciousExtensions); i++) {
            if (_wcsicmp(lastDot, suspiciousExtensions[i]) == 0) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                    "Detection: Suspicious extension detected: %wZ\n", fileName);
                return TRUE;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "EXCEPTION in IsSuspiciousExtension\n");
    }

    return FALSE;
}