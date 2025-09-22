#include "precompiled.h"
// verifica se o caminho fornecido deve ser excluído da detecção
BOOLEAN
IsPathExcludedFromDetection(_In_ PUNICODE_STRING PathName)
{
    PAGED_CODE();

    if (!PathName || !PathName->Buffer || PathName->Length == 0) {
        return FALSE;
    }

    BOOLEAN isExcluded = FALSE;

    __try {
        isExcluded = IsPathExcluded(PathName);

        if (isExcluded) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "Detection: Path %wZ is excluded from scanning.\n", PathName);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "IsPathExcludedFromDetection: Exception 0x%X - allowing scan\n", GetExceptionCode());
        isExcluded = FALSE;
    }

    return isExcluded;
}

// verifica se o caminho fornecido deve ser monitorado
BOOLEAN
IsPathMonitored(
    _In_ PUNICODE_STRING pathName
)
{
    PAGED_CODE();

    return !IsPathExcludedFromDetection(pathName);
}


// detecta se o buffer contém padrões de regras definidos
BOOLEAN
ScanBuffer(
    _In_ PVOID buffer,
    _In_ ULONG length,
    _In_ PUNICODE_STRING fileName,
    _In_opt_ PEPROCESS process
)
{
    UNREFERENCED_PARAMETER(process);

    if (!buffer || length == 0) {
        return FALSE;
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

    // protecao da lista de regras com push lock
    ExAcquirePushLockShared(&g_driverContext.RulesListLock);

    PLIST_ENTRY listEntry = g_driverContext.RulesList.Flink;
    while (listEntry != &g_driverContext.RulesList) {
        PTR_RULE_INFO rule = CONTAINING_RECORD(listEntry, RULE_INFO, ListEntry);

        if (rule->PatternData && rule->PatternLength > 0 && length >= rule->PatternLength) {
            for (ULONG i = 0; i <= length - rule->PatternLength; ++i) {
                // comparando o buffer com o padrão da regra
                SIZE_T bytesEqual = 0;
                SAFE_COMPARE((PUCHAR)buffer + i, rule->PatternData, rule->PatternLength, bytesEqual);

                if (bytesEqual == rule->PatternLength) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                        "!!! Detection: Rule '%wZ' detected in %wZ !!!\n", &rule->RuleName, fileName);

                    detected = TRUE;

                    AlertToUserMode(
                        fileName,
                        PsGetCurrentProcessId(),
                        PsGetCurrentThreadId(),
                        rule->Flags,
                        &rule->RuleName
                    );

                    if (detected && (rule->Flags & RULE_FLAG_MATCH)) {
                        // se for detectado e ativar a flag de match, parar a varredura
                        break;
                    }
                }
            }
        }
        listEntry = listEntry->Flink;
    }
    ExReleasePushLockShared(&g_driverContext.RulesListLock);

    return detected;
}

// escaneando o conteúdo do arquivo fornecido
BOOLEAN
ScanFileContent(
    _In_ PFILE_OBJECT fileObject,
    _In_ PFLT_INSTANCE initialInstance,
    _In_opt_ PEPROCESS process
)
{
    PAGED_CODE();

    // verifica antes se o caminho do arquivo está na whitelist
    if (IsPathExcludedFromDetection(&fileObject->FileName)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "Detection: Path %wZ excluded from full scan.\n", &fileObject->FileName);
        return FALSE;
    }

    NTSTATUS            status;
    PVOID               readBuffer = NULL;
    ULONG               bytesToRead;
    ULONG               bytesRead;
    LARGE_INTEGER       byteOffset;
    BOOLEAN             fileDetected = FALSE;
    ULONG               chunkSize = 65536;
    ULONG               volumeAlignmentRequirement = 512;

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