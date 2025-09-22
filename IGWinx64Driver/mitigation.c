#include "precompiled.h"

// bloqueia uma operacao suspeita de I/O no filtro de arquivos
VOID
BlockSuspiciousOperation(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ NTSTATUS statusToSet
)
{
    NTSTATUS safeStatus = STATUS_ACCESS_DENIED;

    __try {
        // lista de status permitidos para bloqueio
        const NTSTATUS allowedStatus[] = {
            STATUS_ACCESS_DENIED,          
            STATUS_NETWORK_ACCESS_DENIED,   
            STATUS_SHARING_VIOLATION,      
            STATUS_FILE_IS_A_DIRECTORY,     
            STATUS_INSUFFICIENT_RESOURCES,  
            STATUS_DISK_FULL,               
            STATUS_FILE_LOCK_CONFLICT,     
            STATUS_CANNOT_DELETE,           
            STATUS_FILE_INVALID             
        };

        BOOLEAN isValidStatus = FALSE;

		// verifica o ntstatus solicitado para garantir que é um erro de acesso
        if ((statusToSet & 0x80000000) != 0) {
            for (ULONG i = 0; i < ARRAYSIZE(allowedStatus); i++) {
                if (statusToSet == allowedStatus[i]) {
                    isValidStatus = TRUE;
                    break;
                }
            }
        }

        if (isValidStatus) {
            safeStatus = statusToSet;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "Mitigation: Blocking operation for file %wZ with status 0x%X\n",
                &data->Iopb->TargetFileObject->FileName, safeStatus);
        }
        else {
            safeStatus = STATUS_ACCESS_DENIED;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "Mitigation: Invalid status 0x%X requested, using STATUS_ACCESS_DENIED for file %wZ\n",
                statusToSet, &data->Iopb->TargetFileObject->FileName);
        }

        // bloqueia a operação
        data->IoStatus.Status = safeStatus;
        data->IoStatus.Information = 0;
        FltSetCallbackDataDirty(data);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        data->IoStatus.Status = STATUS_ACCESS_DENIED;
        data->IoStatus.Information = 0;
        FltSetCallbackDataDirty(data);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "BlockSuspiciousOperation: Exception 0x%X, using STATUS_ACCESS_DENIED as fallback\n",
            GetExceptionCode());
    }
}

NTSTATUS
BackupFile(
    _In_ PFILE_OBJECT fileObject,
    _In_ PUNICODE_STRING originalFileName,
    _In_ PFLT_INSTANCE initialInstance
)
{
    PAGED_CODE();

    NTSTATUS        status = STATUS_SUCCESS;
    HANDLE          backupFileHandle = NULL;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatusBlock;
    LARGE_INTEGER   byteOffset;
    ULONG           currentChunkLength;
    ULONG           bytesActuallyRead = 0;
    ULONG           bytesActuallyWritten = 0;
    PVOID           buffer = NULL;
    ULONG           chunkSize = 65536;
    UNICODE_STRING  backupFileName;
    WCHAR           backupFileNameBuffer[UNICODE_STRING_MAX_CHARS + 64];

    if (!fileObject || !originalFileName || !originalFileName->Buffer || originalFileName->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "Mitigation: Attempting to backup file %wZ\n", originalFileName);

    __try {
        RtlStringCchCopyW(backupFileNameBuffer, ARRAYSIZE(backupFileNameBuffer), originalFileName->Buffer);
        RtlStringCchCatW(backupFileNameBuffer, ARRAYSIZE(backupFileNameBuffer), L".bkp");
        RtlInitUnicodeString(&backupFileName, backupFileNameBuffer);

        InitializeObjectAttributes(
            &objAttr,
            &backupFileName,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            NULL
        );

        status = FltCreateFile(
            g_FilterHandle,
            initialInstance,
            &backupFileHandle,
            GENERIC_WRITE | SYNCHRONIZE,
            &objAttr,
            &ioStatusBlock,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OVERWRITE_IF,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
            NULL,
            0,
            0
        );

        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "Mitigation: Failed to create backup file %wZ (0x%X).\n", &backupFileName, status);
            return status;
        }

        buffer = ExAllocatePool2(POOL_FLAG_PAGED, chunkSize, TAG_BACKUP);
        if (!buffer) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "Mitigation: Failed to allocate buffer for backup file.\n");
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

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
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "Mitigation: Failed to get original file size (0x%X).\n", status);
            goto Cleanup;
        }

        ULONGLONG fileSize = fileInfo.EndOfFile.QuadPart;
        if (fileSize == 0) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "Mitigation: File is empty, no backup needed.\n");
            status = STATUS_SUCCESS;
            goto Cleanup;
        }

		byteOffset.QuadPart = 0;
        while ((ULONGLONG)byteOffset.QuadPart < fileSize) {
            currentChunkLength = (ULONG)min((ULONGLONG)chunkSize, fileSize - (ULONGLONG)byteOffset.QuadPart);

            // vai ler o arquivo original
            status = FltReadFile(
                initialInstance,
                fileObject,
                &byteOffset,
                currentChunkLength,
                buffer,
                0,
                &bytesActuallyRead,
                NULL,
                NULL
            );

            if (!NT_SUCCESS(status) || bytesActuallyRead == 0) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                    "Mitigation: Failed to read from original file (0x%X).\n", status);
                goto Cleanup;
            }

            // vai escrever no arquivo de backup
            status = FltWriteFile(
                initialInstance,
                backupFileHandle,
                &byteOffset,
                bytesActuallyRead,
                buffer,
                0,
                &bytesActuallyWritten,
                NULL,
                NULL
            );

            if (!NT_SUCCESS(status) || bytesActuallyWritten != bytesActuallyRead) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                    "Mitigation: Failed to write to backup file (0x%X), bytes read: %lu, written: %lu\n",
                    status, bytesActuallyRead, bytesActuallyWritten);
                goto Cleanup;
            }

            byteOffset.QuadPart += bytesActuallyRead;
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "Mitigation: File %wZ successfully backed up to %wZ\n", originalFileName, &backupFileName);
        status = STATUS_SUCCESS;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "BackupFile: Exception 0x%X during backup operation\n", status);
    }

Cleanup:
    if (buffer) {
        ExFreePoolWithTag(buffer, TAG_BACKUP);
    }
    if (backupFileHandle) {
        FltClose(backupFileHandle);

        // Se falhou, tenta deletar o arquivo de backup incompleto
        if (!NT_SUCCESS(status)) {
            NTSTATUS deleteStatus = DeleteBackupFile(&backupFileName);
            if (!NT_SUCCESS(deleteStatus)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "Mitigation: Failed to delete incomplete backup file (0x%X)\n", deleteStatus);
            }
        }
    }

    return status;
}

NTSTATUS
DeleteBackupFile(
    _In_ PUNICODE_STRING FileName
){
    PAGED_CODE();

    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE fileHandle = NULL;
    IO_STATUS_BLOCK ioStatusBlock;
    FILE_DISPOSITION_INFORMATION dispositionInfo;

    InitializeObjectAttributes(
        &objAttr,
        FileName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    status = ZwCreateFile(
        &fileHandle,
        DELETE | SYNCHRONIZE,
        &objAttr,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_DELETE,  
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "DeleteBackupFile: Failed to open file %wZ for deletion (0x%X)\n", FileName, status);
        return status;
    }

	// vai deletar o arquivo
    dispositionInfo.DeleteFile = TRUE;

       status = ZwSetInformationFile(
        fileHandle,
        &ioStatusBlock,
        &dispositionInfo,
        sizeof(FILE_DISPOSITION_INFORMATION),
        FileDispositionInformation
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "DeleteBackupFile: Failed to set deletion info for %wZ (0x%X)\n", FileName, status);
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "DeleteBackupFile: Successfully marked %wZ for deletion\n", FileName);
    }

    if (fileHandle) {
        ZwClose(fileHandle);
    }

    return status;
}

// funcao auxiliar para verificar se é um processo do sistema
BOOLEAN
IsSystemProcess(
    _In_ PEPROCESS process
)
{
    PAGED_CODE();

    if (!process) {
        return FALSE;
    }

    // processos críticos do sistema que NÃO devem ser terminados
    const CHAR* systemProcesses[] = {
        "System",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "svchost.exe",
        "winlogon.exe",
        "wininit.exe",
        "explorer.exe"
    };

    BOOLEAN isSystem = FALSE;

    __try {
        // verifica processos especiais
        PEPROCESS currentProcess = PsGetCurrentProcess();
        if (process == currentProcess) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "Mitigation: Attempt to terminate current process blocked\n");
            return TRUE;
        }

        if (process == PsInitialSystemProcess) {
            return TRUE;  // processo System
        }

        // verificacao por PID (processos críticos do kernel)
        HANDLE processId = PsGetProcessId(process);
        if (processId == NULL || HandleToULong(processId) <= 100) {
            return TRUE;  // PID muito baixo, provavelmente sistema
        }

        // verificacao por nome
        PUNICODE_STRING processName = NULL;
        NTSTATUS status = SeLocateProcessImageName(process, &processName);

        if (NT_SUCCESS(status) && processName && processName->Buffer) {
            // converter para ANSI para comparação
            ANSI_STRING ansiName;
            CHAR processNameBuffer[256] = { 0 };

            RtlInitAnsiString(&ansiName, processNameBuffer);
            status = RtlUnicodeStringToAnsiString(&ansiName, processName, TRUE);

            if (NT_SUCCESS(status)) {
                // verificar contra lista de processos do sistema
                for (ULONG i = 0; i < ARRAYSIZE(systemProcesses); i++) {
                    ANSI_STRING targetName;
                    RtlInitAnsiString(&targetName, systemProcesses[i]);

                    if (RtlCompareString(&ansiName, &targetName, TRUE) == 0) {
                        isSystem = TRUE;
                        break;
                    }
                }
                RtlFreeAnsiString(&ansiName);
            }
            ExFreePool(processName);
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "IsSystemProcess: Exception 0x%X, assuming system process for safety\n", GetExceptionCode());
        isSystem = TRUE;  // em caso de erro, assume que é sistema por segurança
    }

    return isSystem;
}

// termina um processo malicioso com verificações de segurança
NTSTATUS
KillMaliciousProcess(
    _In_ PEPROCESS process
)
{
    PAGED_CODE();

    if (!process) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "Mitigation: Invalid process parameter\n");
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = STATUS_SUCCESS;
    HANDLE processHandle = NULL;
    HANDLE processId = PsGetProcessId(process);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "Mitigation: Attempting to terminate malicious process PID %lu\n", HandleToULong(processId));

    __try {
        // verifica se o processo ainda é válido
        if (PsGetProcessExitStatus(process) != STATUS_PENDING) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "Mitigation: Process PID %lu is terminating or terminated (ExitStatus: 0x%X)\n",
                HandleToULong(processId), PsGetProcessExitStatus(process));
            return STATUS_PROCESS_IS_TERMINATING;
        }

        // verifica se não é um processo crítico do sistema
        if (IsSystemProcess(process)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "Mitigation: Skipping termination of system process PID %lu\n", HandleToULong(processId));
            return STATUS_ACCESS_DENIED;
        }

        // obter handle para o processo com permissões mínimas
        status = ObOpenObjectByPointer(
            process,
            OBJ_KERNEL_HANDLE,
            NULL,
			0x0001 | SYNCHRONIZE, // PROCESS_TERMINATE | SYNCHRONIZE
            *PsProcessType,
            KernelMode,
            &processHandle
        );

        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "Mitigation: Failed to open process PID %lu (0x%X)\n", HandleToULong(processId), status);
            return status;
        }

        // finalizando o processo
        status = ZwTerminateProcess(processHandle, STATUS_ACCESS_DENIED);

        if (NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "Mitigation: Process PID %lu terminated successfully\n", HandleToULong(processId));

            // espera pelo término do processo
            LARGE_INTEGER timeout;
			timeout.QuadPart = 7500000; // 750ms em unidades de 100 nanossegundos

            status = ZwWaitForSingleObject(processHandle, FALSE, &timeout);
            if (!NT_SUCCESS(status)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "Mitigation: Timeout waiting for process PID %lu to terminate (0x%X)\n",
                    HandleToULong(processId), status);
            }
        }
        else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "Mitigation: Failed to terminate process PID %lu (0x%X)\n", HandleToULong(processId), status);
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "Mitigation: Exception 0x%X while terminating process PID %lu\n", status, HandleToULong(processId));
    }
    if (processHandle) {
        ZwClose(processHandle);
    }

    return status;
}