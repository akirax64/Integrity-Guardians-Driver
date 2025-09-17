#include "mitigation.h"
#include "globals.h" 
#include "enum.h"          
#include <ntstrsafe.h>      
#include <wdm.h>


// bloqueia uma operacao suspeita de I/O no filtro de arquivos
VOID
BlockSuspiciousOperation(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ NTSTATUS statusToSet
)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Mitigation: Blocking operation for file %wZ with status 0x%X\n",
        &data->Iopb->TargetFileObject->FileName, statusToSet);

    data->IoStatus.Status = statusToSet;       
    data->IoStatus.Information = 0;             
    FltSetCallbackDataDirty(data);              
}

NTSTATUS
BackupFile(
    _In_ PFILE_OBJECT fileObject,
    _In_ PUNICODE_STRING originalFileName,
    _In_ PFLT_INSTANCE initialInstance
)
{
    PAGED_CODE(); // esta função deve ser chamada em PASSIVE_LEVEL

    NTSTATUS        status;
    HANDLE          backupFileHandle = NULL;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatusBlock;
    LARGE_INTEGER   byteOffset;
    ULONG           currentChunkLength;
    ULONG           bytesActuallyRead;
    ULONG           bytesActuallyWritten;
    PVOID           buffer = NULL;
    ULONG           chunkSize = 65536; // Tamanho do chunk para leitura/escrita, 64KB como valor padrão
    UNICODE_STRING  backupFileName;
    WCHAR           backupFileNameBuffer[UNICODE_STRING_MAX_CHARS + 64];

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Mitigation: Attempting to backup file %wZ\n", originalFileName);

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
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 
        0,    
        0     
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Mitigation: Failed to create backup file %wZ (0x%X).\n", &backupFileName, status);
        return status;
    }

    buffer = ExAllocatePool2(POOL_FLAG_PAGED, chunkSize, TAG_BACKUP);
    if (!buffer) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Mitigation: Failed to allocate buffer for backup file.\n");
        FltClose(backupFileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Mitigation: Failed to get original file size (0x%X).\n", status);
        goto Cleanup;
    }
    ULONGLONG fileSize = fileInfo.EndOfFile.QuadPart;

    byteOffset.QuadPart = 0;
    while ((ULONGLONG)byteOffset.QuadPart < fileSize) {
        currentChunkLength = (ULONG)min((ULONGLONG)chunkSize, fileSize - byteOffset.QuadPart);

        // Ler do arquivo original
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
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Mitigation: Failed to read from original file (0x%X).\n", status);
            goto Cleanup;
        }

        // Escrever no arquivo de backup
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
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Mitigation: Failed to write to backup file (0x%X), or bytes mismatch.\n", status);
            goto Cleanup;
        }

        byteOffset.QuadPart += bytesActuallyRead; // Avança o offset pelo que foi REALMENTE lido
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Mitigation: File %wZ successfully backed up to %wZ.\n", originalFileName, &backupFileName);
    status = STATUS_SUCCESS;

Cleanup:
    if (buffer) {
        ExFreePoolWithTag(buffer, TAG_BACKUP);
    }
    if (backupFileHandle) {
        FltClose(backupFileHandle);
    }
    return status;
}


// termina um processo malicioso
// OBSERVACAO: implementar mais segurança e verificações antes de usar esta função
// alem de verificar a funcao futuramente, pois ela pode causar problemas se usada incorretamente
NTSTATUS
KillMaliciousProcess(
    _In_ PEPROCESS process
)
{
    PAGED_CODE(); 
    NTSTATUS status;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Mitigation: Killing malicious process with PID %lu.\n", HandleToULong(PsGetProcessId(process)));

    status = ZwTerminateProcess(process, STATUS_ACCESS_DENIED); // Usar STATUS_ACCESS_DENIED ou outro status apropriado

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Mitigation: Failed to kill process PID %lu (0x%X).\n", HandleToULong(PsGetProcessId(process)), status);
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Mitigation: Process PID %lu killed successfully.\n", HandleToULong(PsGetProcessId(process)));
    }

    return status;
}
