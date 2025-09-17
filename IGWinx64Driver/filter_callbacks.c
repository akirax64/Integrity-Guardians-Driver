#include "antirnsm.h"
#include "fltcallbacks.h"
#include "detection.h"
#include "globals.h"
#include "mitigation.h"

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, InPreCreate, InPostCreate },
    { IRP_MJ_WRITE, 0, InPreWrite, InPostWrite },
    { IRP_MJ_OPERATION_END }
};

// inicialização do filter manager 
NTSTATUS
InitializeFilter(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ CONST FLT_REGISTRATION* fltRegistration
)
{
    NTSTATUS status;

	PAGED_CODE();

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: Initializing filter driver\n");

    // registro do mini-filter
    status = FltRegisterFilter(driverObject, fltRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians Antiransomware: Failed to register filter (0x%X)\n", status);
        return status;
    }

    // vai inicializar o mini-filter driver
    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: Failed to start filtering (0x%X)\n", status);
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: Filter Manager initialized successfully!\n");
    return STATUS_SUCCESS;
}

// limpeza do filter manager
VOID
CleanFilter(VOID)
{
    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: Cleaning up Filter Manager...\n");

    // vai desregistrar o mini-filter driver
    if (g_FilterHandle) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: Filter Manager cleaned up.\n");
}

NTSTATUS FLTAPI
FilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS flags
)
{
    UNREFERENCED_PARAMETER(flags); // Evita avisos de parâmetro não utilizado
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: Stub function FilterUnload called.");
    
	CleanFilter(); // Limpa o filter manager
	return STATUS_SUCCESS;    
}

// funcao de pré-criação de arquivos
FLT_PREOP_CALLBACK_STATUS
InPreCreate(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS f_Objects,
    _Flt_CompletionContext_Outptr_ PVOID* context
)
{
    UNREFERENCED_PARAMETER(f_Objects);
    UNREFERENCED_PARAMETER(context);

    if (!g_driverContext.MonitoringEnabled) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    __try {
        PUNICODE_STRING fileName = &data->Iopb->TargetFileObject->FileName;

        if (!MmIsAddressValid(fileName) || !MmIsAddressValid(fileName->Buffer)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "PreCreate - File: %wZ\n", fileName);

		// bloquear criação de arquivos com extensões suspeitas
        if (IsSuspiciousExtension(fileName)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "BLOCKING suspicious file creation: %wZ\n", fileName);

            BlockSuspiciousOperation(data, STATUS_ACCESS_DENIED);
            return FLT_PREOP_COMPLETE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "EXCEPTION in InPreCreate: 0x%X\n", GetExceptionCode());
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// função de pós-criação de arquivos
FLT_POSTOP_CALLBACK_STATUS
InPostCreate(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS f_Objects,
    _In_opt_ PVOID context,
    _In_ FLT_POST_OPERATION_FLAGS flags
)
{
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(f_Objects);
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(flags);

    //se o monitoramento não estiver habilitado, finaliza a operação
    if (!g_driverContext.MonitoringEnabled) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Lógica para verificar o resultado da criação, ou para limpar recursos
    return FLT_POSTOP_FINISHED_PROCESSING;

}

// Função de pré-escrita de arquivos
FLT_PREOP_CALLBACK_STATUS
InPreWrite(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS f_Objects,
    _Flt_CompletionContext_Outptr_ PVOID* context
)
{
    UNREFERENCED_PARAMETER(f_Objects);
    UNREFERENCED_PARAMETER(context);

	// verificar se o monitoramento está habilitado
    if (!g_driverContext.MonitoringEnabled || !g_driverContext.RulesListLock) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

	// vendo se está em um IRQL acima de APC_LEVEL, para retornar imediatamente (se for true)
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PFLT_IO_PARAMETER_BLOCK iopb = data->Iopb;
    PVOID writeBuffer = NULL;
    ULONG length = iopb->Parameters.Write.Length;
    PUNICODE_STRING fileName = NULL;

    __try {
        fileName = &data->Iopb->TargetFileObject->FileName;
        if (!MmIsAddressValid(fileName) || !MmIsAddressValid(fileName->Buffer)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "Invalid fileName address in InPreWrite\n");
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        if (length == 0) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        if (!iopb->Parameters.Write.MdlAddress) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        writeBuffer = MmGetSystemAddressForMdlSafe(iopb->Parameters.Write.MdlAddress, NormalPagePriority);
        if (writeBuffer == NULL) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        // 7. Verificar se o buffer é acessível
        if (!MmIsAddressValid(writeBuffer)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        ULONG scanLength = min(length, MAX_SCAN_LENGTH);

        BOOLEAN detected = FALSE;
        detected = ScanBuffer(writeBuffer, scanLength, fileName, IoGetCurrentProcess());

        if (detected) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "BLOCKING suspicious write to %wZ\n", fileName);

            // Fazer backup apenas se estivermos em IRQL PASSIVE
            if (KeGetCurrentIrql() == PASSIVE_LEVEL && g_driverContext.BackupOnDetection) {
                NTSTATUS backupStatus = BackupFile(data->Iopb->TargetFileObject, fileName, f_Objects->Instance);
                if (!NT_SUCCESS(backupStatus)) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                        "Backup failed for %wZ: 0x%X\n", fileName, backupStatus);
                }
            }

            BlockSuspiciousOperation(data, STATUS_ACCESS_DENIED);
            return FLT_PREOP_COMPLETE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "EXCEPTION in InPreWrite for file: 0x%p, Code: 0x%X\n",
            fileName, GetExceptionCode());
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// função de pós-escrita de arquivos
FLT_POSTOP_CALLBACK_STATUS
InPostWrite(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS f_Objects,
    _In_opt_ PVOID context,
    _In_ FLT_POST_OPERATION_FLAGS flags
)
{
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(f_Objects);
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(flags);

	// Se o monitoramento não estiver habilitado, finaliza a operação
    if (!g_driverContext.MonitoringEnabled) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// funçoes para gerenciar instâncias do mini-filter driver
NTSTATUS FLTAPI
InstanceConfig(
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS flags,
    _In_ DEVICE_TYPE volumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE volumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(fltObjects);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(volumeDeviceType);
    UNREFERENCED_PARAMETER(volumeFilesystemType);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: InstanceConfig - Attaching to volume\n");

	// criar logica para "quarentena" de volumes suspeitos ou não monitorados
    return STATUS_SUCCESS; // Permite anexar a instância ao volume
}

// função de consulta de desmontagem de instância
NTSTATUS FLTAPI
InstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS flags
)
{
    UNREFERENCED_PARAMETER(fltObjects);
    UNREFERENCED_PARAMETER(flags);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: InstanceQueryTeardown\n");

	// implementar lógica para verificar se a instância pode ser desmontada
	return STATUS_SUCCESS; // Permite a desmontagem se não houver problemas
}

// inicializacao da consulta de desmontagem de instância
VOID FLTAPI
InstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS f_Objects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS flags
)
{
    UNREFERENCED_PARAMETER(f_Objects);
    UNREFERENCED_PARAMETER(flags);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: InstanceTeardownStart\n");

	// implementar lógica para iniciar desmontagem de instância
}

// finalização da consulta de desmontagem de instância
VOID FLTAPI
InstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS f_Objects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS flags
)
{
    UNREFERENCED_PARAMETER(f_Objects);
    UNREFERENCED_PARAMETER(flags);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: InstanceTeardownComplete\n");

	// logica para finalizar desmontagem de instância
}