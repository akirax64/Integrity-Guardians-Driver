#include "precompiled.h"

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, InPreCreate, InPostCreate },
    { IRP_MJ_WRITE, 0, InPreWrite, InPostWrite },
    { IRP_MJ_OPERATION_END }
};

// inicializa��o do filter manager 
NTSTATUS
InitializeFilter(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ CONST FLT_REGISTRATION* fltRegistration
)
{
    NTSTATUS status;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

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
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

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
    UNREFERENCED_PARAMETER(flags);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_SUCCESS;
    }

	PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "Integrity Guardians AntiRansomware: FilterUnload called. Flags: 0x%X\n", flags);

    CleanFilter();

    CleanCommunicationPort();

    CleanDeviceControl();

    FreeRulesList();

    ClearExcludedPaths();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "Integrity Guardians AntiRansomware: Filter unloaded successfully.\n");

    return STATUS_SUCCESS;
}

// funcoes em caso de subir IRQL
FLT_PREOP_CALLBACK_STATUS
ProcessWriteDispatchLevel(
    _Inout_ PFLT_CALLBACK_DATA data
)
{
    __try {
        PUNICODE_STRING fileName = &data->Iopb->TargetFileObject->FileName;

        // verificacao rapida de extensoes suspeitas, ja que o IRQL esta em DISPATCH_LEVEL
        if (fileName && fileName->Buffer && fileName->Length > 0) {
            // Buscar ponto final manualmente (sem wcsrchr)
            PWCHAR buffer = fileName->Buffer;
            USHORT length = fileName->Length / sizeof(WCHAR);
            PWCHAR lastDot = NULL;

            for (USHORT i = 0; i < length; i++) {
                if (buffer[i] == L'.') {
                    lastDot = &buffer[i];
                }
            }

            if (lastDot) {
                if ((lastDot[0] == L'.' && lastDot[1] == L'c' && lastDot[2] == L'r' && lastDot[3] == L'y' && lastDot[4] == L'p' && lastDot[5] == L't') ||
                    (lastDot[0] == L'.' && lastDot[1] == L'l' && lastDot[2] == L'o' && lastDot[3] == L'c' && lastDot[4] == L'k' && lastDot[5] == L'e' && lastDot[6] == L'd')) {
                    BlockSuspiciousOperation(data, STATUS_ACCESS_DENIED);
                    return FLT_PREOP_COMPLETE;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // silenciar exce��es em IRQL alto
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
ProcessWriteApcLevel(
    _Inout_ PFLT_CALLBACK_DATA data
)
{
    if (!g_driverContext.MonitoringEnabled) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    __try {
        if (QuickPatternCheckDispatchLevel(data)) {
            BlockSuspiciousOperation(data, STATUS_ACCESS_DENIED);
            return FLT_PREOP_COMPLETE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Silenciar exce��es
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
ProcessWritePassiveLevel(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS f_Objects
)
{
    PAGED_CODE();

    return ProcessWriteOperation(data, f_Objects);
}

// funcao de pr�-cria��o de arquivos
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

	KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql > PASSIVE_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

	PAGED_CODE();

    __try {
        PUNICODE_STRING fileName = &data->Iopb->TargetFileObject->FileName;

        if (!MmIsAddressValid(fileName) || !MmIsAddressValid(fileName->Buffer)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "PreCreate - File: %wZ\n", fileName);

		// bloquear cria��o de arquivos com extens�es suspeitas
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

// fun��o de p�s-cria��o de arquivos
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

    //se o monitoramento n�o estiver habilitado, finaliza a opera��o
    if (!g_driverContext.MonitoringEnabled) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // L�gica para verificar o resultado da cria��o, ou para limpar recursos
    return FLT_POSTOP_FINISHED_PROCESSING;

}

// Fun��o de pr�-escrita de arquivos
FLT_PREOP_CALLBACK_STATUS
InPreWrite(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS f_Objects,
    _Flt_CompletionContext_Outptr_ PVOID* context
)
{
    UNREFERENCED_PARAMETER(f_Objects);
    UNREFERENCED_PARAMETER(context);

    if (!data || !data->Iopb || !data->Iopb->TargetFileObject) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    KIRQL currentIrql = KeGetCurrentIrql();

    if (currentIrql == PASSIVE_LEVEL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "InPreWrite: IRQL=%d, Length=%lu\n", currentIrql, data->Iopb->Parameters.Write.Length);
    }

    if (currentIrql > APC_LEVEL) {
        return ProcessWriteDispatchLevel(data);
    }
    if (currentIrql == APC_LEVEL) {
        return ProcessWriteApcLevel(data);
    }

    PAGED_CODE();
    return ProcessWritePassiveLevel(data, f_Objects);
}

FLT_PREOP_CALLBACK_STATUS
ProcessWriteOperation(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS f_Objects
)
{
    PFLT_IO_PARAMETER_BLOCK iopb = data->Iopb;

    if (!g_driverContext.MonitoringEnabled) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Valida��es extensivas
    if (!IsFltCallbackDataValid(data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PUNICODE_STRING fileName = &data->Iopb->TargetFileObject->FileName;

    // Verificar extens�o suspeita
    if (IsSuspiciousExtension(fileName)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,DPFLTR_INFO_LEVEL, "Blocking suspicious file: %wZ\n", fileName);
        BlockSuspiciousOperation(data, STATUS_ACCESS_DENIED);
        return FLT_PREOP_COMPLETE;
    }

    // Verificar se est� exclu�do
    if (IsPathExcludedFromDetection(fileName)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Processar escrita completa
    PMDL mdl = iopb->Parameters.Write.MdlAddress;
    if (!mdl || !IsMdlSafeForAccess(mdl, iopb->Parameters.Write.Length)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PVOID writeBuffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    if (!writeBuffer) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ULONG scanLength = min(iopb->Parameters.Write.Length, 8192);

    if (ScanBuffer(writeBuffer, scanLength, fileName, IoGetCurrentProcess())) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Blocking malicious write to %wZ\n", fileName);

        // Backup se configurado
        if (g_driverContext.BackupOnDetection) {
            NTSTATUS backupStatus = BackupFile(data->Iopb->TargetFileObject, fileName, f_Objects->Instance);
            if (!NT_SUCCESS(backupStatus)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Backup failed: 0x%X\n", backupStatus);
            }
        }

        BlockSuspiciousOperation(data, STATUS_ACCESS_DENIED);
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// fun��o de p�s-escrita de arquivos
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

	// Se o monitoramento n�o estiver habilitado, finaliza a opera��o
    if (!g_driverContext.MonitoringEnabled) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// fun�oes para gerenciar inst�ncias do mini-filter driver
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

	// criar logica para "quarentena" de volumes suspeitos ou n�o monitorados
    return STATUS_SUCCESS; // Permite anexar a inst�ncia ao volume
}

// fun��o de consulta de desmontagem de inst�ncia
NTSTATUS FLTAPI
InstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS flags
)
{
    UNREFERENCED_PARAMETER(fltObjects);
    UNREFERENCED_PARAMETER(flags);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: InstanceQueryTeardown\n");

	// implementar l�gica para verificar se a inst�ncia pode ser desmontada
	return STATUS_SUCCESS; // Permite a desmontagem se n�o houver problemas
}

// inicializacao da consulta de desmontagem de inst�ncia
VOID FLTAPI
InstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS f_Objects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS flags
)
{
    UNREFERENCED_PARAMETER(f_Objects);
    UNREFERENCED_PARAMETER(flags);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: InstanceTeardownStart\n");

	// implementar l�gica para iniciar desmontagem de inst�ncia
}

// finaliza��o da consulta de desmontagem de inst�ncia
VOID FLTAPI
InstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS f_Objects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS flags
)
{
    UNREFERENCED_PARAMETER(f_Objects);
    UNREFERENCED_PARAMETER(flags);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: InstanceTeardownComplete\n");

	// logica para finalizar desmontagem de inst�ncia
}

__forceinline
BOOLEAN
IsWriteOperationSafe(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ KIRQL CurrentIrql
)
{
    if (!Data || !Data->Iopb) {
        return FALSE;
    }

    // CORRE��O: Limita��es extremamente conservadoras
    switch (CurrentIrql) {
    case PASSIVE_LEVEL:
        return TRUE; // Opera��es completas permitidas

    case APC_LEVEL:
        // Apenas verifica��es muito b�sicas
        if (Data->Iopb->Parameters.Write.Length > 8192) {
            return FALSE;
        }
        return TRUE;

    case DISPATCH_LEVEL:
    default:
        // Apenas verifica��o de extens�o de arquivo
        return TRUE;
    }
}
