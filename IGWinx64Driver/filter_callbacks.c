#include "precompiled.h"

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, InPreCreate, InPostCreate },
    { IRP_MJ_WRITE, 0, InPreWrite, InPostWrite },
    { IRP_MJ_OPERATION_END }
};

// inicializacao do filter manager 
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

    // registro do mini-filter
    status = FltRegisterFilter(driverObject, fltRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // vai inicializar o mini-filter driver
    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        return status;
    }

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

    // vai desregistrar o mini-filter driver
    if (g_FilterHandle) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }
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

    CleanFilter();
    CleanCommunicationPort();
    CleanDeviceControl();
    FreeRulesList();
    ClearExcludedPaths();

    return STATUS_SUCCESS;
}

// funcoes em caso de subir IRQL
FLT_PREOP_CALLBACK_STATUS
ProcessWriteDispatchLevel(
    _Inout_ PFLT_CALLBACK_DATA data
)
{
    if (KeGetCurrentIrql() != DISPATCH_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!data || !data->Iopb) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PMDL mdl = data->Iopb->Parameters.Write.MdlAddress;
    if (!mdl) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!(mdl->MdlFlags & MDL_PAGES_LOCKED)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PVOID writeBuffer = MmGetSystemAddressForMdlSafe(mdl, HighPagePriority);
    if (!writeBuffer) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ULONG scanLength = min(data->Iopb->Parameters.Write.Length, 32);

    if (DispatchLevelFastCheck(writeBuffer, scanLength)) {
        data->IoStatus.Status = STATUS_ACCESS_DENIED;
        data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
ProcessWriteApcLevel(
    _Inout_ PFLT_CALLBACK_DATA data
)
{
    if (KeGetCurrentIrql() != APC_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!g_driverContext.MonitoringEnabled) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    __try {
        if (QuickPatternCheck(data)) {
            BlockSuspiciousOperation(data, STATUS_ACCESS_DENIED);
            return FLT_PREOP_COMPLETE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Silenciar excecoes
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

// pre criacao de arquivos
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

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
        "InPreCreate: IRQL=%d, Monitoring=%d\n",
        currentIrql, g_driverContext.MonitoringEnabled);

    // Em DISPATCH_LEVEL ou superior, usar verificação ultra-rápida
    if (currentIrql > APC_LEVEL) {
        __try {
            if (!data || !data->Iopb || !data->Iopb->TargetFileObject) {
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }

            PUNICODE_STRING fileName = &data->Iopb->TargetFileObject->FileName;

            if (SafeExtensionCheckDispatchLevel(fileName)) {
                BlockSuspiciousOperation(data, STATUS_ACCESS_DENIED);
                return FLT_PREOP_COMPLETE;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (currentIrql == PASSIVE_LEVEL) {
        PAGED_CODE();
    }

    __try {
        if (!data || !data->Iopb || !data->Iopb->TargetFileObject) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        PUNICODE_STRING fileName = &data->Iopb->TargetFileObject->FileName;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "InPreCreate: Checking %wZ at IRQL %d\n", fileName, currentIrql);

        BOOLEAN isSuspicious = FALSE;

        if (currentIrql == PASSIVE_LEVEL) {
            // VERIFICAÇÃO COMPLETA: lista estática + regras dinâmicas
            isSuspicious = FullExtensionCheck(fileName);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "FullExtensionCheck result: %d for %wZ\n", isSuspicious, fileName);
        }
        else {
            // APC_LEVEL: verificação rápida apenas
            isSuspicious = QuickExtensionCheck(fileName);
        }

        if (isSuspicious) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "ALERT: Suspicious file creation BLOCKED: %wZ\n", fileName);

            // Enviar alerta para user-mode
            UNICODE_STRING alertMsg = RTL_CONSTANT_STRING(L"Blocked suspicious extension");
            AlertToUserMode(
                fileName,
                PsGetCurrentProcessId(),
                PsGetCurrentThreadId(),
                RULE_FLAG_MATCH,
                &alertMsg
            );

            BlockSuspiciousOperation(data, STATUS_ACCESS_DENIED);
            return FLT_PREOP_COMPLETE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "InPreCreate: Exception 0x%X\n", GetExceptionCode());
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// funcao de pos-criacao de arquivos
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

    if (!g_driverContext.MonitoringEnabled) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// Funcao de pre-escrita de arquivos
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

    if (currentIrql == DISPATCH_LEVEL) {
        return ProcessWriteDispatchLevel(data);
    }
    else if (currentIrql == APC_LEVEL) {
        return ProcessWriteApcLevel(data);
    }
    else if (currentIrql == PASSIVE_LEVEL) {
        PAGED_CODE();
        return ProcessWritePassiveLevel(data, f_Objects);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
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

    if (!IsFltCallbackDataValid(data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PUNICODE_STRING fileName = &data->Iopb->TargetFileObject->FileName;

    // Verificar extensao suspeita
    if (IsSuspiciousExtension(fileName)) {
        BlockSuspiciousOperation(data, STATUS_ACCESS_DENIED);
        return FLT_PREOP_COMPLETE;
    }

    // Verificar se esta excluÌdo
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
        // Backup se configurado
        if (g_driverContext.BackupOnDetection) {
            NTSTATUS backupStatus = BackupFile(data->Iopb->TargetFileObject, fileName, f_Objects->Instance);
            if (!NT_SUCCESS(backupStatus)) {

            }
        }

        BlockSuspiciousOperation(data, STATUS_ACCESS_DENIED);
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// funcao de pos-escrita de arquivos
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

    if (!g_driverContext.MonitoringEnabled) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// funcoes para gerenciar instancias do mini-filter
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

    return STATUS_SUCCESS;
}

// funcao de consulta de desmontagem de instancia
NTSTATUS FLTAPI
InstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS flags
)
{
    UNREFERENCED_PARAMETER(fltObjects);
    UNREFERENCED_PARAMETER(flags);

    return STATUS_SUCCESS;
}

// inicializacao da consulta de desmontagem de instancia
VOID FLTAPI
InstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS f_Objects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS flags
)
{
    UNREFERENCED_PARAMETER(f_Objects);
    UNREFERENCED_PARAMETER(flags);
}

// finalizacao da consulta de desmontagem de instancia
VOID FLTAPI
InstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS f_Objects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS flags
)
{
    UNREFERENCED_PARAMETER(f_Objects);
    UNREFERENCED_PARAMETER(flags);
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

    switch (CurrentIrql) {
    case PASSIVE_LEVEL:
        return TRUE;
    case APC_LEVEL:
        if (Data->Iopb->Parameters.Write.Length > 8192) {
            return FALSE;
        }
        return TRUE;
    case DISPATCH_LEVEL:
    default:
        return FALSE;
    }
}