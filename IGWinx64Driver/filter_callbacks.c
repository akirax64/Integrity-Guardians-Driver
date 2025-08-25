#include "antirnsm.h"
#include "fltcallbacks.h"
#include "detection.h"
#include "globals.h"

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
    // Nenhum acesso a memória, nenhuma operação de E/S, nenhuma lógica complexa.
    // Apenas retorna.
	return STATUS_SUCCESS; // Indica que o filtro foi descarregado com sucesso    
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

	// nome do arquivo sendo criado
    PUNICODE_STRING fileName = &data->Iopb->TargetFileObject->FileName;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: PreCreate - File: %wZ\n", fileName);

	// implementar lógica de detecção de criação de arquivos suspeitos (detection.c)
    // if ( IsSuspiciousFileCreation(Data)) { ... }

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

	// se o monitoramento não estiver habilitado, finaliza a operação
    if (!g_driverContext.MonitoringEnabled) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

	// variáveis locais para armazenar informações sobre a operação de escrita
    PFLT_IO_PARAMETER_BLOCK iopb = data->Iopb;
    PVOID writeBuffer = NULL;
    ULONG length = iopb->Parameters.Write.Length;
    PUNICODE_STRING fileName = &data->Iopb->TargetFileObject->FileName;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: PreWrite - File: %wZ, Length: %lu\n",
        fileName, length);

	if (length == 0) { // se nao há dados para escrever, finaliza a operação
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

	// condicional para verificar se o MdlAddress é válido
	// prevenindo bug checks ao acessar um endereço nulo ou inválido
    if (!iopb->Parameters.Write.MdlAddress) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: MdlAddress is NULL or invalid. Skipping write buffer scan for %wZ.\n", fileName);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    writeBuffer = MmGetSystemAddressForMdlSafe(iopb->Parameters.Write.MdlAddress, HighPagePriority);
    if (writeBuffer == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Failed to get write buffer for %wZ\n", fileName);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

	return FLT_PREOP_SUCCESS_NO_CALLBACK; // Permite a operação se não for detectado
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