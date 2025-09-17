#include "devicectrl.h"
#include "globals.h" 
#include "antirnsm.h"       
#include "rules.h" 
#include "cport.h"      

UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
UNICODE_STRING g_DosDeviceName = RTL_CONSTANT_STRING(DOS_DEVICE_NAME);
// Inicializa o objeto de dispositivo e o link simbólico para comunicação com o user-mode.
NTSTATUS
InitializeDeviceControl(
	_In_ PDRIVER_OBJECT driverObject
)
{
	NTSTATUS status;

	PAGED_CODE();

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "IGAR: Initializing Device Control...\n");

	// Criando o objeto de dispositivo.
	status = IoCreateDevice(
		driverObject,
		0,
		&g_DeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&g_DeviceObject
	);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Failed to create device object (0x%X)\n", status);
		return status;
	}

	// Configura os handlers para os IRPs de controle do dispositivo.
	// IRP_MJ_CREATE e IRP_MJ_CLOSE são direcionados para DeviceControl para gerenciar handles do dispositivo.
	driverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
	driverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceClose;
	driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;

	// Criando o link simbólico (DosDeviceName) para que o user-mode possa acessá-lo.
	status = IoCreateSymbolicLink(&g_DosDeviceName, &g_DeviceName);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Failed to create symbolic link (0x%X)\n", status);
		// Em caso de falha, limpa o objeto de dispositivo já criado.
		IoDeleteDevice(g_DeviceObject);
		g_DeviceObject = NULL;
		return status;
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Device Control initialized successfully.\n");
	return STATUS_SUCCESS;
}

// limpeza do controle de dispositivo
VOID
CleanDeviceControl(VOID)
{
	PAGED_CODE();

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Cleaning up Device Control...\n");

	IoDeleteSymbolicLink(&g_DosDeviceName);

	if (g_DeviceObject) {
		IoDeleteDevice(g_DeviceObject);
		g_DeviceObject = NULL;
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Device Control cleaned up.\n");
}

// controle de dispositivo por meio de IOCTLs

NTSTATUS
DeviceCreate(
	_In_ PDEVICE_OBJECT deviceObject,
	_Inout_ PIRP irp
)
{
	UNREFERENCED_PARAMETER(deviceObject);

	// DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,"Integrity Guardians AntiRansomware: DeviceCreate called.\n");

	// Completa a requisição com sucesso.
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS
DeviceClose(
	_In_ PDEVICE_OBJECT deviceObject,
	_Inout_ PIRP irp
)
{
	UNREFERENCED_PARAMETER(deviceObject);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: DeviceClose called.\n");

	// Completa a requisição com sucesso.
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS
DeviceControl(
	_In_ PDEVICE_OBJECT deviceObject,
	_Inout_ PIRP irp
)
{
	UNREFERENCED_PARAMETER(deviceObject);

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpStack;
	ULONG ioControlCode;
	PVOID inputBuffer;
	ULONG inputBufferLength;
	PVOID outputBuffer;
	ULONG outputBufferLength;
	ULONG_PTR bytesInfo = 0;

	PAGED_CODE(); // funcao roda em PASSIVE_LEVEL
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "IGAR: DeviceControl called.\n");

	irpStack = IoGetCurrentIrpStackLocation(irp);

	// determina o IOCTL recebido
	ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

	// criacao de buffers de I/O para propriedade METHOD_BUFFERED
	inputBuffer = irp->AssociatedIrp.SystemBuffer;
	inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	outputBuffer = irp->AssociatedIrp.SystemBuffer;
	outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: DeviceControl - IOCTL 0x%X received\n", ioControlCode);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Expected IOCTL_CONFIGURE_MONITORING: 0x%X\n", IOCTL_CONFIGURE_MONITORING);

	switch (ioControlCode)
	{
	case IOCTL_LOAD_RULES:
		// Recebe o IOCTL para carregar regras de política do user-mode
		if (inputBuffer && inputBufferLength > 0) {
			status = LoadRules(inputBuffer, inputBufferLength);
			bytesInfo = (ULONG_PTR)inputBufferLength;
		}
		else {
			status = STATUS_INVALID_PARAMETER;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: IOCTL_LOAD_RULES - Invalid input buffer.\n");
		}
		break;
	case IOCTL_GET_ALERT:
		// processa o IOCTL para obter alertas do driver
		if (outputBuffer && outputBufferLength >= sizeof(ALERT_DATA)) {
			//status = GetAlert(outputBuffer, outputBufferLength, (PULONG)&bytesInfo); //implmentar a função GetAlert
		}
		else {
			status = STATUS_INVALID_PARAMETER;
			bytesInfo = 0;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: IOCTL_GET_ALERT - Invalid output buffer (length %lu).\n", outputBufferLength);
		}
		break;

	case IOCTL_CONFIGURE_MONITORING:
		if (inputBuffer && inputBufferLength >= sizeof(MONITORING_CONFIG)) {
			PTR_MONITORING_CONFIG config = (PTR_MONITORING_CONFIG)inputBuffer;
			g_driverContext.MonitoringEnabled = config->EnableMonitoring;
			g_driverContext.DetectionMode = config->Mode;
			g_driverContext.BackupOnDetection = config->BackupOnDetection;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Monitoring set to %s, Mode: %lu, Backup: %s\n",
				config->EnableMonitoring ? "ENABLED" : "DISABLED",
				config->Mode,
				config->BackupOnDetection ? "TRUE" : "FALSE");
			status = STATUS_SUCCESS;
		}
		else {
			status = STATUS_INVALID_PARAMETER;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: IOCTL_CONFIGURE_MONITORING - Invalid input buffer.\n");
		}
		break;

	case IOCTL_STATUS:
		// Retorna o status atual do driver usando a estrutura MONITORING_CONFIG.
		if (outputBuffer && outputBufferLength >= sizeof(MONITORING_CONFIG)) {
			PTR_MONITORING_CONFIG driverStatus = (PTR_MONITORING_CONFIG)outputBuffer;

			// Copia as informações da g_driverContext para o buffer de saída
			driverStatus->EnableMonitoring = g_driverContext.MonitoringEnabled;
			driverStatus->Mode = g_driverContext.DetectionMode;
			driverStatus->BackupOnDetection = g_driverContext.BackupOnDetection;

			bytesInfo = sizeof(MONITORING_CONFIG);
			status = STATUS_SUCCESS;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: IOCTL_STATUS - Retornando status do driver.\n");
		}
		else {
			status = STATUS_INVALID_PARAMETER;
			bytesInfo = 0;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: IOCTL_STATUS - Buffer de saída inválido (tamanho %lu).\n", outputBufferLength);
		}
		break;

		// Handlers para IRPs de CREATE e CLOSE (se o user-mode abrir/fechar o handle do dispositivo).
	case IRP_MJ_CREATE:
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: IRP_MJ_CREATE received by DeviceControl.\n");
		status = STATUS_SUCCESS; // Permite a criação do handle do dispositivo
		break;

	case IRP_MJ_CLOSE:
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: IRP_MJ_CLOSE received by DeviceControl.\n");
		status = STATUS_SUCCESS; // Permite o fechamento do handle do dispositivo
		break;

	default:
		// IOCTL desconhecido.
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: Unknown IOCTL 0x%X\n", ioControlCode);
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	// completar as informações do IRP
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = bytesInfo;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Integrity Guardians AntiRansomware: DeviceControl completed with status 0x%X\n", status);
	return status;
}
