#include "precompiled.h"

UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
UNICODE_STRING g_DosDeviceName = RTL_CONSTANT_STRING(DOS_DEVICE_NAME);

NTSTATUS
InitializeDeviceControl(
	_In_ PDRIVER_OBJECT driverObject
)
{
	NTSTATUS status;

	KIRQL currentIrql = KeGetCurrentIrql();
	if (currentIrql > PASSIVE_LEVEL) {
		return STATUS_INVALID_DEVICE_STATE;
	}

	PAGED_CODE();

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "IGAR: Initializing Device Control...\n");

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
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"IGAR: Failed to create device object (0x%X)\n", status);
		return status;
	}

	driverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
	driverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceClose;
	driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;

	status = IoCreateSymbolicLink(&g_DosDeviceName, &g_DeviceName);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"IGAR: Failed to create symbolic link (0x%X)\n", status);
		IoDeleteDevice(g_DeviceObject);
		g_DeviceObject = NULL;
		return status;
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "IGAR: Device Control initialized successfully.\n");
	return STATUS_SUCCESS;
}

VOID
CleanDeviceControl(VOID)
{
	KIRQL currentIrql = KeGetCurrentIrql();
	if (currentIrql > PASSIVE_LEVEL) {
		return ; 
	}

	PAGED_CODE();

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "IGAR: Cleaning up Device Control...\n");

	IoDeleteSymbolicLink(&g_DosDeviceName);

	if (g_DeviceObject) {
		IoDeleteDevice(g_DeviceObject);
		g_DeviceObject = NULL;
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "IGAR: Device Control cleaned up.\n");
}

NTSTATUS
DeviceCreate(
	_In_ PDEVICE_OBJECT deviceObject,
	_Inout_ PIRP irp
)
{
	UNREFERENCED_PARAMETER(deviceObject);

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

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "IGAR: DeviceClose called.\n");

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

// Função auxiliar para validar buffer do user mode
__forceinline
BOOLEAN
ValidateUserBuffer(
	_In_ PVOID Buffer,
	_In_ ULONG BufferLength
)
{
	if (Buffer == NULL || BufferLength == 0) {
		return FALSE;
	}

	__try {
		// Teste simples de acesso de leitura
		volatile UCHAR testByte = *((volatile PUCHAR)Buffer);
		UNREFERENCED_PARAMETER(testByte);
		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"ValidateUserBuffer: Exception 0x%X\n", GetExceptionCode());
		return FALSE;
	}
}

NTSTATUS
DeviceControl(
	_In_ PDEVICE_OBJECT deviceObject,
	_Inout_ PIRP irp
)
{
	UNREFERENCED_PARAMETER(deviceObject);

	KIRQL currentIrql = KeGetCurrentIrql();
	if (currentIrql > PASSIVE_LEVEL) {
		return STATUS_INVALID_DEVICE_STATE; 
	}

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpStack;
	ULONG ioControlCode;
	PVOID inputBuffer;
	ULONG inputBufferLength;
	PVOID outputBuffer;
	ULONG outputBufferLength;
	ULONG_PTR bytesInfo = 0;

	PAGED_CODE();

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "IGAR: DeviceControl called.\n");

	irpStack = IoGetCurrentIrpStackLocation(irp);
	ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

	inputBuffer = irp->AssociatedIrp.SystemBuffer;
	inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	outputBuffer = irp->AssociatedIrp.SystemBuffer;
	outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "IGAR: IOCTL 0x%X, Input: %lu, Output: %lu\n",
		ioControlCode, inputBufferLength, outputBufferLength);

	switch (ioControlCode)
	{
	case IOCTL_LOAD_RULES:
	{
		if (!ValidateUserBuffer(inputBuffer, inputBufferLength) || inputBufferLength < sizeof(RULES_DATA_HEADER)) {
			status = STATUS_INVALID_PARAMETER;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IOCTL_LOAD_RULES: Invalid buffer\n");
			break;
		}

		__try {
			status = LoadRules(inputBuffer, inputBufferLength);
			if (NT_SUCCESS(status)) {
				bytesInfo = inputBufferLength;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
				"IOCTL_LOAD_RULES: Exception 0x%X\n", status);
		}
		break;
	}

	case IOCTL_GET_ALERT:
	{
		if (outputBufferLength < sizeof(ALERT_DATA)) {
			status = STATUS_BUFFER_TOO_SMALL;
			bytesInfo = sizeof(ALERT_DATA);
			break;
		}

		if (!ValidateUserBuffer(outputBuffer, outputBufferLength)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		status = GetAlert(outputBuffer, outputBufferLength, (PULONG)&bytesInfo);
		break;
	}

	case IOCTL_CONFIGURE_MONITORING:
	{
		if (!ValidateUserBuffer(inputBuffer, inputBufferLength) ||
			inputBufferLength < sizeof(MONITORING_CONFIG)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		__try {
			PTR_MONITORING_CONFIG config = (PTR_MONITORING_CONFIG)inputBuffer;

			// Validação adicional dos valores
			if (config->Mode > DetectionModeMonitorOnly) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			g_driverContext.MonitoringEnabled = config->EnableMonitoring;
			g_driverContext.DetectionMode = config->Mode;
			g_driverContext.BackupOnDetection = config->BackupOnDetection;

			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
				"IGAR: Monitoring config - Enabled: %u, Mode: %u, Backup: %u\n",
				config->EnableMonitoring, config->Mode, config->BackupOnDetection);

			status = STATUS_SUCCESS;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
				"IOCTL_CONFIGURE_MONITORING: Exception 0x%X\n", status);
		}
		break;
	}

	case IOCTL_STATUS:
	{
		if (!ValidateUserBuffer(outputBuffer, outputBufferLength)) {
			status = STATUS_INVALID_PARAMETER;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
				"IOCTL_STATUS: Buffer inválido\n");
			break;
		}

		if (outputBufferLength < sizeof(MONITORING_CONFIG)) {
			status = STATUS_BUFFER_TOO_SMALL;
			bytesInfo = sizeof(MONITORING_CONFIG); // Informa o tamanho necessário
			break;
		}


		__try {
			PTR_MONITORING_CONFIG driverStatus = (PTR_MONITORING_CONFIG)outputBuffer;

			driverStatus->EnableMonitoring = g_driverContext.MonitoringEnabled;
			driverStatus->Mode = g_driverContext.DetectionMode;
			driverStatus->BackupOnDetection = g_driverContext.BackupOnDetection;

			bytesInfo = sizeof(MONITORING_CONFIG);
			status = STATUS_SUCCESS;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
		}
		break;
	}

	case IOCTL_ADD_EXCLUDED_PATH:
	{
		if (!ValidateUserBuffer(inputBuffer, inputBufferLength) || inputBufferLength < sizeof(WCHAR)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		__try {
			PWSTR userString = (PWSTR)inputBuffer;
			ULONG maxChars = (inputBufferLength / sizeof(WCHAR)) - 1; // Excluir null terminator

			// Encontrar o comprimento real da string
			USHORT actualLength = 0;
			for (ULONG i = 0; i < maxChars; i++) {
				if (userString[i] == L'\0') {
					break;
				}
				actualLength += sizeof(WCHAR);
			}

			if (actualLength == 0) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			UNICODE_STRING userPath;
			userPath.Buffer = userString;
			userPath.Length = actualLength;
			userPath.MaximumLength = actualLength + sizeof(WCHAR);

			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
				"IOCTL_ADD_EXCLUDED_PATH: Received string: '%.*ws', Length: %u\n",
				(int)(actualLength / sizeof(WCHAR)), userString);

			status = AddExcludedPath(&userPath);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
		}
		break;
	}

	case IOCTL_REMOVE_EXCLUDED_PATH:
	{
		if (!ValidateUserBuffer(inputBuffer, inputBufferLength) ||
			inputBufferLength < sizeof(UNICODE_STRING)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		__try {
			PUNICODE_STRING userPath = (PUNICODE_STRING)inputBuffer;

			if (!ValidateUnicodeString(userPath, 4096)) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			status = RemoveExcludedPath(userPath);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
				"IOCTL_REMOVE_EXCLUDED_PATH: Exception 0x%X\n", status);
		}
		break;
	}

	case IOCTL_GET_EXCLUDED_PATHS:
	{
		if (!ValidateUserBuffer(outputBuffer, outputBufferLength)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		__try {
			if (outputBufferLength == sizeof(ULONG)) {
				PULONG count = (PULONG)outputBuffer;
				*count = GetExcludedPathsCount();
				bytesInfo = sizeof(ULONG);
				status = STATUS_SUCCESS;
			}
			else {
				status = SerializeExcludedPaths(outputBuffer, outputBufferLength, (PULONG)&bytesInfo);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
				"IOCTL_GET_EXCLUDED_PATHS: Exception 0x%X\n", status);
		}
		break;
	}

	case IOCTL_CLEAR_EXCLUDED_PATHS:
	{
		__try {
			status = ClearExcludedPaths();
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
				"IOCTL_CLEAR_EXCLUDED_PATHS: Exception 0x%X\n", status);
		}
		break;
	}

	default:
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "IGAR: Unknown IOCTL 0x%X\n", ioControlCode);
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = bytesInfo;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "IGAR: DeviceControl completed (0x%X)\n", status);
	return status;
}