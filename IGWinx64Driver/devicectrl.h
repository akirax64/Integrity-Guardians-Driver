#ifndef DEVICE_CONTROL_H
#define DEVICE_CONTROL_H

#pragma once
#include "antirnsm.h"

NTSTATUS
InitializeDeviceControl(
	_In_ PDRIVER_OBJECT driverObject
);

VOID
CleanDeviceControl(VOID);

BOOLEAN
ValidateUserBuffer(
	_In_ PVOID Buffer,
	_In_ ULONG BufferLength
);

NTSTATUS
DeviceCreate(
	_In_ PDEVICE_OBJECT deviceObject,
	_Inout_ PIRP irp
);

NTSTATUS
DeviceClose(
	_In_ PDEVICE_OBJECT deviceObject,
	_Inout_ PIRP irp
);

NTSTATUS
DeviceControl(
	_In_ PDEVICE_OBJECT deviceObject,
	_Inout_ PIRP irp
);
#endif // !DEVICE_CONTROL_H