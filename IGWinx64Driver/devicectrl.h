#ifndef DEVICE_CONTROL_H
#define DEVICE_CONTROL_H

#include "antirnsm.h"
#include <fltKernel.h>

#pragma once

NTSTATUS
InitializeDeviceControl(
	_In_ PDRIVER_OBJECT driverObject
);

VOID
CleanDeviceControl(VOID);

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