#ifndef MAIN_H
#define MAIN_H

#include <fltKernel.h>
#include <ntstrsafe.h>

#pragma once

// prototipos

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT d_Object, _In_ PUNICODE_STRING r_Path);
NTSTATUS Unload(_In_ FLT_FILTER_UNLOAD_FLAGS flags);
NTSTATUS DeviceControl(_In_ PDEVICE_OBJECT deviceObject, _Inout_ PIRP irp);
NTSTATUS ConnectionNotifyCallback(_In_ PFLT_PORT clientPort, _In_ PVOID serverPortCookie, _In_ PVOID connectionContext, _In_ ULONG size, _Out_ PVOID* connectionPortCookie);
VOID DisconnectionNotifyCallback(_In_ PVOID connectionCookie);
NTSTATUS MessageNotifyCallback(_In_ PVOID portCookie, _In_ PVOID inputBuffer, _In_ ULONG inputBufferLength, _Out_ PVOID outputBuffer, _In_ ULONG outputBufferLength, _Out_ PULONG returnOutputBufferLength);

#endif // !MAIN_H

