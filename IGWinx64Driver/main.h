#ifndef MAIN_H
#define MAIN_H

#include <fltKernel.h>
#include <ntstrsafe.h>

#pragma once

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT d_Object, _In_ PUNICODE_STRING r_Path);
VOID DriverUnload(_In_ PDRIVER_OBJECT driverObject);
#endif // !MAIN_H

