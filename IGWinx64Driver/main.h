#ifndef MAIN_H
#define MAIN_H

#pragma once
#include <fltKernel.h>
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT d_Object, _In_ PUNICODE_STRING r_Path);
VOID DriverUnload(_In_ PDRIVER_OBJECT driverObject);
#endif // !MAIN_H

