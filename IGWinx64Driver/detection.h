#ifndef DETECTION_H
#define DETECTION_H

#include "antirnsm.h"
#include <fltKernel.h>

BOOLEAN ScanBuffer(_In_ PVOID buffer, _In_ ULONG length, _In_ PUNICODE_STRING fileName, _In_opt_ PEPROCESS process);
BOOLEAN ScanFileContent(_In_ PFILE_OBJECT fileObject, _In_opt_ PEPROCESS process);
NTSTATUS LoadRules(_In_ PTR_RULES_DATA rulesData, _In_ ULONG rulesDataLength);

#endif // !DETECTION_H


#pragma once
