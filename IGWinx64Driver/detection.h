#ifndef DETECTION_H
#define DETECTION_H

#pragma once
#include "antirnsm.h"
#include <fltKernel.h>

BOOLEAN
ScanBuffer(
	_In_ PVOID buffer,
	_In_ ULONG length,
	_In_ PUNICODE_STRING fileName,
	_In_opt_ PEPROCESS process
);

BOOLEAN
ScanFileContent(
	_In_ PFILE_OBJECT fileObject,
	_In_ PFLT_INSTANCE initialInstance,
	_In_opt_ PEPROCESS process
);

// funcoes para exclusao e monitoramento de caminho
BOOLEAN
IsPathExcludedFromDetection(
	_In_ PUNICODE_STRING pathName
);

// funcao para verificar extensao suspeita
BOOLEAN
IsSuspiciousExtension(
	_In_ PUNICODE_STRING fileName
);

BOOLEAN
DetectEncryptionPatterns(
	_In_ PVOID buffer,
	_In_ ULONG length
);
BOOLEAN
IsIrqlSafeForOperation(
	_In_ KIRQL CurrentIrql,
	_In_ BOOLEAN RequirePassiveLevel
);
BOOLEAN
DispatchLevelFastCheck(_In_ PVOID Buffer, _In_ ULONG Length);
BOOLEAN
QuickPatternCheckDispatchLevel(
	_In_ PFLT_CALLBACK_DATA data
);
BOOLEAN
QuickExtensionCheck(_In_ PUNICODE_STRING fileName);
NTSTATUS
InitializeBehaviorDetection(VOID);
BOOLEAN
SafeExtensionCheckDispatchLevel(
	_In_ PUNICODE_STRING fileName
);
BOOLEAN
QuickCompareExtension(
	_In_ PWSTR Ext,
	_In_ const WCHAR* Pattern
);
BOOLEAN
DispatchLevelFastCheck(
	_In_ PVOID Buffer,
	_In_ ULONG Length);

ULONG
GetScanLimitForIrql(
	_In_ KIRQL CurrentIrql
);
PWSTR
FindLastDotManual(
	_In_ PWSTR Buffer,
	_In_ USHORT MaxLength
);
BOOLEAN
CompareExtensionsManual(
	_In_ PWSTR Ext1,
	_In_ const WCHAR* Ext2
);
BOOLEAN
FullExtensionCheck(
	_In_ PUNICODE_STRING fileName
);
BOOLEAN
CheckPatternsInBuffer(
	_In_ PVOID buffer,
	_In_ ULONG length,
	_In_ KIRQL currentIrql
);
BOOLEAN
QuickPatternCheck(
	_In_ PFLT_CALLBACK_DATA data
);
BOOLEAN
CheckDynamicExtensions(
	_In_ PUNICODE_STRING fileName
);
#endif // !DETECTION_H