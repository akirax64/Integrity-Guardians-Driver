#ifndef WHITELIST_H
#define WHITELIST_H

#pragma once
#include <ntddk.h>
#include <wdm.h>

NTSTATUS
InitializeWhitelist(VOID);
BOOLEAN
IsPathExcluded(
    _In_ PUNICODE_STRING PathName
);
NTSTATUS 
AddExcludedPath(
    _In_ PUNICODE_STRING Path
);
NTSTATUS
ConvertUserPathToKernelPath(
    _In_ PUNICODE_STRING UserPath,
    _Out_ PUNICODE_STRING KernelPath
);
NTSTATUS RemoveExcludedPath(
    _In_ PUNICODE_STRING Path
);
NTSTATUS 
ClearExcludedPaths(VOID);
ULONG 
GetExcludedPathsCount(VOID);
NTSTATUS
GetExcludedPathsList(
    _Out_ PTR_EXCLUDED_PATHS_RESPONSE Response,
    _In_ ULONG ResponseBufferSize,
    _Out_ PULONG BytesReturned
);
NTSTATUS
SerializeExcludedPaths(
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
);
ULONG
CalculateExcludedPathsSize(VOID);
BOOLEAN
ValidateUnicodeString(
    _In_ PUNICODE_STRING UserModeString,
    _In_ ULONG MaxLength
);
NTSTATUS
CopyUnicodeStringFromUserMode(
    _In_ PUNICODE_STRING UserModeString,
    _Out_ PUNICODE_STRING KernelModeString
);

#endif // !WHITELIST_H
