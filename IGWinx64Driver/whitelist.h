#ifndef WHITELIST_H
#define WHITELIST_H

#pragma once
#include <ntddk.h>
#include <wdm.h>

NTSTATUS InitializeWhitelist(VOID);
BOOLEAN IsPathExcluded(_In_ PUNICODE_STRING PathName);
NTSTATUS AddExcludedPath(_In_ PUNICODE_STRING Path);
NTSTATUS RemoveExcludedPath(_In_ PUNICODE_STRING Path);
NTSTATUS ClearExcludedPaths(VOID);
ULONG GetExcludedPathsCount(VOID);
#endif // !WHITELIST_H
