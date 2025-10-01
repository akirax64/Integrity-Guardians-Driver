#ifndef BEHAVIORDET_H
#define BEHAVIORDET_H
#pragma once

#include <fltKernel.h>
#include "antirnsm.h"

NTSTATUS
InitializeBehaviorDetection(VOID);
BOOLEAN 
IsBehaviorDetectionInitialized(VOID);
NTSTATUS
GetBehaviorDetectionStats(
    _Out_ PULONG ActiveTrackers,
    _Out_ PULONG TotalNamesLoaded
);
VOID
CleanupBehaviorDetection(VOID);
BOOLEAN DetectRansomwareBehavior(
    _In_ HANDLE ProcessId,
    _In_ PEPROCESS Process,
    _In_ PUNICODE_STRING FileName,
    _In_ PVOID WriteBuffer,
    _In_ ULONG WriteLength,
    _In_ BOOLEAN IsFileRename,
    _In_ BOOLEAN IsFileDelete
);
BOOLEAN 
IsKnownRansomwareProcess(
    _In_ PTR_BEHAVIOR_TRACKER Tracker
);
ULONG
CalculateEntropy(
    _In_ ULONG Length,
    _In_reads_bytes_(Length) PVOID Buffer
);
BOOLEAN 
IsLikelyEncrypted(
    _In_ ULONG Length,
    _In_reads_bytes_(Length) PVOID Buffer
);
BOOLEAN
IsSuspiciousExtensionChange(
    _In_ PUNICODE_STRING OldFileName,
    _In_ PUNICODE_STRING NewFileName
);

PTR_BEHAVIOR_TRACKER 
GetOrCreateBehaviorTracker(
    _In_ HANDLE ProcessId,
    _In_ PEPROCESS Process
);
VOID
UpdateRiskScore(
    _In_ PTR_BEHAVIOR_TRACKER Tracker,
    _In_ ULONG ScoreIncrement,
    _In_ PCSTR Reason
);
VOID 
GenerateBehaviorAlert(
    _In_ PTR_BEHAVIOR_TRACKER Tracker,
    _In_ PUNICODE_STRING FileName, 
    _In_ PCSTR AlertReason
);
VOID
TerminateMaliciousProcess(
    _In_ PTR_BEHAVIOR_TRACKER Tracker
);
VOID
CleanupOldTrackers(VOID);
#endif