#ifndef MITIGATION_H
#define MITIGATION_H

#pragma once
#include <fltKernel.h>

// funcao para bloquear uma operacao de E/S potencialmente maliciosa
VOID
BlockSuspiciousOperation(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ NTSTATUS statusToSet
);

// backup de arquivos antes de modificações suspeitas
NTSTATUS
BackupFile(
    _In_ PFILE_OBJECT fileObject,
    _In_ PUNICODE_STRING originalFileName,
    _In_ PFLT_INSTANCE initialInstance
);

NTSTATUS
DeleteBackupFile(
    _In_ PUNICODE_STRING FileName
);

// finaliza o processo malicioso
NTSTATUS
KillMaliciousProcess(
    _In_ PEPROCESS process
);

BOOLEAN
IsSystemProcess(
    _In_ PEPROCESS process
);

#endif // !MITIGATION_H

