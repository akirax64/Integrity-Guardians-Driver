#ifndef MITIGATION_H
#define MITIGATION_H

#include <fltKernel.h>

// funcao para bloquear uma operacao de E/S potencialmente maliciosa
VOID
BlockSuspiciousOperation(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ NTSTATUS statusToSet
);

// backup de arquivos antes de modifica��es suspeitas
NTSTATUS
BackupFile(
    _In_ PFILE_OBJECT fileObject,
    _In_ PUNICODE_STRING originalFileName,
    _In_ PFLT_INSTANCE initialInstance
);

// finaliza o processo malicioso
NTSTATUS
KillMaliciousProcess(
    _In_ PEPROCESS process
);

// Adicione aqui outros prot�tipos de fun��es de mitiga��o conforme necess�rio, por exemplo:
// NTSTATUS ArQuarantineFile(_In_ PFILE_OBJECT FileObject); // Para mover um arquivo para quarentena
// NTSTATUS ArRollback

#endif // !MITIGATION_H

