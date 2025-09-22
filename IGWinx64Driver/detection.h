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

BOOLEAN
IsPathMonitored(
    _In_ PUNICODE_STRING pathName
);

// funcao para verificar extensao suspeita
BOOLEAN
IsSuspiciousExtension(
    _In_ PUNICODE_STRING fileName
);
#endif // !DETECTION_H