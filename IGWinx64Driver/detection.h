#ifndef DETECTION_H
#define DETECTION_H

#include "antirnsm.h"
#include <fltKernel.h>

#pragma once

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
IsPathExcluded(
    _In_ PUNICODE_STRING pathName
);

BOOLEAN
IsPathMonitored(
    _In_ PUNICODE_STRING pathName
);

#endif // !DETECTION_H