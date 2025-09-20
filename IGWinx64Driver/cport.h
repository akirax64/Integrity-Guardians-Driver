#ifndef COMMUNICATION_PORT_H
#define COMMUNICATION_PORT_H

#include "antirnsm.h"

#pragma once

// para inicializar a porta de comunicação
NTSTATUS
InitializeCommunicationPort(
    _In_ PFLT_FILTER FilterHandle,
    _In_ PUNICODE_STRING PortName
);

// limpa a porta de comunicação e libera os recursos alocados
VOID
CleanCommunicationPort(VOID);

// notificar que o usuario está conectado à porta de comunicação
NTSTATUS
ConnectionNotify(
    _In_ PFLT_PORT clientPort,
    _In_ PVOID serverPortCookie,
    _In_ PVOID connectionContext,
    _In_ ULONG size,
    _Out_ PVOID* connectionPortCookie
);

// notificar a desconexao da porta
VOID
DisconnectionNotify(
    _In_ PVOID connectionCookie
);

// notificar a mensagem recebida na porta de comunicação
NTSTATUS
MessageNotify(
    _In_ PVOID portCookie,
    _In_ PVOID inputBuffer,
    _In_ ULONG inputBufferLength,
    _Out_ PVOID outputBuffer,
    _In_ ULONG outputBufferLength,
    _Out_ PULONG returnOutputBufferLength
);

NTSTATUS
GetAlert(
    _Out_ PVOID outputBuffer,
    _In_ ULONG outputBufferLength,
    _Out_ PULONG bytesReturned
);

// enviar um alerta para o usuario sobre ameaça detectada
NTSTATUS
AlertToUserMode(
    _In_ PUNICODE_STRING fileName,
    _In_ HANDLE processId,
    _In_ HANDLE threadId,
    _In_ ULONG detectionType,
    _In_ PUNICODE_STRING ruleName
);
#endif // !COMMUNICATION_PORT_H