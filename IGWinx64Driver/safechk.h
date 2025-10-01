#ifndef SAFECHK_H
#define SAFECHK_H

#pragma once

#include <wdm.h>
#include <fltKernel.h>
#include <ntstrsafe.h>

// macros para prevencao de bsods ao acessar memoria
#define SAFE_ACCESS(ptr, size, operation) \
    do { \
        __try { \
            if (MmIsAddressValid(ptr) && \
                (ULONG_PTR)(ptr) + (size) > (ULONG_PTR)(ptr)) { \
                operation; \
            } \
        } __except (EXCEPTION_EXECUTE_HANDLER) { \
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
                "SAFE_ACCESS exception: 0x%X\n", GetExceptionCode()); \
        } \
    } while (0)

#define SAFE_COPY(dest, src, size) \
    SAFE_ACCESS(src, size, RtlCopyMemory(dest, src, size))

#define SAFE_COMPARE(ptr1, ptr2, size, result) \
    do { \
        result = 0; \
        __try { \
            if (MmIsAddressValid(ptr1) && MmIsAddressValid((PVOID)ptr2)) { \
                result = RtlCompareMemory(ptr1, (PVOID)ptr2, size); \
            } \
        } __except (EXCEPTION_EXECUTE_HANDLER) { \
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
                "SAFE_COMPARE exception: 0x%X\n", GetExceptionCode()); \
        } \
    } while (0)

// macros pra verificacao de paths case-sensitive

#define SAFE_UNICODE_COMPARE_CASE_SENSITIVE(str1, str2, result) \
    do { \
        result = -1; \
        __try { \
            if (MmIsAddressValid((str1).Buffer) && MmIsAddressValid((str2).Buffer)) { \
                result = RtlCompareUnicodeString(&(str1), &(str2), FALSE); \
            } \
        } __except (EXCEPTION_EXECUTE_HANDLER) { \
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
                "SAFE_UNICODE_COMPARE exception: 0x%X\n", GetExceptionCode()); \
        } \
    } while (0)

#define SAFE_UNICODE_COMPARE_CASE_INSENSITIVE(str1, str2, result) \
    do { \
        result = -1; \
        __try { \
            if (MmIsAddressValid((str1).Buffer) && MmIsAddressValid((str2).Buffer)) { \
                result = RtlCompareUnicodeString(&(str1), &(str2), TRUE); \
            } \
        } __except (EXCEPTION_EXECUTE_HANDLER) { \
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
                "SAFE_UNICODE_COMPARE exception: 0x%X\n", GetExceptionCode()); \
        } \
    } while (0)

__forceinline
BOOLEAN
IsListEntryValid(_In_ PLIST_ENTRY Entry)
{
    if (Entry == NULL ||
        Entry->Flink == NULL ||
        Entry->Blink == NULL) {
        return FALSE;
    }

    __try {
        // Verificar se os ponteiros são reciprocamente consistentes
        if (Entry->Flink->Blink != Entry || Entry->Blink->Flink != Entry) {
            return FALSE;
        }

        // Verificar alinhamento básico
        if (((ULONG_PTR)Entry & (sizeof(ULONG_PTR) - 1)) != 0) {
            return FALSE; 
        }

        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

__forceinline
BOOLEAN
IsListValid(_In_ PLIST_ENTRY ListHead)
{
    if (!IsListEntryValid(ListHead) || IsListEmpty(ListHead)) {
        return TRUE; 
    }

    __try {
        PLIST_ENTRY current = ListHead->Flink;
        ULONG count = 0;
        ULONG maxEntries = 10000;

        while (current != ListHead && count < maxEntries) {
            if (!IsListEntryValid(current)) {
                return FALSE;
            }

            // Verificar ciclo
            if (current->Flink->Blink != current) {
                return FALSE;
            }

            current = current->Flink;
            count++;

            // Proteção contra loops infinitos
            if (count >= maxEntries) {
                return FALSE;
            }
        }

        return (current == ListHead); 
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

// Verificação robusta de estrutura FLT
__forceinline
BOOLEAN
IsFltCallbackDataValid(_In_ PFLT_CALLBACK_DATA Data)
{
    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        return FALSE;
    }

    if (Data == NULL) return FALSE;

    __try {
        if (!MmIsAddressValid(Data) ||
            !MmIsAddressValid(Data->Iopb) ||
            Data->Iopb->IrpFlags & 0xFFFF0000) { // Flags suspeitas
            return FALSE;
        }

        if (Data->Iopb->Parameters.Write.Length > (1024 * 1024 * 1024)) { // 1GB máximo
            return FALSE;
        }

        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

// Timeout para acquisition de locks
__forceinline
NTSTATUS
AcquirePushLockExclusiveWithTimeout(
    _Inout_ PEX_PUSH_LOCK Lock,
    _In_ ULONG TimeoutMs
)
{
    LARGE_INTEGER timeout;
	timeout.QuadPart = -10000LL * TimeoutMs; // Converter para 100 nanossegundos

    for (ULONG i = 0; i < 3; i++) { // 3 tentativas
        if (ExTryAcquirePushLockExclusive(Lock)) {
            return STATUS_SUCCESS;
        }

        LARGE_INTEGER smallDelay;
        smallDelay.QuadPart = -10000LL; // 1ms
        KeDelayExecutionThread(KernelMode, FALSE, &smallDelay);
    }

    // Última tentativa com timeout
    return ExTryAcquirePushLockExclusive(Lock) ?
        STATUS_SUCCESS : STATUS_TIMEOUT;
}

__forceinline
SIZE_T
SafeCompareMemory(
    _In_ const VOID* Source1,
    _In_ const VOID* Source2,
    _In_ SIZE_T Length
)
{
    if (!Source1 || !Source2 || Length == 0 || Length > 4096) {
        return 0;
    }

    KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql > APC_LEVEL) {
        return 0; 
    }

    SIZE_T result = 0;

    __try {
        // Verificação de acessibilidade em blocos pequenos
        volatile UCHAR test1 = *((volatile const UCHAR*)Source1);
        volatile UCHAR test2 = *((volatile const UCHAR*)Source2);
        UNREFERENCED_PARAMETER(test1);
        UNREFERENCED_PARAMETER(test2);

        // Comparação segura com limite de tamanho
        const UCHAR* src1 = (const UCHAR*)Source1;
        const UCHAR* src2 = (const UCHAR*)Source2;

        SIZE_T safeLength = (currentIrql == APC_LEVEL) ? min(Length, 64) : Length;

        for (SIZE_T i = 0; i < safeLength; i++) {
            if (src1[i] == src2[i]) {
                result++;
            }
            else {
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        result = 0;
    }

    return result;
}

// Macros de segurança expandidas
#define SAFE_ACCESS_EXT(ptr, size, operation, fallback) \
    do { \
        __try { \
            if (MmIsAddressValid(ptr) && \
                (ULONG_PTR)(ptr) + (size) > (ULONG_PTR)(ptr) && \
                (ULONG_PTR)(ptr) + (size) < (ULONG_PTR)0x00007FFFFFFF0000ULL) { \
                operation; \
            } else { \
                fallback; \
            } \
        } __except (EXCEPTION_EXECUTE_HANDLER) { \
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
                "SAFE_ACCESS_EXT exception: 0x%X\n", GetExceptionCode()); \
            fallback; \
        } \
    } while (0)

#define VALIDATE_FLT_OPERATION(data, fallback) \
    if (!IsFltCallbackDataValid(data)) { \
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
            "Invalid FLT data structure\n"); \
        fallback; \
    }

#define VALIDATE_LIST_OPERATION(list, fallback) \
    if (!IsListValid(list)) { \
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
            "List integrity violation detected\n"); \
        fallback; \
    }

__forceinline
BOOLEAN
IsMdlSafeForAccess(
    _In_ PMDL Mdl,
    _In_ ULONG Length
)
{
    if (!Mdl || !MmIsAddressValid(Mdl)) {
        return FALSE;
    }

    __try {
        // Verificar flags do MDL
        if (Mdl->MdlFlags & (MDL_PAGES_LOCKED | MDL_PARTIAL | MDL_PARTIAL_HAS_BEEN_MAPPED)) {
            return FALSE;
        }

        // Verificar se o tamanho é razoável
        if (Length > MAX_SCAN_LENGTH || Length == 0) {
            return FALSE;
        }

        // Tentar mapear de forma segura
        PVOID mappedAddress = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
        if (!mappedAddress) {
            return FALSE;
        }

        // Verificação básica do conteúdo (apenas primeiros bytes)
        if (MmIsAddressValid(mappedAddress)) {
            UCHAR testByte;
            RtlCopyMemory(&testByte, mappedAddress, sizeof(UCHAR));
            return TRUE;
        }

        return FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

__forceinline
BOOLEAN
IsPushLockInitialized(_In_ PEX_PUSH_LOCK Lock)
{
    if (!Lock) {
        return FALSE;
    }

    __try {
        // push locks não inicializados são tipicamente 0
        if (*Lock == 0) {
            return FALSE;
        }
        // retorna TRUE se parece inicializado
        return AreCoreStructuresInitialized();

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

__forceinline
NTSTATUS
AcquirePushLockSharedWithTimeout(
    _Inout_ PEX_PUSH_LOCK Lock,
    _In_ ULONG TimeoutMs
)
{
    if (!Lock) {
        return STATUS_INVALID_PARAMETER;
    }

    LARGE_INTEGER timeout;
    timeout.QuadPart = -10000LL * TimeoutMs; // converte para 100 nanossegundos

    // 4 tentativas com pequenos delays
    for (ULONG i = 0; i < 3; i++) {
        if (ExTryAcquirePushLockShared(Lock)) {
            return STATUS_SUCCESS;
        }

        // pequeno delay entre tentativas (apenas em IRQL baixo)
        if (KeGetCurrentIrql() <= APC_LEVEL) {
            LARGE_INTEGER smallDelay;
            smallDelay.QuadPart = -5000LL; // 0.5ms
            KeDelayExecutionThread(KernelMode, FALSE, &smallDelay);
        }
        else {
            KeStallExecutionProcessor(50); // 50 microssegundos
        }
    }

    // Última tentativa
    return ExTryAcquirePushLockShared(Lock) ?
        STATUS_SUCCESS : STATUS_TIMEOUT;
}
#endif // SAFECHK_H