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
            if (MmIsAddressValid(ptr1) && MmIsAddressValid(ptr2)) { \
                result = RtlCompareMemory(ptr1, ptr2, size); \
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
#endif // SEC_CHECK_H
