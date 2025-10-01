#include "precompiled.h"

UNICODE_STRING g_CryptoRuleName = RTL_CONSTANT_STRING(ALGORITHM_PATTERN);

__forceinline
BOOLEAN
IsIrqlSafeForOperation(
	_In_ KIRQL CurrentIrql,
	_In_ BOOLEAN RequirePassiveLevel
)
{
	if (RequirePassiveLevel) {
		return (CurrentIrql == PASSIVE_LEVEL);
	}
	return (CurrentIrql <= APC_LEVEL);
}

__forceinline
ULONG
GetScanLimitForIrql(
	_In_ KIRQL CurrentIrql
)
{
	switch (CurrentIrql) {
	case PASSIVE_LEVEL:
		return 8192;
	case APC_LEVEL:
		return 128;
	default:
		return 0;
	}
}

BOOLEAN
IsPathExcludedFromDetection(_In_ PUNICODE_STRING PathName)
{
	if (!PathName || !PathName->Buffer || PathName->Length == 0) {
		return FALSE;
	}

	BOOLEAN isExcluded = FALSE;

	__try {
		isExcluded = IsPathExcluded(PathName);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		isExcluded = FALSE;
	}

	return isExcluded;
}

__forceinline
PWSTR
FindLastDotManual(
	_In_ PWSTR Buffer,
	_In_ USHORT MaxLength
)
{
	if (!Buffer || MaxLength == 0) {
		return NULL;
	}

	PWSTR lastDot = NULL;
	USHORT length = min(MaxLength, 256);

	__try {
		for (USHORT i = 0; i < length; i++) {
			if (Buffer[i] == L'\0') {
				break;
			}
			if (Buffer[i] == L'.') {
				lastDot = &Buffer[i];
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return NULL;
	}

	return lastDot;
}

// comparacao manual de extensoes
__forceinline
BOOLEAN
CompareExtensionsManual(
	_In_ PWSTR Ext1,
	_In_ const WCHAR* Ext2
)
{
	if (!Ext1 || !Ext2) {
		return FALSE;
	}

	__try {
		ULONG ext2Len = 0;
		while (Ext2[ext2Len] != L'\0' && ext2Len < 20) {
			ext2Len++;
		}

		for (ULONG i = 0; i < ext2Len; i++) {
			WCHAR c1 = Ext1[i];
			WCHAR c2 = Ext2[i];

			if (c1 == L'\0') return FALSE;

			// Converter para maiúsculas
			if (c1 >= L'a' && c1 <= L'z') c1 -= (L'a' - L'A');
			if (c2 >= L'a' && c2 <= L'z') c2 -= (L'a' - L'A');

			if (c1 != c2) {
				return FALSE;
			}
		}

		return (Ext1[ext2Len] == L'\0');
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
}

BOOLEAN
FullExtensionCheck(
	_In_ PUNICODE_STRING fileName
)
{
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
		return FALSE;
	}

	PAGED_CODE();

	if (!fileName || !fileName->Buffer || fileName->Length == 0) {
		return FALSE;
	}

	// Primeiro verificar lista estática 
	static const WCHAR* suspiciousExtensions[] = {
		// Extensões genéricas de ransomware
		L".crypt", L".locked", L".encrypted", L".ransom",
		L".crypto", L".xtbl", L".zepto", L".cerber",

		// LockBit Family
		L".lockbit", L".lockbit2", L".lockbit3", L".lb",
		L".abraham",

		// Conti Family
		L".conti", L".conty", L".conticrypt",

		// Akira Family
		L".akira", L".akr",

		// Ryuk Family
		L".ryuk", L".ryk",

		// Phobos Family
		L".phobos", L".pho", L".devos", L".elbie",

		// BlackCat/ALPHV
		L".blackcat", L".alphv",

		// Royal Family
		L".royal", L".royal4",

		// Clop Family
		L".clop", L".cl0p",

		// Hive Family
		L".hive",

		// BianLian Family
		L".bianlian",

		// WannaCry Family
		L".wncry", L".wnry", L".wcry",

		// Outros comuns
		L".cryptolocker", L".cryptowall", L".teslacrypt",
		L".locky", L".sage", L".spora", L".globe",
		L".purge", L".crysis", L".arena", L".djvu",
		L".stop", L".puma", L".shadow", L".darkness"
	};

	__try {
		PWSTR lastDot = FindLastDotManual(fileName->Buffer,
			fileName->Length / sizeof(WCHAR));

		if (!lastDot) {
			return CheckDynamicExtensions(fileName);
		}

		// Verificar lista estática primeiro
		for (ULONG i = 0; i < ARRAYSIZE(suspiciousExtensions); i++) {
			if (CompareExtensionsManual(lastDot, suspiciousExtensions[i])) {
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
					"Static extension match: %wZ -> %S\n", fileName, suspiciousExtensions[i]);
				return TRUE;
			}
		}

		return CheckDynamicExtensions(fileName);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
}


BOOLEAN
IsSuspiciousExtension(
	_In_ PUNICODE_STRING fileName
)
{
	if (!fileName || !fileName->Buffer || fileName->Length == 0) {
		return FALSE;
	}

	KIRQL currentIrql = KeGetCurrentIrql();

	if (currentIrql >= DISPATCH_LEVEL) {
		return FALSE;
	}

	if (currentIrql == APC_LEVEL) {
		return QuickExtensionCheck(fileName);
	}

	PAGED_CODE();
	return FullExtensionCheck(fileName);
}

static const UCHAR g_RansomwarePatterns[][8] = {
	{0x4C, 0x6F, 0x63, 0x6B, 0x42, 0x69, 0x74, 0x20},
	{0x43, 0x6F, 0x6E, 0x74, 0x69, 0x20, 0x52, 0x61},
};

BOOLEAN
CheckPatternsInBuffer(
	_In_ PVOID buffer,
	_In_ ULONG length,
	_In_ KIRQL currentIrql
)
{
	if (!buffer || length < 8) {
		return FALSE;
	}

	ULONG scanLimit = min(length, 256);
	ULONG patternLimit = ARRAYSIZE(g_RansomwarePatterns);

	if (currentIrql == APC_LEVEL) {
		scanLimit = min(scanLimit, 64);
		patternLimit = min(patternLimit, 2);
	}

	PUCHAR scanBuffer = (PUCHAR)buffer;
	BOOLEAN detected = FALSE;

	__try {
		// Teste inicial de acesso
		volatile UCHAR testByte = scanBuffer[0];
		UNREFERENCED_PARAMETER(testByte);

		for (ULONG p = 0; p < patternLimit && !detected; p++) {
			for (ULONG i = 0; i <= scanLimit - 8 && !detected; i++) {
				SIZE_T matches = 0;

				for (ULONG j = 0; j < 8; j++) {
					if (scanBuffer[i + j] == g_RansomwarePatterns[p][j]) {
						matches++;
					}
					else {
						break;
					}
				}

				if (matches == 8) {
					detected = TRUE;
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"CheckPatternsInBuffer: Exception 0x%X at IRQL %d\n",
			GetExceptionCode(), currentIrql);
		detected = FALSE;
	}

	return detected;
}

BOOLEAN
DispatchLevelFastCheck(_In_ PVOID Buffer, _In_ ULONG Length)
{
	if (Length < 8) return FALSE;

	PUCHAR scanBuffer = (PUCHAR)Buffer;
	ULONG scanLimit = min(Length - 8, 16);

	static const UCHAR patterns[][8] = {
		{0x4C, 0x6F, 0x63, 0x6B, 0x42, 0x69, 0x74, 0x20},
		{0x43, 0x72, 0x79, 0x70, 0x74, 0x6F, 0x6C, 0x6F}
	};

	__try {
		for (ULONG p = 0; p < 2; p++) {
			for (ULONG i = 0; i <= scanLimit; i++) {
				BOOLEAN match = TRUE;
				for (ULONG j = 0; j < 8; j++) {
					if (scanBuffer[i + j] != patterns[p][j]) {
						match = FALSE;
						break;
					}
				}
				if (match) return TRUE;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	return FALSE;
}

BOOLEAN
SafeExtensionCheckDispatchLevel(_In_ PUNICODE_STRING fileName)
{
	if (!fileName || fileName->Length < 6 * sizeof(WCHAR) ||
		fileName->Length > 256 * sizeof(WCHAR)) {
		return FALSE;
	}

	return FALSE;
}

BOOLEAN
QuickExtensionCheck(_In_ PUNICODE_STRING fileName)
{
	KIRQL currentIrql = KeGetCurrentIrql();
	if (currentIrql >= DISPATCH_LEVEL) {
		return SafeExtensionCheckDispatchLevel(fileName);
	}

	__try {
		if (!fileName || !fileName->Buffer) {
			return FALSE;
		}

		PWSTR buf = fileName->Buffer;
		USHORT len = min(fileName->Length / sizeof(WCHAR), 64);

		PWSTR lastDot = FindLastDotManual(buf, len);
		if (!lastDot) return FALSE;

		// Verificar apenas extensões mais comuns rapidamente
		if (QuickCompareExtension(lastDot, L".crypt") ||
			QuickCompareExtension(lastDot, L".locked") ||
			QuickCompareExtension(lastDot, L".encrypted") ||
			QuickCompareExtension(lastDot, L".ransom")) {
			return TRUE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	return FALSE;
}

BOOLEAN
QuickCompareExtension(
	_In_ PWSTR Ext,
	_In_ const WCHAR* Pattern
)
{
	__try {
		ULONG patternLen = 0;
		while (Pattern[patternLen] != L'\0' && patternLen < 20) {
			patternLen++;
		}

		for (ULONG i = 0; i < patternLen; i++) {
			if (Ext[i] == L'\0') return FALSE;

			WCHAR c1 = Ext[i];
			WCHAR c2 = Pattern[i];

			// Converter para maiúsculas
			if (c1 >= L'a' && c1 <= L'z') c1 -= (L'a' - L'A');
			if (c2 >= L'a' && c2 <= L'z') c2 -= (L'a' - L'A');

			if (c1 != c2) return FALSE;
		}

		return (Ext[patternLen] == L'\0');
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
}

BOOLEAN
DetectEncryptionPatterns(
	_In_ PVOID buffer,
	_In_ ULONG length
)
{
	KIRQL currentIrql = KeGetCurrentIrql();

	if (currentIrql > APC_LEVEL) {
		return FALSE;
	}

	if (currentIrql == PASSIVE_LEVEL) {
		PAGED_CODE();
	}

	if (!buffer || length < 8 || length > MAX_SCAN_LENGTH) {
		return FALSE;
	}

	__try {
		volatile UCHAR testByte = *((volatile PUCHAR)buffer);
		UNREFERENCED_PARAMETER(testByte);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	if (currentIrql == APC_LEVEL) {
		length = min(length, 128);
	}

	return CheckPatternsInBuffer(buffer, length, currentIrql);
}

BOOLEAN
QuickPatternCheckDispatchLevel(
	_In_ PFLT_CALLBACK_DATA data
)
{
	if (KeGetCurrentIrql() != DISPATCH_LEVEL) {
		return FALSE;
	}

	if (!data || !data->Iopb) {
		return FALSE;
	}

	PMDL mdl = data->Iopb->Parameters.Write.MdlAddress;
	if (!mdl) {
		return FALSE;
	}

	if (!(mdl->MdlFlags & MDL_PAGES_LOCKED)) {
		return FALSE;
	}

	PVOID writeBuffer = MmGetSystemAddressForMdlSafe(mdl, HighPagePriority);
	if (!writeBuffer) {
		return FALSE;
	}

	ULONG length = min(data->Iopb->Parameters.Write.Length, 64);

	const UCHAR lockbitPattern[] = { 0x4C, 0x6F, 0x63, 0x6B, 0x42, 0x69, 0x74, 0x20 };

	if (length < 8) return FALSE;

	PUCHAR scanBuffer = (PUCHAR)writeBuffer;
	ULONG scanLimit = min(length - 8, 16);

	__try {
		for (ULONG i = 0; i <= scanLimit; i++) {
			BOOLEAN match = TRUE;

			for (ULONG j = 0; j < 8; j++) {
				if (scanBuffer[i + j] != lockbitPattern[j]) {
					match = FALSE;
					break;
				}
			}

			if (match) return TRUE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		// Silenciar em DISPATCH_LEVEL
	}

	return FALSE;
}

BOOLEAN
QuickPatternCheck(
	_In_ PFLT_CALLBACK_DATA data
)
{
	KIRQL currentIrql = KeGetCurrentIrql();

	if (currentIrql >= DISPATCH_LEVEL) {
		return FALSE;
	}

	if (!data || !data->Iopb) {
		return FALSE;
	}

	PMDL mdl = data->Iopb->Parameters.Write.MdlAddress;
	if (!mdl) {
		return FALSE;
	}

	PVOID writeBuffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
	if (!writeBuffer) {
		return FALSE;
	}

	ULONG length = min(data->Iopb->Parameters.Write.Length,
		GetScanLimitForIrql(currentIrql));

	return CheckPatternsInBuffer(writeBuffer, length, currentIrql);
}

BOOLEAN
CheckDynamicExtensions(
	_In_ PUNICODE_STRING fileName
)
{
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
		return FALSE;
	}

	PAGED_CODE();

	if (!fileName || !fileName->Buffer || fileName->Length == 0) {
		return FALSE;
	}

	if (!IsPushLockInitialized(&g_driverContext.RulesListLock)) {
		return FALSE;
	}

	NTSTATUS lockStatus = AcquirePushLockSharedWithTimeout(&g_driverContext.RulesListLock, 50);
	if (!NT_SUCCESS(lockStatus)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
			"CheckDynamicExtensions: Failed to acquire lock: 0x%X\n", lockStatus);
		return FALSE;
	}

	BOOLEAN found = FALSE;
	PLIST_ENTRY listEntry;
	PTR_RULE_INFO rule;

	__try {
		for (listEntry = g_driverContext.RulesList.Flink;
			listEntry != &g_driverContext.RulesList;
			listEntry = listEntry->Flink) {

			if (!IsListEntryValid(listEntry)) {
				continue;
			}

			rule = CONTAINING_RECORD(listEntry, RULE_INFO, ListEntry);

			// Verificar se a regra está ativa e tem pattern
			if (!rule->PatternData || rule->PatternLength == 0) {
				continue;
			}

			// Converter pattern para string unicode
			UNICODE_STRING patternStr;
			patternStr.Buffer = (PWSTR)rule->PatternData;
			patternStr.Length = (USHORT)rule->PatternLength;
			patternStr.MaximumLength = (USHORT)rule->PatternLength;

			// Verificar se é uma regra de extensão
			BOOLEAN isExtensionRule = FALSE;
			for (USHORT i = 0; i < patternStr.Length / sizeof(WCHAR); i++) {
				if (patternStr.Buffer[i] == L'.') {
					isExtensionRule = TRUE;
					break;
				}
			}

			if (!isExtensionRule) {
				continue;
			}

			// Procurar a extensão no filename
			PWSTR lastDot = FindLastDotManual(fileName->Buffer,
				fileName->Length / sizeof(WCHAR));
			if (!lastDot) {
				continue;
			}

			// Processar múltiplas extensões separadas por ponto-e-vírgula
			WCHAR patternCopy[512];
			ULONG copyLen = min(patternStr.Length / sizeof(WCHAR), 511);

			__try {
				RtlCopyMemory(patternCopy, patternStr.Buffer, copyLen * sizeof(WCHAR));
				patternCopy[copyLen] = L'\0';
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				continue;
			}

			PWSTR currentPos = patternCopy;
			PWSTR tokenStart = patternCopy;

			while (*currentPos && !found) {
				if (*currentPos == L';') {
					*currentPos = L'\0';

					// Verificar esta extensão
					if (tokenStart[0] == L'.') {
						if (QuickCompareExtension(lastDot, tokenStart)) {
							DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
								"Dynamic extension match: %wZ -> %S\n", fileName, tokenStart);
							found = TRUE;
							break;
						}
					}

					tokenStart = currentPos + 1;
				}
				currentPos++;
			}

			if (!found && tokenStart[0] == L'.') {
				if (QuickCompareExtension(lastDot, tokenStart)) {
					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
						"Dynamic extension match: %wZ -> %S\n", fileName, tokenStart);
					found = TRUE;
				}
			}

			if (found) {
				break;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"CheckDynamicExtensions: Exception 0x%X\n", GetExceptionCode());
		found = FALSE;
	}

	ExReleasePushLockShared(&g_driverContext.RulesListLock);
	return found;
}

BOOLEAN
ScanBuffer(
	_In_ PVOID buffer,
	_In_ ULONG length,
	_In_ PUNICODE_STRING fileName,
	_In_opt_ PEPROCESS process
)
{
	UNREFERENCED_PARAMETER(process);

	KIRQL currentIrql = KeGetCurrentIrql();

	if (currentIrql > APC_LEVEL) {
		return FALSE;
	}

	if (currentIrql == PASSIVE_LEVEL) {
		PAGED_CODE();
	}

	if (!buffer || length == 0 || length > MAX_SCAN_LENGTH) {
		return FALSE;
	}

	ULONG safeLength = length;
	if (currentIrql == APC_LEVEL) {
		safeLength = min(length, 1024);
	}

	if (IsPathExcludedFromDetection(fileName)) {
		return FALSE;
	}

	BOOLEAN detected = FALSE;

	if (DetectEncryptionPatterns(buffer, min(safeLength, 8192))) {
		AlertToUserMode(
			fileName,
			PsGetCurrentProcessId(),
			PsGetCurrentThreadId(),
			RULE_FLAG_MATCH,
			&g_CryptoRuleName
		);
		detected = TRUE;
	}

	// Verificação de regras customizadas
	if (!detected && currentIrql == PASSIVE_LEVEL) {
		if (!IsPushLockInitialized(&g_driverContext.RulesListLock)) {
			return detected;
		}

		HANDLE currentPid = PsGetCurrentProcessId();
		HANDLE currentTid = PsGetCurrentThreadId();

		// Verificação de regras customizadas
		if (!detected && currentIrql == PASSIVE_LEVEL) {
			if (!IsPushLockInitialized(&g_driverContext.RulesListLock)) {
				return detected;
			}

			NTSTATUS lockStatus = AcquirePushLockSharedWithTimeout(
				&g_driverContext.RulesListLock, 50);

			if (NT_SUCCESS(lockStatus)) {
				__try {
					if (IsListValid(&g_driverContext.RulesList)) {
						PLIST_ENTRY listEntry = g_driverContext.RulesList.Flink;
						ULONG ruleCount = 0;
						const ULONG maxRules = 1000;

						while (listEntry != &g_driverContext.RulesList &&
							ruleCount < maxRules && !detected) {
							if (!IsListEntryValid(listEntry)) break;

							PTR_RULE_INFO rule = CONTAINING_RECORD(listEntry, RULE_INFO, ListEntry);

							if (rule && rule->PatternData && rule->PatternLength > 0 &&
								safeLength >= rule->PatternLength) {

								ULONG maxScan = min(safeLength - rule->PatternLength, 8192);

								for (ULONG i = 0; i <= maxScan && !detected; ++i) {
									SIZE_T bytesEqual = 0;

									bytesEqual = SafeCompareMemory(
										(PUCHAR)buffer + i,
										rule->PatternData,
										rule->PatternLength
									);

									if (bytesEqual == rule->PatternLength) {
										ExReleasePushLockShared(&g_driverContext.RulesListLock);

										AlertToUserMode(
											fileName,
											currentPid,
											currentTid,
											rule->Flags,
											&rule->RuleName
										);

										return TRUE;  
									}
								}
							}

							listEntry = listEntry->Flink;
							ruleCount++;
						}
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					detected = FALSE;
				}

				ExReleasePushLockShared(&g_driverContext.RulesListLock);
			}

			return detected;
		}
	}

	return detected;
}

BOOLEAN
ScanFileContent(
	_In_ PFILE_OBJECT fileObject,
	_In_ PFLT_INSTANCE initialInstance,
	_In_opt_ PEPROCESS process
)
{
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
		return FALSE;
	}

	if (!fileObject || !initialInstance) {
		return FALSE;
	}

	if (!g_FilterHandle) {
		return FALSE;
	}

	PAGED_CODE();

	if (IsPathExcludedFromDetection(&fileObject->FileName)) {
		return FALSE;
	}

	NTSTATUS status;
	PVOID readBuffer = NULL;
	ULONG bytesToRead;
	ULONG bytesRead;
	LARGE_INTEGER byteOffset;
	BOOLEAN fileDetected = FALSE;
	ULONG chunkSize = 65536;
	ULONG volumeAlignmentRequirement = 512;

	UNREFERENCED_PARAMETER(process);

	PFLT_VOLUME volume = NULL;
	FLT_VOLUME_PROPERTIES volumeProperties;
	ULONG returnedLength;

	status = FltGetVolumeFromInstance(initialInstance, &volume);
	if (!NT_SUCCESS(status)) {
		return FALSE;
	}

	status = FltGetVolumeProperties(
		volume,
		&volumeProperties,
		sizeof(volumeProperties),
		&returnedLength
	);
	FltObjectDereference(volume);

	if (!NT_SUCCESS(status)) {
		volumeAlignmentRequirement = 512;
	}
	else {
		volumeAlignmentRequirement = volumeProperties.SectorSize;
		if (volumeAlignmentRequirement == 0) {
			volumeAlignmentRequirement = 512;
		}
	}

	if (chunkSize % volumeAlignmentRequirement != 0) {
		chunkSize = (chunkSize / volumeAlignmentRequirement + 1) * volumeAlignmentRequirement;
	}

	FILE_STANDARD_INFORMATION fileInfo;
	status = FltQueryInformationFile(
		initialInstance,
		fileObject,
		&fileInfo,
		sizeof(fileInfo),
		FileStandardInformation,
		NULL
	);

	if (!NT_SUCCESS(status)) {
		return FALSE;
	}
	ULONGLONG fileSize = fileInfo.EndOfFile.QuadPart;

	if (fileSize == 0) {
		return FALSE;
	}

	readBuffer = FltAllocatePoolAlignedWithTag(
		initialInstance,
		POOL_FLAG_PAGED,
		chunkSize,
		TAG_SCAN
	);
	if (readBuffer == NULL) {
		return FALSE;
	}

	byteOffset.QuadPart = 0;

	while ((ULONGLONG)byteOffset.QuadPart < fileSize && !fileDetected) {
		bytesToRead = (ULONG)min((ULONGLONG)chunkSize,
			(ULONGLONG)(fileSize - byteOffset.QuadPart));
		bytesToRead = (bytesToRead / volumeAlignmentRequirement) * volumeAlignmentRequirement;

		if (bytesToRead == 0) {
			break;
		}

		if (byteOffset.QuadPart % volumeAlignmentRequirement != 0) {
			fileDetected = FALSE;
			break;
		}

		status = FltReadFile(
			initialInstance,
			fileObject,
			&byteOffset,
			bytesToRead,
			readBuffer,
			FLTFL_IO_OPERATION_NON_CACHED,
			&bytesRead,
			NULL,
			NULL
		);

		if (!NT_SUCCESS(status) || bytesRead == 0) {
			if (status == STATUS_END_OF_FILE && bytesRead > 0) {
				// Continuar
			}
			else if (status == STATUS_END_OF_FILE && bytesRead == 0) {
				break;
			}
			else {
				break;
			}
		}

		if (DetectEncryptionPatterns(readBuffer, bytesRead)) {
			AlertToUserMode(
				&fileObject->FileName,
				PsGetCurrentProcessId(),
				PsGetCurrentThreadId(),
				RULE_FLAG_MATCH,
				&g_CryptoRuleName
			);
			fileDetected = TRUE;
			break;
		}

		if (ScanBuffer(readBuffer, bytesRead, &fileObject->FileName, process)) {
			fileDetected = TRUE;
			break;
		}

		byteOffset.QuadPart += bytesRead;
	}

	if (readBuffer) {
		FltFreePoolAlignedWithTag(initialInstance, readBuffer, TAG_SCAN);
	}

	return fileDetected;
}