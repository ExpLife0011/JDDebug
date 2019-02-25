// ApexR3.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <Windows.h>
#include <Strsafe.h>
#include <wchar.h>
#include <vector>
#include <iostream>

using namespace std;

#define NT_SUCCESS(x) ((x) >= 0)

#define ProcessBasicInformation 0
typedef
NTSTATUS(WINAPI *pfnNtWow64QueryInformationProcess64)
(HANDLE ProcessHandle, UINT32 ProcessInformationClass,
	PVOID ProcessInformation, UINT32 ProcessInformationLength,
	UINT32* ReturnLength);

typedef
NTSTATUS(WINAPI *pfnNtWow64ReadVirtualMemory64)
(HANDLE ProcessHandle, PVOID64 BaseAddress,
	PVOID BufferData, UINT64 BufferLength,
	PUINT64 ReturnLength);

typedef
NTSTATUS(WINAPI *pfnNtQueryInformationProcess)
(HANDLE ProcessHandle, ULONG ProcessInformationClass,
	PVOID ProcessInformation, UINT32 ProcessInformationLength,
	UINT32* ReturnLength);

template <typename T>
struct _UNICODE_STRING_T
{
	WORD Length;
	WORD MaximumLength;
	T Buffer;
};

template <typename T>
struct _LIST_ENTRY_T
{
	T Flink;
	T Blink;
};

template <typename T, typename NGF, int A>
struct _PEB_T
{
	typedef T type;

	union
	{
		struct
		{
			BYTE InheritedAddressSpace;
			BYTE ReadImageFileExecOptions;
			BYTE BeingDebugged;
			BYTE BitField;
		};
		T dummy01;
	};
	T Mutant;
	T ImageBaseAddress;
	T Ldr;
	T ProcessParameters;
	T SubSystemData;
	T ProcessHeap;
	T FastPebLock;
	T AtlThunkSListPtr;
	T IFEOKey;
	T CrossProcessFlags;
	T UserSharedInfoPtr;
	DWORD SystemReserved;
	DWORD AtlThunkSListPtr32;
	T ApiSetMap;
	T TlsExpansionCounter;
	T TlsBitmap;
	DWORD TlsBitmapBits[2];
	T ReadOnlySharedMemoryBase;
	T HotpatchInformation;
	T ReadOnlyStaticServerData;
	T AnsiCodePageData;
	T OemCodePageData;
	T UnicodeCaseTableData;
	DWORD NumberOfProcessors;
	union
	{
		DWORD NtGlobalFlag;
		NGF dummy02;
	};
	LARGE_INTEGER CriticalSectionTimeout;
	T HeapSegmentReserve;
	T HeapSegmentCommit;
	T HeapDeCommitTotalFreeThreshold;
	T HeapDeCommitFreeBlockThreshold;
	DWORD NumberOfHeaps;
	DWORD MaximumNumberOfHeaps;
	T ProcessHeaps;
	T GdiSharedHandleTable;
	T ProcessStarterHelper;
	T GdiDCAttributeList;
	T LoaderLock;
	DWORD OSMajorVersion;
	DWORD OSMinorVersion;
	WORD OSBuildNumber;
	WORD OSCSDVersion;
	DWORD OSPlatformId;
	DWORD ImageSubsystem;
	DWORD ImageSubsystemMajorVersion;
	T ImageSubsystemMinorVersion;
	T ActiveProcessAffinityMask;
	T GdiHandleBuffer[A];
	T PostProcessInitRoutine;
	T TlsExpansionBitmap;
	DWORD TlsExpansionBitmapBits[32];
	T SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	T pShimData;
	T AppCompatInfo;
	_UNICODE_STRING_T<T> CSDVersion;
	T ActivationContextData;
	T ProcessAssemblyStorageMap;
	T SystemDefaultActivationContextData;
	T SystemAssemblyStorageMap;
	T MinimumStackCommit;
	T FlsCallback;
	_LIST_ENTRY_T<T> FlsListHead;
	T FlsBitmap;
	DWORD FlsBitmapBits[4];
	T FlsHighIndex;
	T WerRegistrationData;
	T WerShipAssertPtr;
	T pContextData;
	T pImageHeaderHash;
	T TracingFlags;
	T CsrServerReadOnlySharedMemoryBase;
};

typedef _PEB_T<DWORD, DWORD64, 34> _PEB32;
typedef _PEB_T<DWORD64, DWORD, 30> _PEB64;

typedef struct _STRING_32
{
	WORD Length;
	WORD MaximumLength;
	UINT32 Buffer;
} STRING32, *PSTRING32;

typedef struct _STRING_64
{
	WORD Length;
	WORD MaximumLength;
	UINT64 Buffer;
} STRING64, *PSTRING64;

typedef struct _RTL_DRIVE_LETTER_CURDIR_32
{
	WORD Flags;
	WORD Length;
	ULONG TimeStamp;
	STRING32 DosPath;
} RTL_DRIVE_LETTER_CURDIR32, *PRTL_DRIVE_LETTER_CURDIR32;

typedef struct _RTL_DRIVE_LETTER_CURDIR_64
{
	WORD Flags;
	WORD Length;
	ULONG TimeStamp;
	STRING64 DosPath;
} RTL_DRIVE_LETTER_CURDIR64, *PRTL_DRIVE_LETTER_CURDIR64;

typedef struct _UNICODE_STRING_32
{
	WORD Length;
	WORD MaximumLength;
	UINT32 Buffer;
} UNICODE_STRING32, *PUNICODE_STRING32;

typedef struct _UNICODE_STRING_64
{
	WORD Length;
	WORD MaximumLength;
	UINT64 Buffer;
} UNICODE_STRING64, *PUNICODE_STRING64;


typedef struct _CURDIR_32
{
	UNICODE_STRING32 DosPath;
	UINT32 Handle;
} CURDIR32, *PCURDIR32;

typedef struct _RTL_USER_PROCESS_PARAMETERS_32
{
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	UINT32 ConsoleHandle;
	ULONG ConsoleFlags;
	UINT32 StandardInput;
	UINT32 StandardOutput;
	UINT32 StandardError;
	CURDIR32 CurrentDirectory;
	UNICODE_STRING32 DllPath;
	UNICODE_STRING32 ImagePathName;
	UNICODE_STRING32 CommandLine;
	UINT32 Environment;
	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING32 WindowTitle;
	UNICODE_STRING32 DesktopInfo;
	UNICODE_STRING32 ShellInfo;
	UNICODE_STRING32 RuntimeData;
	RTL_DRIVE_LETTER_CURDIR32 CurrentDirectores[32];
	ULONG EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS32, *PRTL_USER_PROCESS_PARAMETERS32;


typedef struct _CURDIR_64
{
	UNICODE_STRING64 DosPath;
	UINT64 Handle;
} CURDIR64, *PCURDIR64;

typedef struct _RTL_USER_PROCESS_PARAMETERS_64
{
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	UINT64 ConsoleHandle;
	ULONG ConsoleFlags;
	UINT64 StandardInput;
	UINT64 StandardOutput;
	UINT64 StandardError;
	CURDIR64 CurrentDirectory;
	UNICODE_STRING64 DllPath;
	UNICODE_STRING64 ImagePathName;
	UNICODE_STRING64 CommandLine;
	UINT64 Environment;
	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING64 WindowTitle;
	UNICODE_STRING64 DesktopInfo;
	UNICODE_STRING64 ShellInfo;
	UNICODE_STRING64 RuntimeData;
	RTL_DRIVE_LETTER_CURDIR64 CurrentDirectores[32];
	ULONG EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS64, *PRTL_USER_PROCESS_PARAMETERS64;



typedef struct _PROCESS_BASIC_INFORMATION64 {
	NTSTATUS ExitStatus;
	UINT32 Reserved0;
	UINT64 PebBaseAddress;
	UINT64 AffinityMask;
	UINT32 BasePriority;
	UINT32 Reserved1;
	UINT64 UniqueProcessId;
	UINT64 InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION64;

typedef struct _PROCESS_BASIC_INFORMATION32 {
	NTSTATUS ExitStatus;
	UINT32 PebBaseAddress;
	UINT32 AffinityMask;
	UINT32 BasePriority;
	UINT32 UniqueProcessId;
	UINT32 InheritedFromUniqueProcessId;
}PROCESS_BASIC_INFORMATION32;
typedef enum _SYSTEM_INFORMATION_CLASS     //    Q S
{
	SystemBasicInformation,                // 00 Y N
	SystemProcessorInformation,            // 01 Y N
	SystemPerformanceInformation,          // 02 Y N
	SystemTimeOfDayInformation,            // 03 Y N
	SystemNotImplemented1,                 // 04 Y N
	SystemProcessesAndThreadsInformation,  // 05 Y N
	SystemCallCounts,                      // 06 Y N
	SystemConfigurationInformation,        // 07 Y N
	SystemProcessorTimes,                  // 08 Y N
	SystemGlobalFlag,                      // 09 Y Y
	SystemNotImplemented2,                 // 10 Y N
	SystemModuleInformation,               // 11 Y N
	SystemLockInformation,                 // 12 Y N
	SystemNotImplemented3,                 // 13 Y N
	SystemNotImplemented4,                 // 14 Y N
	SystemNotImplemented5,                 // 15 Y N
	SystemHandleInformation,               // 16 Y N
	SystemObjectInformation,               // 17 Y N
	SystemPagefileInformation,             // 18 Y N
	SystemInstructionEmulationCounts,      // 19 Y N
	SystemInvalidInfoClass1,               // 20
	SystemCacheInformation,                // 21 Y Y
	SystemPoolTagInformation,              // 22 Y N
	SystemProcessorStatistics,             // 23 Y N
	SystemDpcInformation,                  // 24 Y Y
	SystemNotImplemented6,                 // 25 Y N
	SystemLoadImage,                       // 26 N Y
	SystemUnloadImage,                     // 27 N Y
	SystemTimeAdjustment,                  // 28 Y Y
	SystemNotImplemented7,                 // 29 Y N
	SystemNotImplemented8,                 // 30 Y N
	SystemNotImplemented9,                 // 31 Y N
	SystemCrashDumpInformation,            // 32 Y N
	SystemExceptionInformation,            // 33 Y N
	SystemCrashDumpStateInformation,       // 34 Y Y/N
	SystemKernelDebuggerInformation,       // 35 Y N
	SystemContextSwitchInformation,        // 36 Y N
	SystemRegistryQuotaInformation,        // 37 Y Y
	SystemLoadAndCallImage,                // 38 N Y
	SystemPrioritySeparation,              // 39 N Y
	SystemNotImplemented10,                // 40 Y N
	SystemNotImplemented11,                // 41 Y N
	SystemInvalidInfoClass2,               // 42
	SystemInvalidInfoClass3,               // 43
	SystemTimeZoneInformation,             // 44 Y N
	SystemLookasideInformation,            // 45 Y N
	SystemSetTimeSlipEvent,                // 46 N Y
	SystemCreateSession,                   // 47 N Y
	SystemDeleteSession,                   // 48 N Y
	SystemInvalidInfoClass4,               // 49
	SystemRangeStartInformation,           // 50 Y N
	SystemVerifierInformation,             // 51 Y Y
	SystemAddVerifier,                     // 52 N Y
	SystemSessionProcessesInformation      // 53 Y N
} SYSTEM_INFORMATION_CLASS;


NTSTATUS WINAPI ZwQuerySystemInformation(
	_In_        SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_     PVOID SystemInformation,
	_In_        ULONG SystemInformationLength,
	_Out_opt_   PULONG ReturnLength
);

UINT64 GetProcessPeb(	int PID)
{
	HANDLE m_ProcessHandle;



	m_ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

	BOOL bSource = FALSE;
	BOOL bTarget = FALSE;
	//判断自己的位数
	IsWow64Process(GetCurrentProcess(), &bSource);
	//判断目标的位数
	IsWow64Process(m_ProcessHandle, &bTarget);

	if (bTarget == FALSE && bSource == FALSE)
	{
		HMODULE NtdllModule = GetModuleHandle(L"ntdll.dll");
		pfnNtWow64QueryInformationProcess64 NtWow64QueryInformationProcess64 = (pfnNtWow64QueryInformationProcess64)GetProcAddress(NtdllModule, "NtQueryInformationProcess");
		pfnNtWow64ReadVirtualMemory64 NtWow64ReadVirtualMemory64 = (pfnNtWow64ReadVirtualMemory64)GetProcAddress(NtdllModule, "NtReadVirtualMemory");

		PROCESS_BASIC_INFORMATION64 pbi = { 0 };
		UINT64 ReturnLength = 0;

		NTSTATUS Status = NtWow64QueryInformationProcess64(m_ProcessHandle, ProcessBasicInformation, &pbi, (UINT32)sizeof(pbi), (UINT32*)&ReturnLength);

		if (NT_SUCCESS(Status))
		{

			_PEB64* Peb = (_PEB64*)malloc(sizeof(_PEB64));
			RTL_USER_PROCESS_PARAMETERS64* ProcessParameters = (RTL_USER_PROCESS_PARAMETERS64*)malloc(sizeof(RTL_USER_PROCESS_PARAMETERS64));
			
			Status = NtWow64ReadVirtualMemory64(m_ProcessHandle, (PVOID64)pbi.PebBaseAddress,(_PEB64*)Peb, sizeof(_PEB64), &ReturnLength);
			CloseHandle(m_ProcessHandle);
			return pbi.PebBaseAddress;
		}
	}
	CloseHandle(m_ProcessHandle);
	return 0;
}
VOID ReHookDbgUiRemoteBreakin(HANDLE hProcess)
{
	byte code3[] = { 0x48,0x83,0xEC,0x28,0x65,0x48,0x8B,0x04,0x25,0x60 };
	BYTE INT3Code[] = { 0XCC };
	ULONG64 pDbgUiRemoteBreakin = (ULONG64)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "DbgUiRemoteBreakin");
	ULONG64  INT3 = (ULONG64)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "DbgBreakPoint");
	DWORD64 Size = 0;
    WriteProcessMemory(hProcess, (PVOID)pDbgUiRemoteBreakin, code3, 10, (SIZE_T *)&Size);
	Size = 0;
	WriteProcessMemory(hProcess, (PVOID)INT3, INT3Code, 1, (SIZE_T *)&Size);
}
VOID HideDebug(DWORD PID,UINT64 Peb)
{
	int Hide = 0;
	DWORD Size = 0;
	HANDLE m_ProcessHandle;
	m_ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);	
	ReHookDbgUiRemoteBreakin(m_ProcessHandle);
	while (1)
	{
		
		WriteProcessMemory(m_ProcessHandle, (PVOID)(Peb + 0x002), &Hide, 4, (SIZE_T *)&Size);
		Sleep(1000);
		printf("调试隐藏中.\n");
	
	}
}
VOID PassBe(DWORD PID)
{
   HideDebug(PID, GetProcessPeb(PID));
}
int main()
{
	PassBe(18092);
	

	
	return 0;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门提示: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
