#include "Driver.h"
#include <HOOK.h>
#include<FastFunction.h>
#include<R3_ReadProcess.h>
static HANDLE T[20] = {NULL};	
static ULONG Number = 0;
static R3_ReadProcess g_R3_ReadProcess;
//BEDaisy.sys
//EasyAntiCheat.sys
VOID PassPubgHook()
{
	BYTE DbgUiCode[10] = { 0, };
	BYTE INT3 =  0XCC ;
	PEPROCESS Process =   FastFunction::ProcessToPeprocess("lsass.exe");
	if (Process == NULL) {
		return;
	}
	PVOID FunAddr = FastFunction::GetFunctionFromModule(Process, L"ntdll.dll", "DbgUiRemoteBreakin", TRUE, FALSE);
	if (FunAddr == NULL) {
		return;
	}
	FastFunction::MMCopyProcessMemory(Process, FunAddr, 10, &DbgUiCode);
	ObDereferenceObject(Process);
	Process = NULL;

	//-------------------------------------------------------开始JB的恢复HOOK
	Process = FastFunction::ProcessToPeprocess("TslGame.exe");
	if (Process == NULL) {
	
		OutPut("没有找到进程\n");
		return;
	}

	FastFunction::WriteProcessPhy_Me(Process, (ULONG64)FunAddr, &DbgUiCode, 10);
	
	//-------------------------------------------------艹第二个HOOK
	FunAddr = NULL;
	FunAddr = FastFunction::GetFunctionFromModule(Process, L"ntdll.dll", "DbgBreakPoint", TRUE, FALSE);
	if (FunAddr == NULL) {
		return;
	}
	FastFunction::WriteProcessPhy_Me(Process, (ULONG64)FunAddr, &INT3, 1);
	ObDereferenceObject(Process);
	Process = NULL;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT pPDriverObj, PUNICODE_STRING pRegistryPath)
{

	ULONG64 Tid[THREAD_MAX_NUMBER] = {0};
	pPDriverObj->DriverUnload = UnLoadDriver;
	FastFunction::Init_SSDT_Fun();
	FastFunction::GetDriverThread("BEDaisy.sys",&Number, Tid);
	for (ULONG i = 0; i < Number; i++)
	{
		T[i] = FastFunction::OpenThread(THREAD_ALL_ACCESS, FALSE, (DWORD)Tid[i]);
		FastFunction::SuspendThread(T[i]);
	}
	PassPubgHook();
	g_R3_ReadProcess.R3_ReadProcess_Start(pPDriverObj);
	return STATUS_SUCCESS;

}

VOID UnLoadDriver(PDRIVER_OBJECT pPDriverObj)
{
     g_R3_ReadProcess.UnLoad_R3_ReadProcess();
	for (ULONG i = 0; i < Number; i++)
	{

		FastFunction::ResumeThread(T[i]);
		ZwClose(T);
	}
}
