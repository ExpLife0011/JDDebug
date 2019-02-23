#include "Driver.h"
#include <HOOK.h>
#include<FastFunction.h>
#include<R3_ReadProcess.h>
static HANDLE T[20] = {NULL};	
static ULONG Number = 0;
static R3_ReadProcess g_R3_ReadProcess;
//BEDaisy.sys
//EasyAntiCheat.sys
NTSTATUS DriverEntry(PDRIVER_OBJECT pPDriverObj, PUNICODE_STRING pRegistryPath)
{

	ULONG64 Tid[THREAD_MAX_NUMBER] = {0};
	pPDriverObj->DriverUnload = UnLoadDriver;

	FastFunction::GetDriverThread("BEDaisy.sys",&Number, Tid);
	for (ULONG i = 0; i < Number; i++)
	{
		T[i] = FastFunction::OpenThread(THREAD_ALL_ACCESS, FALSE, (DWORD)Tid[i]);
		FastFunction::SuspendThread(T[i]);
	}
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
