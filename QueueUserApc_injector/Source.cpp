#include <Windows.h>
#include "..\Common\log.hpp"
#include "..\Common\utils.hpp"

#define DLLPATH "R:\\DllInjectDemo\\Bin\\MyDll.dll"
#define TARGET_PROCESS	"MyProgram.exe"

typedef NTSTATUS  (WINAPI*  ptrNtAlertThread)(HANDLE ThreadHandle);

int main()
{
	ptrNtAlertThread pNtAlertThread = (ptrNtAlertThread)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtAlertThread");
	if (!pNtAlertThread)	ErrorExit("Get NtAlertThread failed.");
	
	DWORD pid = FindProcessId(TARGET_PROCESS);
	if (!pid)	ErrorExit("Get target process id failed.");

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess)	ErrorExit("Get target process handle failed.");

	DWORD tid = GetMainThreadId(pid);

	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	if (!hThread)	ErrorExit("Get target thread handle failed.");

	LPVOID loadLibraryAddress = GetProcAddress(LoadLibraryA("KERNEL32.DLL"), "LoadLibraryA");
	if (!loadLibraryAddress)	ErrorExit("Get LoadLibraryA address failed.");

	LPVOID remoteDllPath = VirtualAllocEx(hProcess, NULL, sizeof(DLLPATH), MEM_COMMIT, PAGE_READWRITE);
	if (!remoteDllPath)	ErrorExit("Alloc remote dll path failed.");

	if (!WriteProcessMemory(hProcess, remoteDllPath, DLLPATH, sizeof(DLLPATH), NULL))
		ErrorExit("Write dllpath to target process failed.");

	if (!QueueUserAPC((PAPCFUNC)loadLibraryAddress, hThread, (ULONG_PTR)remoteDllPath))
		ErrorExit("QueueUserApc failed.");

	NTSTATUS status = pNtAlertThread(hThread);
	
	WaitForSingleObject(hThread, INFINITE);

	return 0;
}