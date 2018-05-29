#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>

#include "log.h"

/*
* bytecode of the MessageBox function
* ******
	push 0x30
	push 0
	push 0xcccc
	push 0
	mov eax, 0xffffffff
	call eax
	ret
*/
byte wrapper[] = { 0x6a,0x30,0x6a,0x00,0x68,0xcc,0xcc,0xcc,0xcc,0x6a,0x00,0xb8,0xff,0xff,0xff,0xff,0xff,0xd0,0xc3 };

DWORD FindProcessId(const char *processname)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	DWORD result = NULL;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcessSnap) return(FALSE);

	pe32.dwSize = sizeof(PROCESSENTRY32); // <----- IMPORTANT

										  // Retrieve information about the first process,
										  // and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);          // clean the snapshot object
		printf("!!! Failed to gather information on system processes! \n");
		return(NULL);
	}

	do
	{
		if (0 == strcmp(processname, pe32.szExeFile))
		{
			result = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	return result;
}

HANDLE GetMainThread(DWORD dwOwnerPID)
{
	HANDLE  hThreadSnap = INVALID_HANDLE_VALUE;
	HANDLE hThread = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	// Take a snapshot of all running threads
	if ((hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)) ==
		INVALID_HANDLE_VALUE)
	{
		log_error("Cannot create thread snapshot!");
		exit(1);
	}

	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve infomation about the frist thread
	if (!Thread32First(hThreadSnap, &te32))
	{
		log_error("Cannot get the handle of the first thread!");
		exit(1);
	}

	while (te32.th32OwnerProcessID != dwOwnerPID)
	{
		Thread32Next(hThreadSnap, &te32);
	}

	// Return the main thread's handle
	if (!(hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID)))
	{
		log_error("Open main thread of the remote process failed!");
		exit(1);
	}

	return hThread;

}
int main()
{
	UINT32 procID;
	HANDLE process;
	LPVOID remoteWrapper;
	LPVOID remoteText;
	HANDLE hThread;
	const char *text = "Injected Hello World";


	// Get injected process handle by PID
	/*if (!(procID = FindProcessId("MyProgram.exe")))
	{
		printf_s("Error: Cannot find process ID!\nExited.\n");
		exit(1);
	}*/
	procID = 17672;
	log_debug("Get process ID : %d", procID);

	if (!(process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID)))
	{
		log_error("Open injected process failed!\nExited.");
		exit(1);
	}
	log_debug("Get process handle : %p", &process);

	if (!(remoteWrapper = VirtualAllocEx(process, NULL,
		sizeof(wrapper), MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
	{
		log_error("Cannot allocate memory for remote wrapper!");
		exit(1);
	}
	log_debug("Get allocated remote wrapper address : %p", remoteWrapper);


	if (!(remoteText = VirtualAllocEx(process, NULL,
		sizeof(text) + 1, MEM_COMMIT, PAGE_READWRITE)))
	{
		log_error("Cannot allocate memory for output text!");
		exit(1);
	}
	log_debug("Get allocated remote text address: %p", remoteText);

	if (!WriteProcessMemory(process, remoteText, (LPVOID)text, strlen(text) + 1, NULL))
	{
		log_error("Cannot write  text to process memory!");
		exit(1);
	}
	log_debug("Write text content to process memory.");

	MEMORY_BASIC_INFORMATION bi;
	VirtualQuery(wrapper, &bi, sizeof(bi));
	if (!VirtualProtect(wrapper, sizeof(wrapper), PAGE_READWRITE, &(bi.Protect)))
	{
		log_error("VirtualProtect failed!");
		GetLastError();
		exit(1);
	}

	*(DWORD*)(wrapper + 5) = (DWORD)remoteText;
	if (!(*(DWORD*)(wrapper + 12) =
		(DWORD)GetProcAddress(LoadLibrary("USER32.DLL"), "MessageBoxA")))
	{
		log_error("Cannot find the address of function MessageBoxA! ");
		exit(1);
	}

	if (!WriteProcessMemory(process, remoteWrapper,
		(LPVOID)wrapper, sizeof(wrapper), NULL))
	{
		log_error("Cannot write wrapper to process memory!");
		exit(1);
	}

	CONTEXT context;
	hThread = GetMainThread(procID);
	if (SuspendThread(hThread) == -1)
	{
		log_error("Suspend thread failed!");
		exit(1);
	}
	memset(&context, NULL, sizeof(context));
	context.ContextFlags = CONTEXT_ALL;

	if (!GetThreadContext(hThread, &context))
	{
		log_error("Get thread context failed!");
		exit(1);
	}

	context.Eip = (DWORD)wrapper;
	if (!SetThreadContext(hThread, &context))
	{
		log_error("Set thread context failed!");
		exit(1);
	}
	ResumeThread(hThread);

	CloseHandle(hThread);


}