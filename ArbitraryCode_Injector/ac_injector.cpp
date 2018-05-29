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
	procID = 12048;
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

	if (!(hThread = CreateRemoteThread(process, NULL, NULL,
		(LPTHREAD_START_ROUTINE)remoteWrapper, NULL, NULL, NULL)))
	{
		log_error("Create remote thread failed!");
		exit(1);
	}

	WaitForSingleObject(hThread, INFINITE);

	DWORD exitCode = NULL;
	if (!GetExitCodeThread(hThread, &exitCode))
		return NULL;

	CloseHandle(hThread);

	if (!VirtualFreeEx(process, remoteText, 0, MEM_RELEASE) || !VirtualFreeEx(process, remoteWrapper, 0, MEM_RELEASE))
		return NULL;


	return exitCode;

}