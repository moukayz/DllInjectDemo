#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>


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
	const char *dllpath = "MyDll.dll";
	UINT32 procID;
	HANDLE process;
	LPVOID llAddr;
	LPVOID arg;
	HANDLE threadID;

	// Get injected process handle by PID
	if (!(procID = FindProcessId("MyProgram.exe")))
	{
		printf_s("Error: Cannot find process ID!\nExited.\n");
		exit(1);
	}
	printf_s("Get process ID : %d\n", procID);

	if (!(process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID)))
	{
		printf_s("Error: Open injected process failed!\nExited.\n");
		exit(1);
	}
	printf_s("Get process handle : %p\n", &process);

	// Get address of the function LoadLibraryA 
	llAddr = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if (!llAddr)
	{
		printf_s("Error: Get address of the LoadLibrary failed!\n");
		exit(1);
	}
	printf_s("Get LoadLibrary entry address : %p\n", llAddr);

	//// Allocate new memory region inside the injected process's memory space
	//// arg is the start address of the allocated memory
	arg = VirtualAllocEx(process, NULL, strlen(dllpath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!arg)
	{
		printf_s("Error: Cannot allocate memory region in the injected process!\n");
		exit(1);
	}
	printf_s("Get newly allocated memory address : %p\n", arg);

	//// Write the arg of LoadLibrary to the process's newly allocated memory
	if (!WriteProcessMemory(process, arg, dllpath, strlen(dllpath), NULL))
	{
		printf_s("Error: Cannot write the dllpath into the process's memory\n");
		exit(1);
	}

	//// Inject dll into the target process using CreateRemoteThread
	threadID = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)llAddr, arg, NULL, NULL);
	if (!threadID)
	{
		printf_s("Error: Cannot create remote thread!\n");
		exit(1);
	}
	else
	{
		printf_s("Success: the remote thread was successfully created!\n");
	}

	//CloseHandle(process);
	//getchar();

	return 0;
}