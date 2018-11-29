#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <strsafe.h>
#include "..\Common\log.hpp"

typedef struct _GUI_INFO
{
	HWND	hWindow;
	DWORD	ThreadId;
	DWORD	ProcessId;
}GUI_INFO, *PGUI_INFO;

inline VOID ErrorExit(LPCSTR lpszFunction)
{
	// Retrieve the system error message for the last-error code

	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s ---- error code %d: %s"),
		lpszFunction, dw, lpMsgBuf);
	//MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);
	log_error((LPCSTR)lpDisplayBuf);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	system("PAUSE");
	ExitProcess(dw);
}

inline DWORD FindProcessId(const char *processname)
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
		ErrorExit(TEXT(" Failed to gather information on system processes! "));
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

inline DWORD GetMainThreadId(DWORD dwOwnerPID)
{
	HANDLE  hThreadSnap = NULL;
	THREADENTRY32 te32;

	// Take a snapshot of all running threads
	if ((hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)) ==
		INVALID_HANDLE_VALUE)
	{
		ErrorExit(TEXT("Cannot create thread snapshot!"));

	}

	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve infomation about the frist thread
	if (!Thread32First(hThreadSnap, &te32))
	{
		ErrorExit(TEXT("Cannot get the handle of the first thread!"));

	}

	while (te32.th32OwnerProcessID != dwOwnerPID)
	{
		Thread32Next(hThreadSnap, &te32);
		if (te32.th32OwnerProcessID == dwOwnerPID)
			return te32.th32ThreadID;
	}

	return 0;
}

inline HANDLE GetMainThread(DWORD dwOwnerPID)
{
	HANDLE hThread = NULL;

	// Return the main thread's handle
	if (!(hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, GetMainThreadId(dwOwnerPID))))
	{
		ErrorExit(TEXT("Open main thread of the remote process failed!"));
	}

	return hThread;

}

inline BOOL FileExists(LPCTSTR szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

inline BOOL CALLBACK EnumWindowsProc(
	HWND   hwnd,
	LPARAM lParam
)
{
	DWORD pid, tid = 0;
	PGUI_INFO guiInfo = (PGUI_INFO)lParam;

	tid = GetWindowThreadProcessId(hwnd, &pid);
	if (!tid)	ErrorExit("Get window process failed.");

	if (pid == guiInfo->ProcessId)
	{
		guiInfo->hWindow = hwnd;
		guiInfo->ThreadId = tid;
		SetLastError(ERROR_SUCCESS);
		return FALSE;
	}

	return TRUE;
}

inline BOOLEAN GetProcessGUIThreadInfo(PGUI_INFO pGUIInfo)
{
	if (!EnumWindows((WNDENUMPROC)EnumWindowsProc, (LPARAM)pGUIInfo) &&
		GetLastError() != ERROR_SUCCESS)
		return FALSE;

	return TRUE;
	
}

