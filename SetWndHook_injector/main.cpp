#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <strsafe.h>

#include "..\Common\utils.hpp"

#define TARGET_NAME "MyWindowProgram.exe"

int main()
{
	HMODULE mydll = LoadLibraryA( "C:\\Users\\MOUKA\\Source\\Repos\\DLLInjectDemo\\Bin\\MyDll.dll" );
	if ( !mydll )	ErrorExit( "Load mydll failed.\n" );

	HOOKPROC myfoo = (HOOKPROC)GetProcAddress( mydll, "foo" );
	if ( !myfoo )	ErrorExit( "Get foo failed.\n" );

	DWORD pid = FindProcessId( TARGET_NAME );
	if ( !pid )	ErrorExit( "Get target process id failed.\n" );

	DWORD TargetThreadId = GetMainThreadId( pid );
	if ( !TargetThreadId )	ErrorExit( "Get target main thread failed.\n" );

	if ( !SetWindowsHookExA(
		WH_KEYBOARD,
		myfoo,
		mydll,
		TargetThreadId ) )
	{
		ErrorExit( "Install windows hook failed.\n" );
	}
	log_debug( "Install hook successfully.\n" );

	WaitForSingleObject( GetMainThread( pid ), INFINITE );

}