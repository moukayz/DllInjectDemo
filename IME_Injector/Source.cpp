#include <Windows.h>
#include <tchar.h>

#include "..\Common\log.hpp"
#include "..\Common\utils.hpp"

#define DLLPATH	_T("C:\\Users\\MOUKA\\Source\\Repos\\DLLInjectDemo\\Bin\\MyDll.dll")
#define IMEPATH	_T("C:\\Users\\MOUKA\\Source\\Repos\\DLLInjectDemo\\Bin\\MyDll.ime")
#define TARGET_PROCESS	_T("windbg.exe")

int _tmain()
{
	// Check dll is valid
	if ( !FileExists( DLLPATH ) )	ErrorExit( "Injected dll not exist." );

	// Copy dll to ime file
	if ( !CopyFile( DLLPATH, IMEPATH, FALSE ) )	ErrorExit( "Copy dll to ime failed." );


}