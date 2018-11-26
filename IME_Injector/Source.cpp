#include <Windows.h>
#include <tchar.h>
#include <imm.h>
#include <ShlObj.h>
#include <strsafe.h>

#include "..\Common\log.hpp"
#include "..\Common\utils.hpp"

#pragma comment(lib, "imm32.lib")

/*
IME Injection:
ime file can be any dll
* "ime" extension not matter,
* no need to implement any ime function

*** need version resource which specify it's a input method
eg:
FILETYPE 0x3L		(VFT_DRV)
FILESUBTYPE 0xbL	(VFT2_DRV_INPUTMETHOD)
*/

#define DLLPATH	_T("C:\\UInject.ime")
#define DLLPATH2 _T("C:\\Users\\MOUKA\\Source\\Repos\\DLLInjectDemo\\Bin\\MyDll.dll")
#define IME_FILENAME	_T("MyDll.dll")
#define IME_NAME	_T("MyDll")
#define TARGET_PROCESS	_T("MyWindowProgram.exe")

#define REG_CURRENT_USER_KBDLAYOUT	_T("Keyboard Layout\\Preload")
#define REG_LOCAL_MACHINE_KBDLAYOUT	_T("SYSTEM\\ControlSet001\\Control\\Keyboard Layouts")
int _tmain()
{
	CHAR	windir[MAX_PATH] = { 0 };
	CHAR	imeDir[MAX_PATH] = { 0 };
	// Check dll is valid
	if ( !FileExists( DLLPATH2 ) )	ErrorExit( "Injected dll not exist." );

	SHGetSpecialFolderPathA( 0, windir, CSIDL_SYSTEM, FALSE );

	StringCbPrintfA( imeDir, MAX_PATH, "%s\\%s", windir, "MyDll.dll" );
	log_debug( "Ime path: %s", imeDir );


	// Copy dll to ime file
	if ( !CopyFile( DLLPATH2, imeDir, FALSE ) )	ErrorExit( "Copy dll to ime failed." );

	DWORD pid = FindProcessId( TARGET_PROCESS );
	if ( !pid )	ErrorExit( "Get process id failed." );

	GUI_INFO guiInfo = { 0 };
	guiInfo.ProcessId = pid;
	if ( !GetProcessGUIThreadInfo( &guiInfo ) )
		ErrorExit( "Get GUI thread failed." );

	HKL hIME = ImmInstallIME( imeDir, "MyDll" );
	if ( !hIME )
	{
		log_error( "hIME = %p\n", hIME );
		ErrorExit( "Install ime failed. " );
	}

	// Backup default ime
	HKL	oldIme = 0;
	SystemParametersInfo( SPI_GETDEFAULTINPUTLANG, 0, &oldIme, 0 );

	PostMessage( guiInfo.hWindow, WM_INPUTLANGCHANGEREQUEST, INPUTLANGCHANGE_SYSCHARSET, (LPARAM)hIME );
	PostMessage( guiInfo.hWindow, WM_INPUTLANGCHANGE, 0, (LPARAM)hIME );
	Sleep( 1000 );

	//// Restore default ime in target window
	//PostMessage( guiInfo.hWindow, WM_INPUTLANGCHANGEREQUEST, INPUTLANGCHANGE_SYSCHARSET, (LPARAM)oldIme );
	//PostMessage( guiInfo.hWindow, WM_INPUTLANGCHANGE, 0, (LPARAM)oldIme );
	//Sleep( 1000 );

	// Remove inject ime from system after injection
	if ( !UnloadKeyboardLayout( hIME ) )
		ErrorExit( "Unload inject IME failed." );

	HKEY hKey = 0;
	DWORD valuesCount = 0;
	TCHAR valueName[MAX_PATH] = { 0 };
	DWORD valueNameSize = MAX_PATH;
	TCHAR subKeyName[MAX_PATH] = { 0 };


	if ( ERROR_SUCCESS == RegOpenKeyEx(
		HKEY_CURRENT_USER,
		REG_CURRENT_USER_KBDLAYOUT,
		0,
		KEY_ALL_ACCESS,
		&hKey )
		)
	{
		if ( ERROR_SUCCESS == RegQueryInfoKey( hKey, NULL, NULL, NULL, NULL, NULL, NULL, &valuesCount, NULL, NULL, NULL, NULL ) )
		{
			if ( ERROR_SUCCESS == RegEnumValue( hKey, valuesCount - 1, valueName, &valueNameSize, NULL, NULL, NULL, NULL ) )
			{
				RegDeleteValue( hKey, valueName );
			}
			else
				ErrorExit( "Enum value failed." );
		}
		else
			ErrorExit( "Query key info failed." );

		RegCloseKey( hKey );
	}
	else
		ErrorExit( "Open reg key failed." );

	DWORD ret = ERROR_SUCCESS;
	DWORD idx = 0;
	DWORD keyIme = 0;

	if ( ERROR_SUCCESS == RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		REG_LOCAL_MACHINE_KBDLAYOUT,
		0, KEY_ALL_ACCESS, &hKey ) )
	{
		while ( RegEnumKey( hKey, idx++, subKeyName, MAX_PATH ) == ERROR_SUCCESS )
		{
			keyIme = _tcstoul( subKeyName, NULL, 16 );
			if ( keyIme > 0x100000 )
				log_debug( "Delete ime key !" );
			if ( keyIme == (DWORD)hIME )
			{
				DebugBreak();
				if ( ERROR_SUCCESS == RegDeleteKey( hKey, subKeyName ) )
				{
					log_debug( "Delete ime key !" );
					break;
				}
				else
					ErrorExit( "Delete ime key failed." );

			}

		}
	}
	else
		ErrorExit( "Open ime key failed." );



	system( "PAUSE" );
	return 0;

}