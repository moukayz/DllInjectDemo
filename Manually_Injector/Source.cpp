#include <Windows.h>
#include <tchar.h>

#include "..\Common\log.hpp"
#include "..\Common\utils.hpp"

#define DLLPATH _T("d:\\repos\\DllInjectDemo\\Bin\\MyDll.dll")
#define TARGET_PROCESS	_T("MyWindowProgram.exe")
#define INVALID_HANDLE(handle)	(handle == INVALID_HANDLE_VALUE)
#define PointerAdd(PointerType, Pointer, Increment)	(PointerType)((ULONG_PTR)Pointer + Increment)

typedef
HMODULE
( WINAPI
	*pLoadLibraryA )(
		_In_ LPCSTR lpLibFileName
		);

typedef
FARPROC
( WINAPI
	*pGetProcAddress )(
		_In_ HMODULE hModule,
		_In_ LPCSTR lpProcName
		);

typedef BOOL( WINAPI *pDllMain )( HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
	);

typedef struct _LOADER_PARAMS
{
	PVOID						ImageBase;
	PIMAGE_NT_HEADERS			pNtHeaders;

	PIMAGE_BASE_RELOCATION		pBaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR	pImportDirectory;

	pLoadLibraryA				fnLoadLibraryA;
	pGetProcAddress				fnGetProcAddress;
}LOADER_PARAMS, *PLOADER_PARAMS;

DWORD WINAPI LibLoader( PVOID	Params )
{
	PLOADER_PARAMS LoaderParams = (PLOADER_PARAMS)Params;

	PIMAGE_BASE_RELOCATION pBaseRelocation = LoaderParams->pBaseRelocation;

	ULONG_PTR delta = (ULONG_PTR)LoaderParams->ImageBase - LoaderParams->pNtHeaders->OptionalHeader.ImageBase; // Calculate the delta

	while ( pBaseRelocation->VirtualAddress )
	{
		if ( pBaseRelocation->SizeOfBlock >= sizeof( IMAGE_BASE_RELOCATION ) )
		{
			int blockCount = ( pBaseRelocation->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( WORD );
			PWORD blockList = (PWORD)( pBaseRelocation + 1 );

			for ( int i = 0; i < blockCount; i++ )
			{
				if ( blockList[i] )
				{
					PULONG_PTR relocPointer = (PULONG_PTR)( (LPBYTE)LoaderParams->ImageBase + ( pBaseRelocation->VirtualAddress + ( blockList[i] & 0xFFF ) ) );
					*relocPointer += delta;
				}
			}
		}

		// Go to next base-allocation block
		pBaseRelocation = (PIMAGE_BASE_RELOCATION)( (LPBYTE)pBaseRelocation + pBaseRelocation->SizeOfBlock );
	}

	PIMAGE_IMPORT_DESCRIPTOR pIID = LoaderParams->pImportDirectory;

	// Resolve DLL imports
	//printf("Go to IAT");
	while ( pIID->Characteristics )
	{
		PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)( (LPBYTE)LoaderParams->ImageBase + pIID->OriginalFirstThunk );
		PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)( (LPBYTE)LoaderParams->ImageBase + pIID->FirstThunk );

		HMODULE hModule = LoaderParams->fnLoadLibraryA( (LPCSTR)( (LPBYTE)LoaderParams->ImageBase + pIID->Name ) );
		if ( !hModule )
			return ERROR_INVALID_PARAMETER;

		while ( OrigFirstThunk->u1.AddressOfData )
		{
			if ( OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG )
			{
				// Import by ordinal
				ULONG_PTR Function = (ULONG_PTR)LoaderParams->fnGetProcAddress( hModule,
					(LPCSTR)( OrigFirstThunk->u1.Ordinal & 0xFFFF ) );
				if ( !Function )
					return ERROR_INVALID_PARAMETER;

				FirstThunk->u1.Function = Function;
			}
			else
			{
				// Import by name
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)( (LPBYTE)LoaderParams->ImageBase + OrigFirstThunk->u1.AddressOfData );
				ULONG_PTR Function = (ULONG_PTR)LoaderParams->fnGetProcAddress( hModule, (LPCSTR)pIBN->Name );
				if ( !Function )
					return ERROR_INVALID_PARAMETER;

				FirstThunk->u1.Function = Function;
			}
			// Move to next import function
			OrigFirstThunk++;
			FirstThunk++;
		}
		// Move to next import dll
		pIID++;
	}

	if ( LoaderParams->pNtHeaders->OptionalHeader.AddressOfEntryPoint )
	{
		pDllMain EntryPoint = (pDllMain)( (LPBYTE)LoaderParams->ImageBase + LoaderParams->pNtHeaders->OptionalHeader.AddressOfEntryPoint );

		if ( EntryPoint( (HMODULE)LoaderParams->ImageBase, DLL_PROCESS_ATTACH, NULL ) ) // Call the entry point
			return ERROR_SUCCESS;
		else
			return ERROR_INVALID_PARAMETER;
	}

	return ERROR_INVALID_PARAMETER;
}

DWORD WINAPI stubFunc()
{
	return 0;
}
/*
Manually Dll Inject:
1. Load target dll into injector,
2. Create memory-mapped file of it and write to target process
3. Write loader to target process
4. Create remote thread to execute loader
*/
int _tmain()
{
	//
	// Validate dllpath and target process
	//

	HANDLE hFile = CreateFile( DLLPATH, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL );
	if ( INVALID_HANDLE( hFile ) )	ErrorExit( "Open target dll failed." );

	HANDLE hFileMap = CreateFileMapping( hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL );
	if ( !hFileMap )	ErrorExit( "Create dll file mapping oject failed." );

	PVOID pMapAddress = MapViewOfFileEx( hFileMap, FILE_MAP_READ, 0, 0, 0, (LPVOID)NULL );
	if ( !pMapAddress )	ErrorExit( "Map dll file failed." );

	DWORD pid = FindProcessId( TARGET_PROCESS );
	if ( !pid )	ErrorExit( "Get target process id failed." );

	HANDLE hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid );
	if ( !hProcess )	ErrorExit( "Open target process failed." );

	//
	// Prepare injection parameters
	//

	// Target Dll's DOS Header
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pMapAddress;
	// Target Dll's NT Headers
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)( (LPBYTE)pMapAddress + pDosHeader->e_lfanew );
	DWORD	imageSize = pNtHeaders->OptionalHeader.SizeOfImage;
	ULONG_PTR	loaderSize = (ULONG_PTR)stubFunc - (ULONG_PTR)LibLoader;
	log_debug( "Loader size : %x -- Dll image size : %x", loaderSize, imageSize );
	// Target Dll's Section Header
	PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)( (LPBYTE)pNtHeaders + sizeof( IMAGE_NT_HEADERS ) );

	LPVOID fnLoadLibraryA = GetProcAddress( LoadLibraryA( "KERNEL32.DLL" ), "LoadLibraryA" );
	LPVOID fnGetProcAddress = GetProcAddress( LoadLibraryA( "KERNEL32.DLL" ), "GetProcAddress" );
	if ( !fnLoadLibraryA || !fnGetProcAddress )	ErrorExit( "Get loader function address failed." );


	//
	// Allocate memory for dll and loader in target process and write into it
	//
	SIZE_T bytesWrite = 0;

	PVOID remoteImageBase = VirtualAllocEx( hProcess, NULL, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	if ( !remoteImageBase )	ErrorExit( "Allocate image space in target process failed." );

	if ( !WriteProcessMemory( hProcess, remoteImageBase, pMapAddress, imageSize, &bytesWrite ) ||
		bytesWrite < imageSize )
		ErrorExit( "Write dll image to target proces failed." );

	LOADER_PARAMS loaderParams = { 0 };
	loaderParams.fnGetProcAddress = (pGetProcAddress)fnGetProcAddress;
	loaderParams.fnLoadLibraryA = (pLoadLibraryA)fnLoadLibraryA;
	loaderParams.pBaseRelocation = (PIMAGE_BASE_RELOCATION)( (LPBYTE)remoteImageBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress );
	loaderParams.pImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)( (LPBYTE)remoteImageBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress );
	loaderParams.pNtHeaders = (PIMAGE_NT_HEADERS)( (LPBYTE)remoteImageBase + pDosHeader->e_lfanew );
	loaderParams.ImageBase = remoteImageBase;

	// Allocate loader and its params together
	PVOID remoteLoaderAddress = VirtualAllocEx( hProcess, NULL, loaderSize + sizeof( LOADER_PARAMS ), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	if ( !remoteLoaderAddress )	ErrorExit( "Allocate loader space in target process failed." );
	PVOID remoteParams = (PVOID)( (ULONG_PTR)remoteLoaderAddress + loaderSize );

	if ( !WriteProcessMemory( hProcess, remoteLoaderAddress, LibLoader, loaderSize, &bytesWrite ) ||
		bytesWrite < loaderSize )
		ErrorExit( "Write loader to target process failed." );
	if ( !WriteProcessMemory( hProcess, remoteParams, &loaderParams, sizeof( LOADER_PARAMS ), &bytesWrite ) ||
		bytesWrite < sizeof( LOADER_PARAMS ) )
		ErrorExit( "Write params to target process failed." );

	HANDLE hRemoteThread = CreateRemoteThread( hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)remoteLoaderAddress,
		(LPVOID)remoteParams,
		0, NULL );
	if ( !hRemoteThread )	ErrorExit( "Create remote loader failed." );

	WaitForSingleObject( hRemoteThread, INFINITE );

	DWORD exitCode;
	if ( !GetExitCodeThread( hRemoteThread, &exitCode ) && GetLastError() != STILL_ACTIVE )
		ErrorExit( "Get remote thread exit code failed." );

	if ( exitCode == ERROR_SUCCESS )
		log_debug( "Dll inject !" );
	else
		log_debug( "Dll inject failed with error %x", exitCode );

	VirtualFreeEx( hProcess, remoteLoaderAddress, 0, MEM_RELEASE );


	//ULONG_PTR delta = (ULONG_PTR)((LPBYTE)pMapAddress - pNtHeaders->OptionalHeader.ImageBase); // Calculate the delta

	//while (pBaseRelocation->VirtualAddress)
	//{
	//	if (pBaseRelocation->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
	//	{
	//		int blockCount = (pBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
	//		PWORD blockList = (PWORD)(pBaseRelocation + 1);

	//		for (int i = 0; i < blockCount; i++)
	//		{
	//			if (blockList[i])
	//			{
	//				PULONG_PTR ptr = (PULONG_PTR)((LPBYTE)pMapAddress + (pBaseRelocation->VirtualAddress + (blockList[i] & 0xFFF)));
	//				//*ptr += delta;
	//			}
	//		}
	//	}

	//	pBaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)pBaseRelocation + pBaseRelocation->SizeOfBlock);
	//}

	//// Resolve DLL imports
	//while (pImportDirectory->Characteristics)
	//{
	//	PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)pMapAddress + pImportDirectory->OriginalFirstThunk);
	//	PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)pMapAddress + pImportDirectory->FirstThunk);

	//	HMODULE hModule = LoadLibraryA((LPCSTR)pMapAddress + pImportDirectory->Name);

	//	if (!hModule)
	//		return FALSE;

	//	while (OrigFirstThunk->u1.AddressOfData)
	//	{
	//		if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
	//		{
	//			// Import by ordinal
	//			ULONG_PTR Function = (ULONG_PTR)GetProcAddress(hModule,
	//				(LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

	//			if (!Function)
	//				return FALSE;

	//			FirstThunk->u1.Function = Function;
	//		}
	//		else
	//		{
	//			// Import by name
	//			PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)pMapAddress + OrigFirstThunk->u1.AddressOfData);
	//			ULONG_PTR Function = (ULONG_PTR)GetProcAddress(hModule, (LPCSTR)pIBN->Name);
	//			if (!Function)
	//				return FALSE;

	//			//FirstThunk->u1.Function = Function;
	//		}
	//		OrigFirstThunk++;
	//		FirstThunk++;
	//	}
	//	pImportDirectory++;
	//}
}