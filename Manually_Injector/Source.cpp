#include <Windows.h>
#include <tchar.h>

#include "..\Common\log.hpp"
#include "..\Common\utils.hpp"

#define DLLPATH _T("D:\\repos\\DllInjectDemo\\Bin\\MyDll.dll")
#define TARGET_PROCESS	_T("MyProgram.exe")
#define INVALID_HANDLE(handle)	(handle == INVALID_HANDLE_VALUE)

typedef
HMODULE
WINAPI
pLoadLibraryA(
	_In_ LPCSTR lpLibFileName
);

typedef
FARPROC
WINAPI
pGetProcAddress(
	_In_ HMODULE hModule,
	_In_ LPCSTR lpProcName
);

typedef struct _LOADER_PARAMS
{
	PVOID ImageBase;
	PIMAGE_NT_HEADERS	pNtHeaders;

	PIMAGE_BASE_RELOCATION	pBaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR	pImportDirectory;

	pLoadLibraryA	fnLoadLibraryA;
	pGetProcAddress	fnGetProcAddress;
}LOADER_PARAMS, *PLOADER_PARAMS;
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

	HANDLE hFileMap = CreateFileMapping( hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
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

	// Target Dll's Section Header
	PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)( (LPBYTE)pNtHeaders + sizeof(IMAGE_NT_HEADERS) );

	PIMAGE_IMPORT_DESCRIPTOR pImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)( (LPBYTE)pMapAddress + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress );

	PIMAGE_BASE_RELOCATION pBaseRelocation = (PIMAGE_BASE_RELOCATION)( (LPBYTE)pMapAddress + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress );

	ULONG_PTR delta = (ULONG_PTR)( (LPBYTE)pMapAddress - pNtHeaders->OptionalHeader.ImageBase ); // Calculate the delta

	while ( pBaseRelocation->VirtualAddress )
	{
		if ( pBaseRelocation->SizeOfBlock >= sizeof( IMAGE_BASE_RELOCATION ) )
		{
			int count = ( pBaseRelocation->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( WORD );
			PWORD list = (PWORD)( pBaseRelocation + 1 );

			for ( int i = 0; i < count; i++ )
			{
				if ( list[i] )
				{
					PULONG_PTR ptr = (PULONG_PTR)( (LPBYTE)pMapAddress + ( pBaseRelocation->VirtualAddress + ( list[i] & 0xFFF ) ) );
					//*ptr += delta;
				}
			}
		}

		pBaseRelocation = (PIMAGE_BASE_RELOCATION)( (LPBYTE)pBaseRelocation + pBaseRelocation->SizeOfBlock );
	}

	// Resolve DLL imports
	while ( pImportDirectory->Characteristics )
	{
		PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)( (LPBYTE)pMapAddress + pImportDirectory->OriginalFirstThunk );
		PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)( (LPBYTE)pMapAddress + pImportDirectory->FirstThunk );

		HMODULE hModule = LoadLibraryA( (LPCSTR)pMapAddress + pImportDirectory->Name );

		if ( !hModule )
			return FALSE;

		while ( OrigFirstThunk->u1.AddressOfData )
		{
			if ( OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG )
			{
				// Import by ordinal
				ULONG_PTR Function = (ULONG_PTR)GetProcAddress( hModule,
					(LPCSTR)( OrigFirstThunk->u1.Ordinal & 0xFFFF ) );

				if ( !Function )
					return FALSE;

				FirstThunk->u1.Function = Function;
			}
			else
			{
				// Import by name
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)( (LPBYTE)pMapAddress + OrigFirstThunk->u1.AddressOfData );
				ULONG_PTR Function = (ULONG_PTR)GetProcAddress( hModule, (LPCSTR)pIBN->Name );
				if ( !Function )
					return FALSE;

				//FirstThunk->u1.Function = Function;
			}
			OrigFirstThunk++;
			FirstThunk++;
		}
		pImportDirectory++;
	}
}