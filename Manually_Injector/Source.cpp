#include <Windows.h>
#include <tchar.h>

#include "..\Common\log.hpp"
#include "..\Common\utils.hpp"

#define DLLPATH _T("d:\\repos\\DllInjectDemo\\Bin\\MyDll.dll")
#define TARGET_PROCESS	_T("MyWindowProgram.exe")

#define GetModuleFuncAddress(ModuleName, FuncName)	(LPVOID)(GetProcAddress(LoadLibrary(_T(ModuleName)), _T(FuncName)))

#define INVALID_HANDLE(handle)	(handle == INVALID_HANDLE_VALUE)
#define OffsetToVA(address, offset)	((ULONG_PTR)(address) + (offset))

#define DEREF( name )		*(PULONG_PTR)(name)
#define DEREF_64( name )	*(PDWORD64)(name)
#define DEREF_32( name )	*(PDWORD)(name)
#define DEREF_16( name )	*(PWORD )(name)
#define DEREF_8( name )		*(PBYTE)(name)

// PE Field Macros
#define DOS_HEADER(pImageBase)	((PIMAGE_DOS_HEADER)pImageBase)
#define NT_HEADERS(pImageBase)	((PIMAGE_NT_HEADERS)(OffsetToVA(pImageBase, DOS_HEADER(pImageBase)->e_lfanew)))
#define SEC_HEADER(pImageBase)	((PIMAGE_SECTION_HEADER)(OffsetToVA(NT_HEADERS(pImageBase), sizeof(IMAGE_NT_HEADERS))))
#define IMAGE_SIZE(pImageBase)	(NT_HEADERS(pImageBase)->OptionalHeader.SizeOfImage)
#define IMAGE_BASE(pImageBase)	(NT_HEADERS(pImageBase)->OptionalHeader.ImageBase)
#define IMAGE_ENTRYPOINT(pImageBase)	((PVOID)(OffsetToVA(pImageBase, NT_HEADERS(pImageBase)->OptionalHeader.AddressOfEntryPoint )))

#define	RVA_DATA_DIRECTORY(pImageBase, Index)	((NT_HEADERS(pImageBase)->OptionalHeader.DataDirectory[Index].VirtualAddress))
#define VA_DATA_DIRECTORY(pImageBase, Index)	((PVOID)(OffsetToVA(pImageBase, RVA_DATA_DIRECTORY(pImageBase, Index))))
#define REMOTE_DATA_DIRECTORY(pRemote, pImageBase, Index)	((PVOID)(OffsetToVA(pRemote, RVA_DATA_DIRECTORY(pImageBase, Index))))

#define RELOC_BLOCKS_COUNT(pBR)	(( (pBR)->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( WORD ))
#define RELOC_BLOCKS(pBR)	(PWORD(OffsetToVA(pBR, sizeof(IMAGE_BASE_RELOCATION))))
#define	RELOC_DELTA(pImageBase)	((ULONG_PTR)pImageBase - IMAGE_BASE(pImageBase))
#define RELOC_POINTER(pImageBase, pBR, BlockIndex)	((PULONG_PTR)(OffsetToVA(pImageBase, (pBR)->VirtualAddress + RELOC_BLOCKS(pBR)[BlockIndex] & 0xFFF )))
#define RELOC_NEXT_BASERELOC(pBR)	((PIMAGE_BASE_RELOCATION)OffsetToVA(pBR, (pBR)->SizeOfBlock))

#define IMPORT_OFT(pImageBase, pID)	((PIMAGE_THUNK_DATA)(OffsetToVA(pImageBase, (pID)->OriginalFirstThunk)))
#define IMPORT_FT(pImageBase, pID)	((PIMAGE_THUNK_DATA)(OffsetToVA(pImageBase, (pID)->FirstThunk)))
#define IMPORT_NAME(pImageBase, pID)	((LPCSTR)(OffsetToVA(pImageBase, (pID)->Name)))
#define IMPORT_FUNC_ORDINAL(pID)		((pID)->u1.Ordinal)
#define IMPORT_FUNC_NAME(pImageBase, pOFT)	((LPCSTR)((PIMAGE_IMPORT_BY_NAME)OffsetToVA(pImageBase, (pOFT)->u1.AddressOfData))->Name)
#define IMPORT_NEXT_THUNK(pThunk)	((PIMAGE_THUNK_DATA)(OffsetToVA(pThunk, sizeof(IMAGE_THUNK_DATA))))
#define IMPORT_NEXT_DESCRIPTOR(pID)	((PIMAGE_IMPORT_DESCRIPTOR)(OffsetToVA(pID, sizeof(IMAGE_IMPORT_DESCRIPTOR))))


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
	PVOID pImageBase = LoaderParams->ImageBase;

	PIMAGE_BASE_RELOCATION pBaseRelocation = LoaderParams->pBaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = LoaderParams->pImportDirectory;

	ULONG_PTR delta = RELOC_DELTA(pImageBase); // Calculate the delta
	while ( pBaseRelocation->VirtualAddress &&
		pBaseRelocation->SizeOfBlock >= sizeof( IMAGE_BASE_RELOCATION ) )
	{
		DWORD blockCount = RELOC_BLOCKS_COUNT(pBaseRelocation);
		PWORD blockList = RELOC_BLOCKS(pBaseRelocation);
		for ( DWORD i = 0; i < blockCount; i++ )
		{
			if ( blockList[i] )
			{
				/*PULONG_PTR ptr = (PULONG_PTR)( (LPBYTE)pImageBase + ( pBaseRelocation->VirtualAddress + ( blockList[i] & 0xFFF ) ) );*/
				PULONG_PTR ptr = RELOC_POINTER( pImageBase, pBaseRelocation, i );
				*ptr += delta;
			}
		}

		// Go to next base-allocation block
		pBaseRelocation = RELOC_NEXT_BASERELOC( pBaseRelocation );
	}

	// Resolve DLL imports
	while ( pImportDescriptor->Characteristics )
	{
		PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)IMPORT_OFT(pImageBase, pImportDescriptor);
		PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)IMPORT_FT( pImageBase, pImportDescriptor );

		HMODULE hModule = LoaderParams->fnLoadLibraryA(IMPORT_NAME(pImageBase, pImportDescriptor ) );
		if ( !hModule )
			return 5;

		while ( OrigFirstThunk->u1.AddressOfData )
		{
			if ( OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG )
			{
				// Import by ordinal
				ULONG_PTR Function = (ULONG_PTR)LoaderParams->fnGetProcAddress( hModule,
					(LPCSTR)( OrigFirstThunk->u1.Ordinal & 0xFFFF ) );
				if ( !Function )
					return 1;

				FirstThunk->u1.Function = Function;
			}
			else
			{
				// Import by name
				ULONG_PTR Function = (ULONG_PTR)LoaderParams->fnGetProcAddress( hModule, IMPORT_FUNC_NAME(pImageBase, OrigFirstThunk) );
				if ( !Function )
					return 2;

				FirstThunk->u1.Function = Function;
			}
			// Move to next import function
			OrigFirstThunk = IMPORT_NEXT_THUNK(OrigFirstThunk);
			FirstThunk = IMPORT_NEXT_THUNK( FirstThunk );
		}
		// Move to next import dll
		pImportDescriptor = IMPORT_NEXT_DESCRIPTOR(pImportDescriptor);
	}

	if ( LoaderParams->pNtHeaders->OptionalHeader.AddressOfEntryPoint )
	{
		pDllMain EntryPoint = (pDllMain)IMAGE_ENTRYPOINT(pImageBase);

		if ( EntryPoint( (HMODULE)pImageBase, DLL_PROCESS_ATTACH, NULL ) ) // Call the entry point
			return ERROR_SUCCESS;
		else
			return 3;
	}

	return 4;
}

// Stub function used to calculate loader's size
DWORD WINAPI stubFunc()
{
	return 0;
}
/*
Manually Dll Inject:
*****************************************

MAKE SURE YOUR DLL ARE RELEASE BUILDED

MAKE SURE YOUR INJECTOR ARE RELEASE BUILDED

******************************************
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

	PIMAGE_DOS_HEADER pDosHeader = DOS_HEADER(pMapAddress);
	PIMAGE_NT_HEADERS pNtHeaders = NT_HEADERS(pMapAddress);
	PIMAGE_SECTION_HEADER pSectHeader = SEC_HEADER(pMapAddress);
	DWORD	imageSize = IMAGE_SIZE(pMapAddress);
	ULONG_PTR	loaderSize = (ULONG_PTR)stubFunc - (ULONG_PTR)LibLoader;
	log_debug( "Loader size : %x -- Dll image size : %x", loaderSize, imageSize );

	LPVOID fnLoadLibraryA = GetModuleFuncAddress( "KERNEL32.DLL", "LoadLibraryA" );
		/*GetProcAddress( LoadLibraryA( "KERNEL32.DLL" ), "LoadLibraryA" );*/
	LPVOID fnGetProcAddress = GetModuleFuncAddress( "KERNEL32.DLL", "GetProcAddress" );
		/*GetProcAddress( LoadLibraryA( "KERNEL32.DLL" ), "GetProcAddress" );*/
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
	//loaderParams.pBaseRelocation = (PIMAGE_BASE_RELOCATION)( (LPBYTE)remoteImageBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress );
	//loaderParams.pImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)( (LPBYTE)remoteImageBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress );
	loaderParams.pBaseRelocation = (PIMAGE_BASE_RELOCATION)REMOTE_DATA_DIRECTORY( remoteImageBase, pMapAddress, IMAGE_DIRECTORY_ENTRY_BASERELOC );
	loaderParams.pImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)REMOTE_DATA_DIRECTORY( remoteImageBase, pMapAddress, IMAGE_DIRECTORY_ENTRY_IMPORT );
	loaderParams.pNtHeaders = (PIMAGE_NT_HEADERS)OffsetToVA(remoteImageBase, pDosHeader->e_lfanew);
	loaderParams.ImageBase = remoteImageBase;
	log_debug("RemoteLoader parameters:"
		"\n\nRemoteImageBase : %p"
		"\nNtHeaders : %p"
		"\nImportDirectory : %p"
		"\nBaseRelocation  : %p"
		"\nLoadLibrary	: %p"
		"\nGetProcAddress : %p\n",
		remoteImageBase,
		loaderParams.pNtHeaders,
		loaderParams.pImportDirectory,
		loaderParams.pBaseRelocation,
		loaderParams.fnLoadLibraryA,
		loaderParams.fnGetProcAddress );

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

	system( "PAUSE" );
}

#pragma region test
//// Target Dll's DOS Header
//PIMAGE_DOS_HEADER pDosHeader = DOS_HEADER(pMapAddress);
//// Target Dll's NT Headers
//PIMAGE_NT_HEADERS pNtHeaders = NT_HEADERS(pMapAddress);
//DWORD	imageSize = IMAGE_SIZE(pMapAddress);
//ULONG_PTR	loaderSize = (ULONG_PTR)stubFunc - (ULONG_PTR)LibLoader;
//log_debug( "Loader size : %x -- Dll image size : %x", loaderSize, imageSize );
//// Target Dll's Section Header
//PIMAGE_SECTION_HEADER pSectHeader = SEC_HEADER(pMapAddress);

//PIMAGE_BASE_RELOCATION pBaseRelocation = ( PIMAGE_BASE_RELOCATION)VA_DATA_DIRECTORY( pMapAddress, IMAGE_DIRECTORY_ENTRY_BASERELOC );
//PIMAGE_IMPORT_DESCRIPTOR	pImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)VA_DATA_DIRECTORY( pMapAddress, IMAGE_DIRECTORY_ENTRY_IMPORT );

//ULONG_PTR delta = RELOC_DELTA(pMapAddress); // Calculate the delta
//PIMAGE_BASE_RELOCATION pBR2 = pBaseRelocation;
//PIMAGE_IMPORT_DESCRIPTOR pID2 = pImportDirectory;
//while (pBaseRelocation->VirtualAddress)
//{
//	if (pBaseRelocation->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
//	{
//		int blockCount = RELOC_BLOCKS_COUNT(pBaseRelocation);
//		PWORD blockList = RELOC_BLOCKS(pBaseRelocation);

//		for (int i = 0; i < blockCount; i++)
//		{
//			if (blockList[i])
//			{
//				PULONG_PTR ptr = (PULONG_PTR)((LPBYTE)pMapAddress + (pBaseRelocation->VirtualAddress + (blockList[i] & 0xFFF)));
//				PULONG_PTR ptr2 = RELOC_POINTER( pMapAddress, pBaseRelocation, i );
//				ULONG_PTR a = *ptr + *ptr2;
//			}
//		}
//	}

//	pBaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)pBaseRelocation + pBaseRelocation->SizeOfBlock);
//	pBR2 = RELOC_NEXT_BASERELOC( pBR2 );
//}

//// Resolve DLL imports
//while (pImportDirectory->Characteristics)
//{
//	PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)pMapAddress + pImportDirectory->OriginalFirstThunk);
//	PIMAGE_THUNK_DATA	oft = IMPORT_OFT( pMapAddress, pImportDirectory );
//	PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)pMapAddress + pImportDirectory->FirstThunk);
//	PIMAGE_THUNK_DATA ft = IMPORT_FT( pMapAddress, pImportDirectory );

//	HMODULE hModule = LoadLibraryA((LPCSTR)pMapAddress + pImportDirectory->Name);
//	LPCSTR	importName = IMPORT_NAME( pMapAddress, pImportDirectory );
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
//			LPCSTR pIBN2 = IMPORT_FUNC_NAME( pMapAddress, OrigFirstThunk );
//			ULONG_PTR Function = (ULONG_PTR)GetProcAddress(hModule, (LPCSTR)pIBN->Name);
//			if (!Function)
//				return FALSE;

//			//FirstThunk->u1.Function = Function;
//		}
//		OrigFirstThunk++;
//		FirstThunk++;
//		oft = IMPORT_NEXT_THUNK( oft );
//		ft = IMPORT_NEXT_THUNK( ft );
//	}
//	pImportDirectory++;
//	pID2 = IMPORT_NEXT_DESCRIPTOR( pID2 );
//}

//PVOID dllmain = IMAGE_ENTRYPOINT( pMapAddress );

//return 0;
#pragma endregion