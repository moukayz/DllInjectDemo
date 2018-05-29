// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <stdio.h>
#include <Windows.h>

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	/* Open file*/
	FILE *file;
	fopen_s(&file, "tmp.txt", "a");

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:	
		fprintf_s(file, "DLL Process Attached!");
		break;
	case DLL_THREAD_ATTACH:
		fprintf_s(file, "DLL Thread Attached!");
		break;
	case DLL_THREAD_DETACH:
		fprintf_s(file, "DLL Process Detached!");
		break;
	case DLL_PROCESS_DETACH:
		fprintf_s(file, "DLL Thread Detached!");
		break;

	}

	fclose(file);

	return TRUE;
}

