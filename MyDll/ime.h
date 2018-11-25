#pragma once
#include <Windows.h>

// Posts messages safely.
//BOOL syncPostMessage(HIMC hIMC, UINT msg, WPARAM wParam, LPARAM lParam);

// The IME window doesn't need to do anything.
LRESULT WINAPI UIWndProc(HWND hUIWnd, UINT message, WPARAM wParam, LPARAM lParam) {

	return 0;
}
LRESULT WINAPI StatusWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) { return 0; }
LRESULT WINAPI CompWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) { return 0; }
LRESULT WINAPI CandWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) { return 0; }

// Necessary IME exports
UINT WINAPI ImeEnumRegisterWord(REGISTERWORDENUMPROC lpfnRegisterWordEnumProc, LPCTSTR lpszReading, DWORD dwStyle, LPCTSTR lpszString, LPVOID lpData) { return (FALSE); }
UINT WINAPI ImeGetRegisterWordStyle(UINT nItem, LPSTYLEBUF lpStyleBuf) { return (FALSE); }
BOOL WINAPI ImeRegisterWord(LPCTSTR lpszReading, DWORD dwStyle, LPCTSTR lpszString) { return (FALSE); }
BOOL WINAPI ImeUnregisterWord(LPCTSTR lpszReading, DWORD dwStyle, LPCTSTR lpszString) { return (FALSE); }
BOOL WINAPI NotifyIME(HIMC hIMC, DWORD dwAction, DWORD dwIndex, DWORD dwValue) { return (FALSE); }
UINT WINAPI ImeToAsciiEx(UINT uVKey, UINT uScanCode, CONST LPBYTE lpbKeyState, LPDWORD lpdwTransKey, UINT fuState, HIMC hIMC) { return 0; }
BOOL WINAPI ImeSetCompositionString(HIMC hIMC, DWORD dwIndex, LPCVOID lpComp, DWORD dwComp, LPCVOID lpRead, DWORD dwRead) { return (FALSE); }
BOOL WINAPI ImeProcessKey(HIMC hIMC, UINT uKey, LPARAM lKeyData, CONST LPBYTE lpbKeyState) { return (FALSE); }
LRESULT WINAPI ImeEscape(HIMC hIMC, UINT uSubFunc, LPVOID lpData) { return (FALSE); }
DWORD WINAPI ImeConversionList(HIMC hIMC, LPCTSTR lpSource, LPCANDIDATELIST lpCandList, DWORD dwBufLen, UINT uFlag) { return (FALSE); }
BOOL WINAPI ImeDestroy(UINT uForce) { return (uForce ? TRUE : (FALSE)); }
BOOL WINAPI ImeSetActiveContext(HIMC hIMC, BOOL fFlag) { return TRUE; }