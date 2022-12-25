// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

BOOL WINAPI DllMain(HMODULE hModule, DWORD reason, LPVOID) {
	switch (reason) {
		case DLL_PROCESS_ATTACH:
			WCHAR text[64];
			StringCchPrintf(text, _countof(text), L"Injected into process %u!", GetCurrentProcessId());
			MessageBox(nullptr, text, L"Injected DLL", MB_OK);
			break;

		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}

