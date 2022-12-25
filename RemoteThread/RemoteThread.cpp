// RemoteThread.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>

int Error(const char* text) {
	printf("%s (%u)\n", text, GetLastError());
	return 1;
}

int main(int argc, const char* argv[]) {
	if (argc < 3) {
		printf("Usage: remotethread <pid> <dllpath>\n");
		return 0;
	}

	int pid = atoi(argv[1]);
	HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, pid);
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

	printf("Remote thread created successfully!");

	WaitForSingleObject(hThread, 5000);
	VirtualFreeEx(hProcess, buffer, 0, MEM_RELEASE);
	CloseHandle(hProcess);

	return 0;
}

