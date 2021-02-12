#include <Windows.h>
#include <stdio.h>

typedef int (*pfnMessageBoxA)(
	HWND   hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT   uType
);
typedef BOOL (*pfnCreateProcessA)(
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
);
typedef DWORD (*pfnGetModuleFileNameA)(
	HMODULE hModule,
	LPSTR   lpFilename,
	DWORD   nSize
);
typedef HANDLE (*pfnCreateThread)(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
);

pfnMessageBoxA messageBoxA = NULL;
pfnCreateProcessA createProcessA = NULL;
pfnGetModuleFileNameA getModuleFileNameA = NULL;
pfnCreateThread createThread = NULL;

void InitializeFunctionPointers() {
    // NOTE:
	// The following Win32 API addresses are stored as global variables
	// Win32 API functions are called through these global variables
	HMODULE kernel32Base = LoadLibraryA("kernel32.dll");
	if (kernel32Base) {
		createProcessA = (pfnCreateProcessA)GetProcAddress(kernel32Base, "CreateProcessA");
		getModuleFileNameA = (pfnGetModuleFileNameA)GetProcAddress(kernel32Base, "GetModuleFileNameA");
		createThread = (pfnCreateThread)GetProcAddress(kernel32Base, "CreateThread");
	}
	HMODULE user32Base = LoadLibraryA("user32.dll");
	if (user32Base) {
		messageBoxA = (pfnMessageBoxA)GetProcAddress(user32Base, "MessageBoxA");
	}

	printf("%p %p %p %p\n", createProcessA, getModuleFileNameA, createThread, messageBoxA);
}

int main() {
	InitializeFunctionPointers();
	messageBoxA(NULL, "Hi", "Hello", MB_OK);
	return 0;
}