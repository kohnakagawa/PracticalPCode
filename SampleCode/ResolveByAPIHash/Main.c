#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <intrin.h>

#include <Windows.h>
#include <winternl.h>

uint32_t calc_dll_hash(const char* dll_name,
    uint32_t len) {
    uint32_t hash = 0;
    for (uint32_t i = 0; i < len; i++) {
        hash = _rotr(hash, 0xd);
        if (dll_name[i] > 0x60) { // to uppercase
            hash -= 0x20;
        }
        hash += (uint32_t)dll_name[i];
    }
    return hash;
}

uint32_t calc_fnc_hash(const char* fnc_name,
    uint32_t len) {
    uint32_t hash = 0;
    for (uint32_t i = 0; i < len; i++) {
        hash = _rotr(hash, 0xd) + (uint32_t)fnc_name[i];
    }
    return hash;
}

void show_hashes(const char* dll_name, const char* fnc_name) {
    const uint32_t dll_hash = calc_dll_hash(dll_name, (uint32_t)strlen(dll_name) + 1);
    const uint32_t fnc_hash = calc_fnc_hash(fnc_name, (uint32_t)strlen(fnc_name) + 1);
    printf("%x %x\n", dll_hash, fnc_hash);
}

#define RVA2VA(type, base, offset) (type)((ULONG_PTR)base + offset)

LPVOID search_exp_function(LPVOID dll_base, DWORD dll_hash_target, DWORD fnc_hash_target) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dll_base;
    PIMAGE_NT_HEADERS nt = RVA2VA(PIMAGE_NT_HEADERS, dll_base, dos->e_lfanew);
    PIMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory;
    DWORD rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (rva == 0) return NULL;
	PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY) RVA2VA(ULONG_PTR, dll_base, rva);
	DWORD cnt = exp->NumberOfNames;
	if (cnt == 0) return NULL;
	PDWORD adr = RVA2VA(PDWORD, dll_base, exp->AddressOfFunctions);
	PDWORD sym = RVA2VA(PDWORD, dll_base, exp->AddressOfNames);
	PWORD ord = RVA2VA(PWORD, dll_base, exp->AddressOfNameOrdinals);
	PCHAR dll = RVA2VA(PCHAR, dll_base, exp->Name);
	DWORD dll_hash = calc_dll_hash(dll, (uint32_t)strlen(dll) + 1);
    if (dll_hash != dll_hash_target) return NULL;

    LPVOID api_addr = NULL;
	do {
		PCHAR api = RVA2VA(PCHAR, dll_base, sym[cnt-1]);
		if (calc_fnc_hash(api, (uint32_t)strlen(api) + 1) == fnc_hash_target) {
			api_addr = RVA2VA(LPVOID, dll_base, adr[ord[cnt-1]]);
			return api_addr;
		}
	} while (--cnt && api_addr==0);
	return api_addr;
}

typedef struct {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA;

typedef struct {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY;

LPVOID resolve_api_addr(DWORD dll_hash, DWORD fnc_hash) {
    LPVOID api_addr = NULL;
    PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    MY_PEB_LDR_DATA* ldr = (MY_PEB_LDR_DATA*)(peb->Ldr);
    for (MY_LDR_DATA_TABLE_ENTRY* dte = (MY_LDR_DATA_TABLE_ENTRY*)ldr->InLoadOrderModuleList.Flink;
        dte->DllBase != 0 && api_addr == NULL;
        dte = (MY_LDR_DATA_TABLE_ENTRY*)dte->InLoadOrderLinks.Flink) {
        LPVOID dll_base = dte->DllBase;
        api_addr = search_exp_function(dll_base, dll_hash, fnc_hash);
    }
    return api_addr;
}

#define KERNEL32_DLL_HASH 0x50bb715e
#define GET_PROC_ADDRESS_HASH 0xe553e06f

void test_resolve_api_addr(const char* dll_name,
    const char* fnc_name) {
    HMODULE dll_base = LoadLibraryA(dll_name);
    LPVOID api_addr0 = NULL;
    if (dll_base) {
		api_addr0 = GetProcAddress(dll_base, fnc_name);
    }

    LPVOID api_addr1 = resolve_api_addr(calc_dll_hash(dll_name, (uint32_t)strlen(dll_name) + 1),
        calc_fnc_hash(fnc_name, (uint32_t)strlen(fnc_name) + 1));

    if (api_addr0 == api_addr1) {
        puts("OK");
    }
    else {
        puts("NG");
    }
}

typedef NTSTATUS (NTAPI* pNtAlloateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect
);
pNtAlloateVirtualMemory fnNtAlloateVirtualMemory = NULL;

typedef NTSTATUS (NTAPI* pNtFlushInstructionCache)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	ULONG NumberOfBytesToFlush
);
pNtFlushInstructionCache fnNtFlushInstructionCache = NULL;

typedef NTSTATUS (NTAPI* pLdrLoadDll)(
	ULONGLONG PathToFile,
	PULONG Flags,
	PUNICODE_STRING ModuleFileName,
	PHANDLE ModuleHandle
);
pLdrLoadDll fnLdrLoadDll = NULL;

typedef NTSTATUS (NTAPI* pRtlUnicodeStringToAnsiString)(
	PANSI_STRING DestinationString,
	PUNICODE_STRING SourceString,
	BOOLEAN AllocateDestinationString
);
pRtlUnicodeStringToAnsiString fnRtlUnicodeStringToAnsiString = NULL;

typedef NTSTATUS (NTAPI* pRtlAnsiStringToUnicodeString)(
	PUNICODE_STRING DestinationString,
	PANSI_STRING SourceString,
	BOOLEAN AllocateDestinationString
);
pRtlAnsiStringToUnicodeString fnRtlAnsiStringToUnicodeString = NULL;

typedef void (NTAPI* pRtlInitAnsiString)(
	PANSI_STRING DestinationString,
	PSZ SourceString
);
pRtlInitAnsiString fnRtlInitAnsiString = NULL;

typedef void (NTAPI* pRtlFreeAnsiString)(PANSI_STRING AnsiString);
pRtlFreeAnsiString fnRtlFreeAnsiString = NULL;

typedef void (NTAPI* pRtlFreeUnicodeString)(PUNICODE_STRING UnicodeString);
pRtlFreeUnicodeString fnRtlFreeUnicodeString = NULL;

typedef NTSTATUS (NTAPI* pLdrGetProcedureAddressForCaller)(
	HMODULE       ModuleHandle,
	PANSI_STRING  FunctionName,
	WORD          Oridinal,
	PVOID        *FunctionAddress,
	BOOL          bValue,
	PVOID         CallbackAddress
);
pLdrGetProcedureAddressForCaller fnLdrGetProcedureAddressForCaller;

typedef int (WINAPI* pMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
pMessageBoxA fnMessageBoxA = NULL;

void show_all_hashes() {
    show_hashes("user32.dll", "MessageBoxA");
    show_hashes("ntdll.dll", "NtAlloateVirtualMemory");
    show_hashes("ntdll.dll", "NtFlushInstructionCache");
    show_hashes("ntdll.dll", "LdrLoadDll");
    show_hashes("ntdll.dll", "RtlUnicodeStringToAnsiString");
    show_hashes("ntdll.dll", "RtlAnsiStringToUnicodeString");
    show_hashes("ntdll.dll", "RtlInitAnsiString");
    show_hashes("ntdll.dll", "RtlFreeUnicodeString");
}

#define USER32_DLL_HASH 0x1031956f
#define MESSAGE_BOXA_HASH 0x1545e26d

#define NT_DLL_HASH 0xdf956ba6
#define NT_ALLOCATE_VIRTUAL_MEMORY_HASH 0x9b8819a3
#define NT_FLUSH_INSTRUCTION_CACHE_HASH 0x55c29a60
#define LDR_LOAD_DLL_HASH 0x7f2584c4
#define RTL_UNICODE_STRING_TO_ANSI_STRING_HASH 0xedb43455
#define RTL_ANSI_STRING_TO_UNICODE_STRING_HASH 0x1c4f5b64
#define RTL_INIT_ANSI_STRING_HASH 0x41ebe619
#define RTL_FREE_UNICODE_STRING   0x01554596

void resolve_all_apis() {
    fnMessageBoxA = resolve_api_addr(USER32_DLL_HASH, MESSAGE_BOXA_HASH);
    fnNtAlloateVirtualMemory = resolve_api_addr(NT_DLL_HASH, NT_ALLOCATE_VIRTUAL_MEMORY_HASH);
    fnNtFlushInstructionCache = resolve_api_addr(NT_DLL_HASH, NT_FLUSH_INSTRUCTION_CACHE_HASH);
    fnLdrLoadDll = resolve_api_addr(NT_DLL_HASH, LDR_LOAD_DLL_HASH);
    fnRtlUnicodeStringToAnsiString = resolve_api_addr(NT_DLL_HASH, RTL_UNICODE_STRING_TO_ANSI_STRING_HASH);
    fnRtlAnsiStringToUnicodeString = resolve_api_addr(NT_DLL_HASH, RTL_ANSI_STRING_TO_UNICODE_STRING_HASH);
    fnRtlInitAnsiString = resolve_api_addr(NT_DLL_HASH, RTL_INIT_ANSI_STRING_HASH);
    fnRtlFreeUnicodeString = resolve_api_addr(NT_DLL_HASH, RTL_FREE_UNICODE_STRING);
}

int main() {
    LoadLibraryA("user32.dll"); // to use MessageBoxA

    // show_all_hashes();
    resolve_all_apis();
    fnMessageBoxA(NULL, "Hello", "Hello", MB_OK);
    return EXIT_SUCCESS;
}