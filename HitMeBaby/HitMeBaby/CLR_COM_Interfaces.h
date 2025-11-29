#pragma once

#include <Windows.h>
#include <unknwn.h>

// ========================================
// Manual COM Interface Definitions
// (No mscorlib.tlb required!)
// ========================================

// Forward declarations
interface IUnknown;
interface _AppDomain;
interface _Assembly;
interface _MethodInfo;
interface _Type;

// ========================================
// GUIDs for .NET COM Interfaces
// ========================================

// IID for _AppDomain
// {05F696DC-2B29-3663-AD8B-C4389CF2A713}
static const IID IID_AppDomain =
{ 0x05F696DC, 0x2B29, 0x3663, { 0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13 } };

// IID for _Assembly
// {17156360-2F1A-384A-BC52-FDE93C215C5B}
static const IID IID_Assembly =
{ 0x17156360, 0x2F1A, 0x384A, { 0xBC, 0x52, 0xFD, 0xE9, 0x3C, 0x21, 0x5C, 0x5B } };

// IID for _MethodInfo
// {FFCC1B5D-ECB8-38DD-9B01-3DC8ABC2AA5F}
static const IID IID_MethodInfo =
{ 0xFFCC1B5D, 0xECB8, 0x38DD, { 0x9B, 0x01, 0x3D, 0xC8, 0xAB, 0xC2, 0xAA, 0x5F } };

// IID for _Type
// {BCA8B44D-AAD6-3A86-8AB7-03349F4F2DA2}
static const IID IID_Type =
{ 0xBCA8B44D, 0xAAD6, 0x3A86, { 0x8A, 0xB7, 0x03, 0x34, 0x9F, 0x4F, 0x2D, 0xA2 } };

// ========================================
// _AppDomain Interface
// ========================================

#undef INTERFACE
#define INTERFACE _AppDomain
DECLARE_INTERFACE_(_AppDomain, IUnknown)
{
    // IUnknown methods
    STDMETHOD(QueryInterface)(THIS_ REFIID riid, void** ppvObject) PURE;
    STDMETHOD_(ULONG, AddRef)(THIS) PURE;
    STDMETHOD_(ULONG, Release)(THIS) PURE;

    // IDispatch methods (we skip these for brevity)
    STDMETHOD(GetTypeInfoCount)(THIS_ UINT * pctinfo) PURE;
    STDMETHOD(GetTypeInfo)(THIS_ UINT iTInfo, LCID lcid, ITypeInfo * *ppTInfo) PURE;
    STDMETHOD(GetIDsOfNames)(THIS_ REFIID riid, LPOLESTR * rgszNames, UINT cNames, LCID lcid, DISPID * rgDispId) PURE;
    STDMETHOD(Invoke)(THIS_ DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS * pDispParams, VARIANT * pVarResult, EXCEPINFO * pExcepInfo, UINT * puArgErr) PURE;

    // _AppDomain methods
    STDMETHOD(get_ToString)(THIS_ BSTR * pRetVal) PURE;
    STDMETHOD(Equals)(THIS_ VARIANT other, VARIANT_BOOL * pRetVal) PURE;
    STDMETHOD(GetHashCode)(THIS_ long* pRetVal) PURE;
    STDMETHOD(GetType)(THIS_ _Type * *pRetVal) PURE;
    STDMETHOD(InitializeLifetimeService)(THIS_ VARIANT * pRetVal) PURE;
    STDMETHOD(GetLifetimeService)(THIS_ VARIANT * pRetVal) PURE;
    STDMETHOD(get_Evidence)(THIS_ IUnknown * *pRetVal) PURE;
    STDMETHOD(add_DomainUnload)(THIS_ IUnknown * value) PURE;
    STDMETHOD(remove_DomainUnload)(THIS_ IUnknown * value) PURE;
    STDMETHOD(add_AssemblyLoad)(THIS_ IUnknown * value) PURE;
    STDMETHOD(remove_AssemblyLoad)(THIS_ IUnknown * value) PURE;
    STDMETHOD(add_ProcessExit)(THIS_ IUnknown * value) PURE;
    STDMETHOD(remove_ProcessExit)(THIS_ IUnknown * value) PURE;
    STDMETHOD(add_TypeResolve)(THIS_ IUnknown * value) PURE;
    STDMETHOD(remove_TypeResolve)(THIS_ IUnknown * value) PURE;
    STDMETHOD(add_ResourceResolve)(THIS_ IUnknown * value) PURE;
    STDMETHOD(remove_ResourceResolve)(THIS_ IUnknown * value) PURE;
    STDMETHOD(add_AssemblyResolve)(THIS_ IUnknown * value) PURE;
    STDMETHOD(remove_AssemblyResolve)(THIS_ IUnknown * value) PURE;
    STDMETHOD(add_UnhandledException)(THIS_ IUnknown * value) PURE;
    STDMETHOD(remove_UnhandledException)(THIS_ IUnknown * value) PURE;
    STDMETHOD(DefineDynamicAssembly)(THIS_ BSTR name, int access, _Assembly * *pRetVal) PURE;
    STDMETHOD(DefineDynamicAssembly_2)(THIS_ BSTR name, int access, BSTR dir, _Assembly * *pRetVal) PURE;
    STDMETHOD(DefineDynamicAssembly_3)(THIS_ BSTR name, int access, IUnknown * evidence, _Assembly * *pRetVal) PURE;
    STDMETHOD(DefineDynamicAssembly_4)(THIS_ BSTR name, int access, IUnknown * requiredPermissions, IUnknown * optionalPermissions, IUnknown * refusedPermissions, _Assembly * *pRetVal) PURE;
    STDMETHOD(DefineDynamicAssembly_5)(THIS_ BSTR name, int access, BSTR dir, IUnknown * evidence, _Assembly * *pRetVal) PURE;
    STDMETHOD(DefineDynamicAssembly_6)(THIS_ BSTR name, int access, BSTR dir, IUnknown * requiredPermissions, IUnknown * optionalPermissions, IUnknown * refusedPermissions, _Assembly * *pRetVal) PURE;
    STDMETHOD(DefineDynamicAssembly_7)(THIS_ BSTR name, int access, IUnknown * evidence, IUnknown * requiredPermissions, IUnknown * optionalPermissions, IUnknown * refusedPermissions, _Assembly * *pRetVal) PURE;
    STDMETHOD(DefineDynamicAssembly_8)(THIS_ BSTR name, int access, BSTR dir, IUnknown * evidence, IUnknown * requiredPermissions, IUnknown * optionalPermissions, IUnknown * refusedPermissions, _Assembly * *pRetVal) PURE;
    STDMETHOD(DefineDynamicAssembly_9)(THIS_ BSTR name, int access, BSTR dir, IUnknown * evidence, IUnknown * requiredPermissions, IUnknown * optionalPermissions, IUnknown * refusedPermissions, VARIANT_BOOL isSynchronized, _Assembly * *pRetVal) PURE;
    STDMETHOD(CreateInstance)(THIS_ BSTR assemblyName, BSTR typeName, VARIANT * pRetVal) PURE;
    STDMETHOD(CreateInstanceFrom)(THIS_ BSTR assemblyFile, BSTR typeName, VARIANT * pRetVal) PURE;
    STDMETHOD(CreateInstance_2)(THIS_ BSTR assemblyName, BSTR typeName, SAFEARRAY * activationAttributes, VARIANT * pRetVal) PURE;
    STDMETHOD(CreateInstanceFrom_2)(THIS_ BSTR assemblyFile, BSTR typeName, SAFEARRAY * activationAttributes, VARIANT * pRetVal) PURE;
    STDMETHOD(CreateInstance_3)(THIS_ BSTR assemblyName, BSTR typeName, VARIANT_BOOL ignoreCase, int bindingAttr, IUnknown * Binder, SAFEARRAY * args, IUnknown * culture, SAFEARRAY * activationAttributes, IUnknown * securityAttributes, VARIANT * pRetVal) PURE;
    STDMETHOD(CreateInstanceFrom_3)(THIS_ BSTR assemblyFile, BSTR typeName, VARIANT_BOOL ignoreCase, int bindingAttr, IUnknown * Binder, SAFEARRAY * args, IUnknown * culture, SAFEARRAY * activationAttributes, IUnknown * securityAttributes, VARIANT * pRetVal) PURE;
    STDMETHOD(Load)(THIS_ BSTR assemblyString, _Assembly * *pRetVal) PURE;
    STDMETHOD(Load_2)(THIS_ BSTR rawAssemblyName, _Assembly * *pRetVal) PURE;
    STDMETHOD(Load_3)(THIS_ SAFEARRAY * rawAssembly, _Assembly * *pRetVal) PURE;  // ← This is what we need!
    STDMETHOD(Load_4)(THIS_ SAFEARRAY * rawAssembly, SAFEARRAY * rawSymbolStore, _Assembly * *pRetVal) PURE;
    STDMETHOD(Load_5)(THIS_ SAFEARRAY * rawAssembly, SAFEARRAY * rawSymbolStore, IUnknown * securityEvidence, _Assembly * *pRetVal) PURE;
    STDMETHOD(Load_6)(THIS_ BSTR assemblyString, IUnknown * assemblySecurity, _Assembly * *pRetVal) PURE;
    STDMETHOD(Load_7)(THIS_ BSTR rawAssemblyName, IUnknown * assemblySecurity, _Assembly * *pRetVal) PURE;
    STDMETHOD(ExecuteAssembly)(THIS_ BSTR assemblyFile, IUnknown * assemblySecurity, long* pRetVal) PURE;
    STDMETHOD(ExecuteAssembly_2)(THIS_ BSTR assemblyFile, long* pRetVal) PURE;
    STDMETHOD(ExecuteAssembly_3)(THIS_ BSTR assemblyFile, IUnknown * assemblySecurity, SAFEARRAY * args, long* pRetVal) PURE;
    STDMETHOD(get_FriendlyName)(THIS_ BSTR * pRetVal) PURE;
    STDMETHOD(get_BaseDirectory)(THIS_ BSTR * pRetVal) PURE;
    STDMETHOD(get_RelativeSearchPath)(THIS_ BSTR * pRetVal) PURE;
    STDMETHOD(get_ShadowCopyFiles)(THIS_ VARIANT_BOOL * pRetVal) PURE;
    STDMETHOD(GetAssemblies)(THIS_ SAFEARRAY * *pRetVal) PURE;
    STDMETHOD(AppendPrivatePath)(THIS_ BSTR path) PURE;
    STDMETHOD(ClearPrivatePath)(THIS) PURE;
    STDMETHOD(SetShadowCopyPath)(THIS_ BSTR s) PURE;
    STDMETHOD(ClearShadowCopyPath)(THIS) PURE;
    STDMETHOD(SetCachePath)(THIS_ BSTR s) PURE;
    STDMETHOD(SetData)(THIS_ BSTR name, VARIANT data) PURE;
    STDMETHOD(GetData)(THIS_ BSTR name, VARIANT * pRetVal) PURE;
    STDMETHOD(SetAppDomainPolicy)(THIS_ IUnknown * domainPolicy) PURE;
    STDMETHOD(SetThreadPrincipal)(THIS_ IUnknown * principal) PURE;
    STDMETHOD(SetPrincipalPolicy)(THIS_ int policy) PURE;
    STDMETHOD(DoCallBack)(THIS_ IUnknown * theDelegate) PURE;
    STDMETHOD(get_DynamicDirectory)(THIS_ BSTR * pRetVal) PURE;
};

// ========================================
// _Assembly Interface
// ========================================

#undef INTERFACE
#define INTERFACE _Assembly
DECLARE_INTERFACE_(_Assembly, IUnknown)
{
    // IUnknown methods
    STDMETHOD(QueryInterface)(THIS_ REFIID riid, void** ppvObject) PURE;
    STDMETHOD_(ULONG, AddRef)(THIS) PURE;
    STDMETHOD_(ULONG, Release)(THIS) PURE;

    // IDispatch methods
    STDMETHOD(GetTypeInfoCount)(THIS_ UINT * pctinfo) PURE;
    STDMETHOD(GetTypeInfo)(THIS_ UINT iTInfo, LCID lcid, ITypeInfo * *ppTInfo) PURE;
    STDMETHOD(GetIDsOfNames)(THIS_ REFIID riid, LPOLESTR * rgszNames, UINT cNames, LCID lcid, DISPID * rgDispId) PURE;
    STDMETHOD(Invoke)(THIS_ DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS * pDispParams, VARIANT * pVarResult, EXCEPINFO * pExcepInfo, UINT * puArgErr) PURE;

    // _Assembly methods (simplified - only what we need)
    STDMETHOD(get_ToString)(THIS_ BSTR * pRetVal) PURE;
    STDMETHOD(Equals)(THIS_ VARIANT other, VARIANT_BOOL * pRetVal) PURE;
    STDMETHOD(GetHashCode)(THIS_ long* pRetVal) PURE;
    STDMETHOD(GetType)(THIS_ _Type * *pRetVal) PURE;
    STDMETHOD(get_CodeBase)(THIS_ BSTR * pRetVal) PURE;
    STDMETHOD(get_EscapedCodeBase)(THIS_ BSTR * pRetVal) PURE;
    STDMETHOD(GetName)(THIS_ IUnknown * *pRetVal) PURE;
    STDMETHOD(GetName_2)(THIS_ VARIANT_BOOL copiedName, IUnknown * *pRetVal) PURE;
    STDMETHOD(get_FullName)(THIS_ BSTR * pRetVal) PURE;
    STDMETHOD(get_EntryPoint)(THIS_ _MethodInfo * *pRetVal) PURE;  // ← This is what we need!
    STDMETHOD(GetType_2)(THIS_ BSTR name, _Type * *pRetVal) PURE;
    STDMETHOD(GetType_3)(THIS_ BSTR name, VARIANT_BOOL throwOnError, _Type * *pRetVal) PURE;
    STDMETHOD(GetExportedTypes)(THIS_ SAFEARRAY * *pRetVal) PURE;
    STDMETHOD(GetTypes)(THIS_ SAFEARRAY * *pRetVal) PURE;
    STDMETHOD(GetManifestResourceStream)(THIS_ _Type * type, BSTR name, IUnknown * *pRetVal) PURE;
    STDMETHOD(GetManifestResourceStream_2)(THIS_ BSTR name, IUnknown * *pRetVal) PURE;
    STDMETHOD(GetFile)(THIS_ BSTR name, IUnknown * *pRetVal) PURE;
    STDMETHOD(GetFiles)(THIS_ SAFEARRAY * *pRetVal) PURE;
    STDMETHOD(GetFiles_2)(THIS_ VARIANT_BOOL getResourceModules, SAFEARRAY * *pRetVal) PURE;
    STDMETHOD(GetManifestResourceNames)(THIS_ SAFEARRAY * *pRetVal) PURE;
    STDMETHOD(GetManifestResourceInfo)(THIS_ BSTR resourceName, IUnknown * *pRetVal) PURE;
    STDMETHOD(get_Location)(THIS_ BSTR * pRetVal) PURE;
    STDMETHOD(get_Evidence)(THIS_ IUnknown * *pRetVal) PURE;
    STDMETHOD(GetCustomAttributes)(THIS_ _Type * attributeType, VARIANT_BOOL inherit, SAFEARRAY * *pRetVal) PURE;
    STDMETHOD(GetCustomAttributes_2)(THIS_ VARIANT_BOOL inherit, SAFEARRAY * *pRetVal) PURE;
    STDMETHOD(IsDefined)(THIS_ _Type * attributeType, VARIANT_BOOL inherit, VARIANT_BOOL * pRetVal) PURE;
    STDMETHOD(GetObjectData)(THIS_ IUnknown * info, VARIANT context) PURE;
    STDMETHOD(add_ModuleResolve)(THIS_ IUnknown * value) PURE;
    STDMETHOD(remove_ModuleResolve)(THIS_ IUnknown * value) PURE;
    STDMETHOD(GetType_4)(THIS_ BSTR name, VARIANT_BOOL throwOnError, VARIANT_BOOL ignoreCase, _Type * *pRetVal) PURE;
    STDMETHOD(GetSatelliteAssembly)(THIS_ IUnknown * culture, _Assembly * *pRetVal) PURE;
    STDMETHOD(GetSatelliteAssembly_2)(THIS_ IUnknown * culture, IUnknown * Version, _Assembly * *pRetVal) PURE;
    STDMETHOD(LoadModule)(THIS_ BSTR moduleName, SAFEARRAY * rawModule, IUnknown * *pRetVal) PURE;
    STDMETHOD(LoadModule_2)(THIS_ BSTR moduleName, SAFEARRAY * rawModule, SAFEARRAY * rawSymbolStore, IUnknown * *pRetVal) PURE;
    STDMETHOD(CreateInstance)(THIS_ BSTR typeName, VARIANT * pRetVal) PURE;
    STDMETHOD(CreateInstance_2)(THIS_ BSTR typeName, VARIANT_BOOL ignoreCase, VARIANT * pRetVal) PURE;
    STDMETHOD(CreateInstance_3)(THIS_ BSTR typeName, VARIANT_BOOL ignoreCase, int bindingAttr, IUnknown * Binder, SAFEARRAY * args, IUnknown * culture, SAFEARRAY * activationAttributes, VARIANT * pRetVal) PURE;
    STDMETHOD(GetLoadedModules)(THIS_ SAFEARRAY * *pRetVal) PURE;
    STDMETHOD(GetLoadedModules_2)(THIS_ VARIANT_BOOL getResourceModules, SAFEARRAY * *pRetVal) PURE;
    STDMETHOD(GetModules)(THIS_ SAFEARRAY * *pRetVal) PURE;
    STDMETHOD(GetModules_2)(THIS_ VARIANT_BOOL getResourceModules, SAFEARRAY * *pRetVal) PURE;
    STDMETHOD(GetModule)(THIS_ BSTR name, IUnknown * *pRetVal) PURE;
    STDMETHOD(GetReferencedAssemblies)(THIS_ SAFEARRAY * *pRetVal) PURE;
    STDMETHOD(get_GlobalAssemblyCache)(THIS_ VARIANT_BOOL * pRetVal) PURE;
};

// ========================================
// _MethodInfo Interface
// ========================================

#undef INTERFACE
#define INTERFACE _MethodInfo
DECLARE_INTERFACE_(_MethodInfo, IUnknown)
{
    // IUnknown methods
    STDMETHOD(QueryInterface)(THIS_ REFIID riid, void** ppvObject) PURE;
    STDMETHOD_(ULONG, AddRef)(THIS) PURE;
    STDMETHOD_(ULONG, Release)(THIS) PURE;

    // IDispatch methods
    STDMETHOD(GetTypeInfoCount)(THIS_ UINT * pctinfo) PURE;
    STDMETHOD(GetTypeInfo)(THIS_ UINT iTInfo, LCID lcid, ITypeInfo * *ppTInfo) PURE;
    STDMETHOD(GetIDsOfNames)(THIS_ REFIID riid, LPOLESTR * rgszNames, UINT cNames, LCID lcid, DISPID * rgDispId) PURE;
    STDMETHOD(Invoke)(THIS_ DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS * pDispParams, VARIANT * pVarResult, EXCEPINFO * pExcepInfo, UINT * puArgErr) PURE;

    // _MethodInfo methods (simplified - only what we need)
    STDMETHOD(get_ToString)(THIS_ BSTR * pRetVal) PURE;
    STDMETHOD(Equals)(THIS_ VARIANT other, VARIANT_BOOL * pRetVal) PURE;
    STDMETHOD(GetHashCode)(THIS_ long* pRetVal) PURE;
    STDMETHOD(GetType)(THIS_ _Type * *pRetVal) PURE;
    STDMETHOD(get_MemberType)(THIS_ int* pRetVal) PURE;
    STDMETHOD(get_name)(THIS_ BSTR * pRetVal) PURE;
    STDMETHOD(get_DeclaringType)(THIS_ _Type * *pRetVal) PURE;
    STDMETHOD(get_ReflectedType)(THIS_ _Type * *pRetVal) PURE;
    STDMETHOD(GetCustomAttributes)(THIS_ _Type * attributeType, VARIANT_BOOL inherit, SAFEARRAY * *pRetVal) PURE;
    STDMETHOD(GetCustomAttributes_2)(THIS_ VARIANT_BOOL inherit, SAFEARRAY * *pRetVal) PURE;
    STDMETHOD(IsDefined)(THIS_ _Type * attributeType, VARIANT_BOOL inherit, VARIANT_BOOL * pRetVal) PURE;
    STDMETHOD(GetParameters)(THIS_ SAFEARRAY * *pRetVal) PURE;
    STDMETHOD(GetMethodImplementationFlags)(THIS_ int* pRetVal) PURE;
    STDMETHOD(get_MethodHandle)(THIS_ VARIANT * pRetVal) PURE;
    STDMETHOD(get_Attributes)(THIS_ int* pRetVal) PURE;
    STDMETHOD(get_CallingConvention)(THIS_ int* pRetVal) PURE;
    STDMETHOD(Invoke_2)(THIS_ VARIANT obj, int invokeAttr, IUnknown * Binder, SAFEARRAY * parameters, IUnknown * culture, VARIANT * pRetVal) PURE;
    STDMETHOD(get_IsPublic)(THIS_ VARIANT_BOOL * pRetVal) PURE;
    STDMETHOD(get_IsPrivate)(THIS_ VARIANT_BOOL * pRetVal) PURE;
    STDMETHOD(get_IsFamily)(THIS_ VARIANT_BOOL * pRetVal) PURE;
    STDMETHOD(get_IsAssembly)(THIS_ VARIANT_BOOL * pRetVal) PURE;
    STDMETHOD(get_IsFamilyAndAssembly)(THIS_ VARIANT_BOOL * pRetVal) PURE;
    STDMETHOD(get_IsFamilyOrAssembly)(THIS_ VARIANT_BOOL * pRetVal) PURE;
    STDMETHOD(get_IsStatic)(THIS_ VARIANT_BOOL * pRetVal) PURE;
    STDMETHOD(get_IsFinal)(THIS_ VARIANT_BOOL * pRetVal) PURE;
    STDMETHOD(get_IsVirtual)(THIS_ VARIANT_BOOL * pRetVal) PURE;
    STDMETHOD(get_IsHideBySig)(THIS_ VARIANT_BOOL * pRetVal) PURE;
    STDMETHOD(get_IsAbstract)(THIS_ VARIANT_BOOL * pRetVal) PURE;
    STDMETHOD(get_IsSpecialName)(THIS_ VARIANT_BOOL * pRetVal) PURE;
    STDMETHOD(get_IsConstructor)(THIS_ VARIANT_BOOL * pRetVal) PURE;
    STDMETHOD(Invoke_3)(THIS_ VARIANT obj, SAFEARRAY * parameters, VARIANT * pRetVal) PURE;  // ← This is what we need!
    STDMETHOD(get_returnType)(THIS_ _Type * *pRetVal) PURE;
    STDMETHOD(get_ReturnTypeCustomAttributes)(THIS_ IUnknown * *pRetVal) PURE;
    STDMETHOD(GetBaseDefinition)(THIS_ _MethodInfo * *pRetVal) PURE;
};