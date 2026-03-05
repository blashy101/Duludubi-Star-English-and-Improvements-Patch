#include <windows.h>
#include <string>
#include "MinHook.h"

// --------------------
// Forward real dinput8
// --------------------
using DirectInput8Create_t = HRESULT(WINAPI*)(HINSTANCE, DWORD, REFIID, LPVOID*, LPUNKNOWN);

static HMODULE g_real = nullptr;
static DirectInput8Create_t g_DirectInput8Create = nullptr;

static void LoadRealDInput8()
{
    if (g_real)
        return;

    wchar_t sysdir[MAX_PATH];
    GetSystemDirectoryW(sysdir, MAX_PATH);

    std::wstring path = std::wstring(sysdir) + L"\\dinput8.dll";
    g_real = LoadLibraryW(path.c_str());
    if (!g_real)
        return;

    g_DirectInput8Create =
        (DirectInput8Create_t)GetProcAddress(g_real, "DirectInput8Create");
}

extern "C" __declspec(dllexport)
HRESULT WINAPI DirectInput8Create(
    HINSTANCE hinst,
    DWORD dwVersion,
    REFIID riid,
    LPVOID* ppvOut,
    LPUNKNOWN punkOuter)
{
    LoadRealDInput8();

    if (!g_DirectInput8Create)
        return E_FAIL;

    return g_DirectInput8Create(hinst, dwVersion, riid, ppvOut, punkOuter);
}

// --------------------
// Locale / codepage hooks (Simplified Chinese)
// --------------------

// CP936 = GBK (Simplified Chinese ANSI code page)
// LCID 0x0804 = Chinese (Simplified, PRC)

static const UINT kForcedACP = 936;
static const LCID kForcedLCID = 0x0804;

// Kernel32 exports we hook
using GetACP_t = UINT(WINAPI*)();
using GetOEMCP_t = UINT(WINAPI*)();
using MultiByteToWideChar_t =
int (WINAPI*)(UINT, DWORD, LPCCH, int, LPWSTR, int);
using WideCharToMultiByte_t =
int (WINAPI*)(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);

// Locale queries
using GetUserDefaultLCID_t = LCID(WINAPI*)();
using GetSystemDefaultLCID_t = LCID(WINAPI*)();
using GetThreadLocale_t = LCID(WINAPI*)();

static GetACP_t fpGetACP = nullptr;
static GetOEMCP_t fpGetOEMCP = nullptr;
static MultiByteToWideChar_t fpMultiByteToWideChar = nullptr;
static WideCharToMultiByte_t fpWideCharToMultiByte = nullptr;
static GetUserDefaultLCID_t fpGetUserDefaultLCID = nullptr;
static GetSystemDefaultLCID_t fpGetSystemDefaultLCID = nullptr;
static GetThreadLocale_t fpGetThreadLocale = nullptr;

static UINT WINAPI hkGetACP()
{
    return kForcedACP;
}

static UINT WINAPI hkGetOEMCP()
{
    return kForcedACP;
}

static int WINAPI hkMultiByteToWideChar(
    UINT CodePage,
    DWORD dwFlags,
    LPCCH lpMultiByteStr,
    int cbMultiByte,
    LPWSTR lpWideCharStr,
    int cchWideChar)
{
    // If the app asks for "system ANSI" or "OEM", force GBK/CP936
    if (CodePage == CP_ACP || CodePage == CP_OEMCP)
        CodePage = kForcedACP;

    return fpMultiByteToWideChar(
        CodePage,
        dwFlags,
        lpMultiByteStr,
        cbMultiByte,
        lpWideCharStr,
        cchWideChar);
}

static int WINAPI hkWideCharToMultiByte(
    UINT CodePage,
    DWORD dwFlags,
    LPCWCH lpWideCharStr,
    int cchWideChar,
    LPSTR lpMultiByteStr,
    int cbMultiByte,
    LPCCH lpDefaultChar,
    LPBOOL lpUsedDefaultChar)
{
    if (CodePage == CP_ACP || CodePage == CP_OEMCP)
        CodePage = kForcedACP;

    return fpWideCharToMultiByte(
        CodePage,
        dwFlags,
        lpWideCharStr,
        cchWideChar,
        lpMultiByteStr,
        cbMultiByte,
        lpDefaultChar,
        lpUsedDefaultChar);
}

static LCID WINAPI hkGetUserDefaultLCID()
{
    return kForcedLCID;
}

static LCID WINAPI hkGetSystemDefaultLCID()
{
    return kForcedLCID;
}

static LCID WINAPI hkGetThreadLocale()
{
    return kForcedLCID;
}

static void hook_api(LPCWSTR mod, LPCSTR name, LPVOID detour, LPVOID* orig)
{
    MH_CreateHookApi(mod, name, detour, orig);
}

static void InstallHooks()
{
    if (MH_Initialize() != MH_OK)
        return;

    hook_api(L"kernel32", "GetACP", (LPVOID)hkGetACP, (LPVOID*)&fpGetACP);
    hook_api(L"kernel32", "GetOEMCP", (LPVOID)hkGetOEMCP, (LPVOID*)&fpGetOEMCP);

    hook_api(
        L"kernel32",
        "MultiByteToWideChar",
        (LPVOID)hkMultiByteToWideChar,
        (LPVOID*)&fpMultiByteToWideChar);

    hook_api(
        L"kernel32",
        "WideCharToMultiByte",
        (LPVOID)hkWideCharToMultiByte,
        (LPVOID*)&fpWideCharToMultiByte);

    hook_api(
        L"kernel32",
        "GetUserDefaultLCID",
        (LPVOID)hkGetUserDefaultLCID,
        (LPVOID*)&fpGetUserDefaultLCID);

    hook_api(
        L"kernel32",
        "GetSystemDefaultLCID",
        (LPVOID)hkGetSystemDefaultLCID,
        (LPVOID*)&fpGetSystemDefaultLCID);

    hook_api(
        L"kernel32",
        "GetThreadLocale",
        (LPVOID)hkGetThreadLocale,
        (LPVOID*)&fpGetThreadLocale);

    MH_EnableHook(MH_ALL_HOOKS);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinstDLL);
        LoadRealDInput8();
        InstallHooks();
    }

    return TRUE;
}