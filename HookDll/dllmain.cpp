// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"

HINSTANCE g_hInstance = nullptr;
HHOOK g_hHook = nullptr;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            g_hInstance = hModule;
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

LRESULT __stdcall KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    return CallNextHookEx(g_hHook, nCode, wParam, lParam);
}

#ifdef __cplusplus
extern "C"
{
#endif

    __declspec(dllexport) void StartHook(DWORD tid)
    {
        if (g_hHook == nullptr) {
            MessageBoxA(nullptr, "StartHook OK", "HookDll", MB_OK);
            g_hHook = SetWindowsHookEx(WH_KEYBOARD, KeyboardProc, g_hInstance, tid);
        }
    }

    __declspec(dllexport) void StopHook(DWORD /*tid*/)
    {
        if (g_hHook) {
            UnhookWindowsHookEx(g_hHook);
            g_hHook = nullptr;
            MessageBoxA(nullptr, "StopHook OK", "HookDll", MB_OK);
        }
    }

#ifdef __cplusplus
}
#endif
