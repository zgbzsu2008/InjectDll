// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"

DWORD CALLBACK FreeDll(LPARAM lParam);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    HANDLE hThread = nullptr;
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            hThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)FreeDll, hModule, 0, nullptr);
            if (hThread) {
                CloseHandle(hThread);
            }
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

DWORD CALLBACK FreeDll(LPARAM lParam)
{
    HMODULE moduleBase = (HMODULE)lParam;
    MessageBoxA(nullptr, "FreeDllByThread", "NormalDll", MB_OK);
    FreeLibraryAndExitThread(moduleBase, 0);
    return 0;
}

