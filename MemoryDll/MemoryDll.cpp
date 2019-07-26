// MemoryDll.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include <Windows.h>

#ifdef __cplusplus
extern "C"
{
#endif

    __declspec(dllexport) int MemoryDllFunc()
    {
        MessageBoxA(nullptr, "MemoryDll", "MemoryDll", MB_OK);
        return 0;
    }

#ifdef __cplusplus
}
#endif