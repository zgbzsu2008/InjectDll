#include "DllInject.hpp"

#include <TlHelp32.h>
#include <Psapi.h>

BOOL GrantPriviledge(WCHAR* PriviledgeName)
{
    TOKEN_PRIVILEGES TokenPrivileges, OldPrivileges;
    DWORD dwReturnLength = sizeof(OldPrivileges);
    HANDLE TokenHandle = NULL;
    LUID uID;

    // CurrentThread权限令牌
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &TokenHandle))
    {
        if (GetLastError() != ERROR_NO_TOKEN)
        {
            return FALSE;
        }
        // CurrentProcess权限令牌
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle))
        {
            return FALSE;
        }
    }

    // 通过权限名称查找uID
    if (!LookupPrivilegeValue(NULL, PriviledgeName, &uID))
    {
        CloseHandle(TokenHandle);
        return FALSE;
    }

    TokenPrivileges.PrivilegeCount = 1; // 要提升的权限个数
    TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // 动态数组，数组大小根据Count的数目
    TokenPrivileges.Privileges[0].Luid = uID;

    // 在这里我们进行调整权限
    if (!AdjustTokenPrivileges(TokenHandle, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), &OldPrivileges, &dwReturnLength))
    {
        CloseHandle(TokenHandle);
        return FALSE;
    }

    CloseHandle(TokenHandle);
    return TRUE;
}

BOOL GrantPriviledge(IN UINT32 Priviledge)
{
    BOOLEAN WasEnable = FALSE;
    pfnRtlAdjustPrivilege RtlAdjustPrivilege = NULL;

    RtlAdjustPrivilege = (pfnRtlAdjustPrivilege)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlAdjustPrivilege");
    if (RtlAdjustPrivilege == NULL)
    {
        return FALSE;
    }

    RtlAdjustPrivilege(Priviledge, TRUE, FALSE, &WasEnable);

    return TRUE;
}

BOOL FindProcessByName(IN PCWSTR szExeFile, OUT DWORD& pid)
{
    auto hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    pid = 0;
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (::Process32First(hSnapshot, &pe))
    {
        do
        { // 遍历进程
            if (_wcsicmp(pe.szExeFile, szExeFile) == 0)
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (::Process32Next(hSnapshot, &pe));
    }
    ::CloseHandle(hSnapshot);
    return pid > 0;
}

BOOL FindProcessByFullPath(IN LPCSTR szExeFilePath, OUT DWORD& pid)
{
    DWORD lpidProcess[1000] = { 0 };
    DWORD cbNeeded;
    pid = 0;

    EnumProcesses(lpidProcess, sizeof(lpidProcess), &cbNeeded);
    DWORD dwProcessCount = cbNeeded / sizeof(DWORD);

    char path[MAX_PATH];
    for (DWORD i = 0; i < dwProcessCount; ++i)
    {
        ZeroMemory(path, MAX_PATH);
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lpidProcess[i]);
        GetProcessImageFileNameA(hProcess, path, MAX_PATH);
        CloseHandle(hProcess);

        if (!strcmp(szExeFilePath, path))
        {
            pid = lpidProcess[i];
            break;
        }
    }

    return pid > 0;
}

BOOL FindModuleHandleByName(IN DWORD pid, IN PCWSTR szModule, OUT HMODULE& hModule)
{
    auto hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPALL, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    hModule = NULL;
    MODULEENTRY32 me = { sizeof(me) };
    if (::Module32First(hSnapshot, &me))
    {
        do
        {
            // 遍历进程
            if (_wcsicmp(me.szModule, szModule) == 0)
            {
                hModule = me.hModule;
                break;
            }
        } while (::Module32Next(hSnapshot, &me));
    }

    if (hModule == NULL)
    {
        return FALSE;
    }

    return true;
}

BOOL FindModuleHandleByFullPath(IN DWORD pid, IN PCSTR szModulePath, OUT HMODULE& hModule)
{
    DWORD cbNeeded;
    HMODULE lphModule[1024] = { 0 };
    hModule = NULL;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    EnumProcessModules(hProcess, lphModule, sizeof(lphModule), &cbNeeded);
    DWORD dwProcessCount = cbNeeded / sizeof(HMODULE);

    char path[MAX_PATH];
    for (DWORD i = 0; i < dwProcessCount; ++i)
    {
        ZeroMemory(path, MAX_PATH);
        GetModuleFileNameExA(hProcess, hModule, path, MAX_PATH);
        // GetModuleBaseNameA(hProcess, lphModule[i], path, MAX_PATH);
        if (strcmp(path, szModulePath) == 0)
        {
            hModule = lphModule[i];
            break;
        }
    }
    CloseHandle(hProcess);

    return hModule != NULL;
}


BOOL GetThreadIdByProcessId(IN DWORD ProcessId, OUT std::vector<DWORD>& tids)
{
    HANDLE hSnapshot = NULL;
    THREADENTRY32 te = { sizeof(te) };
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    if (Thread32First(hSnapshot, &te))
    {
        do
        { // 遍历线程
            if (te.th32OwnerProcessID == ProcessId)
            {
                tids.push_back(te.th32ThreadID); // 保存tid
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);
    return TRUE;
}

BOOL DosPathToNtPath(LPCSTR pszDosPath, LPSTR pszNtPath)
{
    CHAR szDriveStr[500];
    CHAR szDrive[3];
    CHAR szDevName[100];
    int cchDevName;

    if (pszDosPath == NULL || pszNtPath == NULL)
    {
        return FALSE;
    }

    // 获取本地磁盘字符串
    if (GetLogicalDriveStringsA(sizeof(szDriveStr), szDriveStr))
    {
        for (int i = 0; szDriveStr[i]; i += 4)
        {
            if (strcmp(&(szDriveStr[i]), "A:\\") == 0 || strcmp(&(szDriveStr[i]), "B:\\") == 0)
            {
                continue;
            }

            szDrive[0] = szDriveStr[i];
            szDrive[1] = szDriveStr[i + 1];
            szDrive[2] = 0;

            // 查询Dos设备名
            if (!QueryDosDeviceA(szDrive, szDevName, 100))
            {
                return FALSE;
            }

            cchDevName = strlen(szDevName);
            if (_strnicmp(pszDosPath, szDevName, cchDevName) == 0)// 命中  
            {
                strcpy(pszNtPath, szDrive);
                strcat(pszNtPath, pszDosPath + cchDevName);

                return TRUE;
            }
        }
    }

    strcpy(pszNtPath, pszDosPath);

    return FALSE;
}