#include <iostream>
#include <windows.h>

#include <Psapi.h>
#include <TlHelp32.h>

BOOL GrantPriviledge(LPCWSTR PriviledgeName);
BOOL FindProcessByName(IN PCWSTR szExeFile, OUT DWORD& pid);
HMODULE FindModuleHandleByFullPath(IN DWORD pid, IN PCWSTR szModulePath);

wchar_t buffer[] = L"D:\\Projects\\InjectDll\\x64\\Debug\\LoadRemoteDll.dll";

int main()
{
    if (!GrantPriviledge(SE_DEBUG_NAME)) {
        std::cout << "GrantPriviledge Failed...\n";
        return 1;
    }

    DWORD pid = 0;
    if (!FindProcessByName(L"calc.exe", pid)) {
        std::cout << "FindProcessByName Failed...\n";
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess) {
        HMODULE hModule = FindModuleHandleByFullPath(pid, buffer);
        if (hModule) {
            auto FreeLibraryAddress = (LPTHREAD_START_ROUTINE)::GetProcAddress(GetModuleHandle(L"Kernel32"), "FreeLibrary");
            HANDLE hThread = ::CreateRemoteThread(hProcess, NULL, 0, FreeLibraryAddress, hModule, 0, NULL); // 创建线程
            if (hThread) {
                WaitForSingleObject(hThread, INFINITE);
                CloseHandle(hThread);
            }
            CloseHandle(hModule);
        }
        CloseHandle(hProcess);
    }

    std::getchar();
    return 0;
}

BOOL GrantPriviledge(LPCWSTR PriviledgeName)
{
    HANDLE TokenHandle = NULL;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &TokenHandle)) {
        if (GetLastError() != ERROR_NO_TOKEN) {
            return FALSE;
        }
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle)) {
            return FALSE;
        }
    }

    LUID uID;
    if (!LookupPrivilegeValue(NULL, PriviledgeName, &uID)) {
        CloseHandle(TokenHandle);
        return FALSE;
    }

    TOKEN_PRIVILEGES TokenPrivileges, OldPrivileges;
    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    TokenPrivileges.Privileges[0].Luid = uID;

    DWORD dwReturnLength = sizeof(OldPrivileges);
    if (!AdjustTokenPrivileges(TokenHandle, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), &OldPrivileges, &dwReturnLength)) {
        CloseHandle(TokenHandle);
        return FALSE;
    }

    CloseHandle(TokenHandle);
    return TRUE;
}

BOOL FindProcessByName(IN PCWSTR szExeFile, OUT DWORD& pid)
{
    auto hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    pid = 0;
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (::Process32First(hSnapshot, &pe)) {
        do { // 遍历进程
            if (_wcsicmp(pe.szExeFile, szExeFile) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (::Process32Next(hSnapshot, &pe));
    }
    ::CloseHandle(hSnapshot);
    return pid > 0;
}

HMODULE FindModuleHandleByFullPath(IN DWORD pid, IN PCWSTR szModulePath)
{
    DWORD cbNeeded;
    HMODULE lphModule[1024] = { 0 };

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    EnumProcessModules(hProcess, lphModule, sizeof(lphModule), &cbNeeded);
    DWORD dwProcessCount = cbNeeded / sizeof(HMODULE);

    wchar_t path[MAX_PATH];
    for (DWORD i = 0; i < dwProcessCount; ++i) {
        ZeroMemory(path, MAX_PATH);
        GetModuleFileNameEx(hProcess, lphModule[i], path, MAX_PATH);
        // GetModuleBaseNameA(hProcess, lphModule[i], path, MAX_PATH);
        if (wcscmp(path, szModulePath) == 0) {
            return lphModule[i];
        }
    }
    CloseHandle(hProcess);

    return NULL;
}
