#include <iostream>
#include <windows.h>

#include <Psapi.h>
#include <TlHelp32.h>

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef NTSTATUS(NTAPI* pfnRtlCreateUserThread)(
    IN HANDLE ProcessHandle,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    IN BOOLEAN CreateSuspended,
    IN ULONG StackZeroBits OPTIONAL,
    IN SIZE_T StackReserve OPTIONAL,
    IN SIZE_T StackCommit OPTIONAL,
    IN PTHREAD_START_ROUTINE StartAddress,
    IN PVOID Parameter OPTIONAL,
    OUT PHANDLE ThreadHandle OPTIONAL,
    OUT PCLIENT_ID ClientId OPTIONAL); // RtlCreateUserThread

BOOL GrantPriviledge(LPCWSTR PriviledgeName);
BOOL FindProcessByName(IN PCWSTR szExeFile, OUT DWORD& pid);

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
        UINT32 len = sizeof(buffer) + 1;
        auto p = VirtualAllocEx(hProcess, nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        SIZE_T returnLen;
        WriteProcessMemory(hProcess, p, buffer, len, &returnLen);

        auto LoadLibraryAddress = (LPTHREAD_START_ROUTINE)::GetProcAddress(GetModuleHandle(L"Kernel32"), "LoadLibraryW");

       HANDLE hThread = NULL;
        auto RtlCreateUserThread = (pfnRtlCreateUserThread)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlCreateUserThread");
        NTSTATUS Status = RtlCreateUserThread(hProcess, NULL, FALSE, 0, 0, 0, LoadLibraryAddress, p, &hThread, NULL);
        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }
        VirtualFreeEx(hProcess, p, 0, MEM_RELEASE | MEM_DECOMMIT);
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
        do { // ±éÀú½ø³Ì
            if (_wcsicmp(pe.szExeFile, szExeFile) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (::Process32Next(hSnapshot, &pe));
    }
    ::CloseHandle(hSnapshot);
    return pid > 0;
}
