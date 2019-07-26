#include <windows.h>
#include <TlHelp32.h>

#include <iostream>
#include <vector>

bool FindProcess(PCWSTR exeName, DWORD& pid, std::vector<DWORD>& tids)
{
    auto hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    pid = 0;
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (::Process32First(hSnapshot, &pe)) {
        do { // 遍历进程
            if (_wcsicmp(pe.szExeFile, exeName) == 0) {
                pid = pe.th32ProcessID;
                THREADENTRY32 te = { sizeof(te) };
                if (::Thread32First(hSnapshot, &te)) {
                    do { // 遍历线程
                        if (te.th32OwnerProcessID == pid) {
                            tids.push_back(te.th32ThreadID);
                        }
                    } while (::Thread32Next(hSnapshot, &te));
                }
                break;
            }
        } while (::Process32Next(hSnapshot, &pe));
    }
    ::CloseHandle(hSnapshot);
    return pid > 0 && !tids.empty();
}

wchar_t buffer[] = L"D:\\Projects\\InjectDll\\x64\\Debug\\NormalDll.dll";

int main()
{
    DWORD pid;
    std::vector<DWORD> tids;
    if (!FindProcess(L"calc.exe", pid, tids)) {
        std::cout << "FindProcess Failed...\n";
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess) 
    {
        auto len = sizeof(buffer) + 1;
        auto p = VirtualAllocEx(hProcess, nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        WriteProcessMemory(hProcess, p, buffer, len, nullptr);
        for (const auto& tid : tids) {
            HANDLE hThread = OpenThread(PROCESS_ALL_ACCESS, FALSE, tid);
            if (hThread) {
                QueueUserAPC((PAPCFUNC)::GetProcAddress(GetModuleHandle(L"kernel32"), "LoadLibraryW"), hThread, (ULONG_PTR)p);
                CloseHandle(hThread);
            }
        }
        VirtualFreeEx(hProcess, p, 0, MEM_RELEASE | MEM_DECOMMIT);
        CloseHandle(hProcess);
    }

    std::cin.get();
    return 0;
}
