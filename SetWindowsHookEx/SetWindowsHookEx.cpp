#include <iostream>
#include <vector>

#include <Windows.h>
#include <TlHelp32.h>

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

typedef void (*PFN_HOOKFUNC)(DWORD);

wchar_t buffer[] = L"D:\\Projects\\InjectDll\\x64\\Debug\\HookDll.dll";

int main()
{
    DWORD pid;
    std::vector<DWORD> tids;
    if (!FindProcess(L"calc.exe", pid, tids)) {
        std::cout << "FindProcess Failed...\n";
        return 1;
    }

    HMODULE hModule = LoadLibrary(buffer);
    if (hModule) {
        auto StartHook = (PFN_HOOKFUNC)GetProcAddress(hModule, "StartHook");
        if (StartHook) {
            for (auto tid : tids) {
                StartHook(tid);
                break;
            }
        }

        std::cout << "press any key to unhook...";
        std::getchar();

        auto StopHook = (PFN_HOOKFUNC)GetProcAddress(hModule, "StopHook");
        if (StopHook) {
            for (auto tid : tids) {
                StopHook(tid);
                break;
            }
        }
    }

    std::getchar();
    return 0;
}
