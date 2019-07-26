#include <stdio.h>
#include <windows.h>
#include <vector>

typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)
(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID lpStartAddress,
    IN PVOID lpParameter,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits,
    IN SIZE_T SizeOfStackCommit,
    IN SIZE_T SizeOfStackReserve,
    OUT PVOID lpBytesBuffer); // NtCreateThreadEx

typedef
struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef
NTSTATUS(NTAPI * pfnRtlCreateUserThread)(
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

#define SE_DEBUG_PRIVILEGE  (20L)

typedef
NTSTATUS(NTAPI * pfnRtlAdjustPrivilege)(
    UINT32 Privilege,
    BOOLEAN Enable,
    BOOLEAN Client,
    PBOOLEAN WasEnabled); // RtlAdjustPrivilege

BOOL GrantPriviledge(WCHAR* PriviledgeName); // 参数 SE_DEBUG_NAME
BOOL GrantPriviledge(IN UINT32 Priviledge);  // 参数 SE_DEBUG_PRIVILEGE

BOOL FindProcessByName(IN PCWSTR szExeFile, OUT DWORD& pid);
BOOL FindProcessByFullPath(IN LPCSTR szExeFilePath, OUT DWORD& pid);
BOOL FindModuleHandleByName(IN DWORD pid, IN PCWSTR szModule, OUT HMODULE& hModule);
BOOL FindModuleHandleByFullPath(IN DWORD pid, IN PCSTR szModulePath, OUT HMODULE& hModule);
BOOL GetThreadIdByProcessId(IN DWORD ProcessId, OUT std::vector<DWORD>& tids);
BOOL DosPathToNtPath(LPCSTR pszDosPath, LPSTR pszNtPath);