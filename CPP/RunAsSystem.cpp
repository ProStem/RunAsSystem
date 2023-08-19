// RunAsSystem - RunAsSystem.cpp - by Michael Badichi

#include <Windows.h>
#include <Psapi.h>
#include <UserEnv.h>
#include <Shlwapi.h>
#include <sstream>


#pragma comment (lib, "Psapi")
#pragma comment (lib, "UserEnv")
#pragma comment (lib, "Shlwapi")

void _SetPrivilege()
{
    HANDLE currentProcess = GetCurrentProcess();
    HANDLE tokenHandle;
    if (OpenProcessToken(currentProcess, TOKEN_ALL_ACCESS, &tokenHandle))
    {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        LookupPrivilegeValue(NULL, L"SeDebugPrivilege", &tp.Privileges[0].Luid);
        BOOL stat = AdjustTokenPrivileges(tokenHandle, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        CloseHandle(tokenHandle);
    }
}

bool IsProcessIdMatchingName(DWORD processID, std::wstring name)
{
    bool isMatchingName = false;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess)
    {
        WCHAR path[MAX_PATH + FILENAME_MAX + 1];
        if (GetProcessImageFileName(hProcess, path, sizeof(path) / sizeof(path[0])))
        {
            WCHAR* fileName = StrRChr(path, NULL, L'\\');
            if (fileName)
            {
                fileName++;
                isMatchingName = (_wcsicmp(fileName, name.c_str()) == 0);
            }
        }
        CloseHandle(hProcess);
    }
    return isMatchingName;
}

DWORD GetProcessIdByName(std::wstring name, DWORD sessionID)
{
    DWORD processID = 0;
    DWORD processesIDArray[16 * 1024];
    DWORD arrayLength;
    unsigned int i;
    if (EnumProcesses(processesIDArray, sizeof(processesIDArray), &arrayLength))
    {
        DWORD processCount = arrayLength / sizeof(DWORD);
        for (i = 0; i < processCount; i++)
        {
            if (processesIDArray[i] != 0)
            {
                if (IsProcessIdMatchingName(processesIDArray[i], name))
                {
                    DWORD sesID = 0;
                    if (ProcessIdToSessionId(processesIDArray[i], &sesID))
                    {
                        if (sesID == sessionID)
                        {
                            //found it
                            processID = processesIDArray[i];
                            break;
                        }
                    }
                }
            }
        }
    }
    return processID;
}

void RunAsSystem(const WCHAR* cmd_, DWORD* procDoneRetCode_ = NULL)
{
    std::wstring cmd = cmd_ ? cmd_ : L"";
    WCHAR* targetProcess = L"winlogon.exe";

    _SetPrivilege();

    DWORD sessionID = WTSGetActiveConsoleSessionId();
    if (sessionID != 0xFFFFFFFF)
    {
        DWORD processId = GetProcessIdByName(targetProcess, sessionID);
        if (processId)
        {
            HANDLE targetProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
            if (targetProcessHandle != NULL)
            {
                HANDLE targetProcessToken;
                if (OpenProcessToken(targetProcessHandle, TOKEN_DUPLICATE, &targetProcessToken))
                {
                    HANDLE impersonationToken;
                    if (DuplicateTokenEx(targetProcessToken, TOKEN_ALL_ACCESS, NULL, SecurityIdentification, TokenPrimary, &impersonationToken))
                    {
                        STARTUPINFO si = { 0 };
                        PROCESS_INFORMATION pi = { 0 };
                        si.cb = sizeof(si);
                        si.lpDesktop = L"winsta0\\default";

                        typedef BOOL(WINAPI* CreateProcessWithTokenW_proto) (HANDLE targetProcessToken, DWORD dwLogonFlags, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
                        CreateProcessWithTokenW_proto CreateProcessWithTokenW_fn = NULL;
                        HMODULE hMod = LoadLibrary(L"ADVAPI32.dll");
                        if (hMod)
                        {
                            CreateProcessWithTokenW_fn = (CreateProcessWithTokenW_proto)GetProcAddress(hMod, "CreateProcessWithTokenW");
                        }

                        if (CreateProcessWithTokenW_fn == NULL || !CreateProcessWithTokenW_fn(impersonationToken, LOGON_WITH_PROFILE, NULL, (LPWSTR)cmd.c_str(), NULL, NULL, NULL, &si, &pi))
                        {
                            //failed crating with token, try create as user
                            CreateProcessAsUserW(impersonationToken, NULL, (LPWSTR)cmd.c_str(), NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi);
                        }
                        CloseHandle(impersonationToken);
                    }
                    CloseHandle(targetProcessToken);
                }
                CloseHandle(targetProcessHandle);
            }
        }
    }
}
