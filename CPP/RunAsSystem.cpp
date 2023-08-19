
// RunAsSystem - RunAsSystem.cpp - by Michael Badichi


#include <Windows.h>
#include <Psapi.h>
#include <UserEnv.h>
#include <Shlwapi.h>
#include <sstream>

#pragma comment (lib, "Psapi")
#pragma comment (lib, "UserEnv")
#pragma comment (lib, "Shlwapi")


bool _SetPrivilege(std::wstring Privilege)
{
    bool retCode = false;
    HANDLE curProc = GetCurrentProcess();
    HANDLE hToken;
    if (OpenProcessToken(curProc, TOKEN_ALL_ACCESS, &hToken))
    {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        LookupPrivilegeValue(L"", Privilege.c_str(), &tp.Privileges[0].Luid);
        TOKEN_PRIVILEGES tpout;
        DWORD retLen = 0;
        BOOL stat = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tpout), &tpout, &retLen);
        DWORD lasterr = GetLastError();
        CloseHandle(hToken);
        retCode = (stat == TRUE);
    }
    return retCode;
}


bool IsProcessIdMatchingName(DWORD processID, std::wstring name)
{
    bool retCode = false;
    WCHAR szProcessName[MAX_PATH] = L"<unknown>";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess)
    {
        WCHAR path[MAX_PATH + FILENAME_MAX + 1];
        if (GetProcessImageFileName(hProcess, path, sizeof(path) / sizeof(path[0])))
        {
            WCHAR* fname = StrRChr(path, NULL, L'\\');
            if (fname)
            {
                fname++;
                retCode = (_wcsicmp(fname, name.c_str()) == 0);
            }
        }
        CloseHandle(hProcess);
    }
    return retCode;
}


DWORD GetProcessIdByName(std::wstring name, DWORD sessionID)
{
    DWORD retCode = 0;
    DWORD aProcesses[16 * 1024];
    DWORD cbNeeded;
    unsigned int i;
    if (EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        DWORD cProcesses = cbNeeded / sizeof(DWORD);
        for (i = 0; i < cProcesses; i++)
        {
            if (aProcesses[i] != 0)
            {
                if (IsProcessIdMatchingName(aProcesses[i], name))
                {
                    DWORD sesID = 0;
                    if (ProcessIdToSessionId(aProcesses[i], &sesID))
                    {
                        if (sesID == sessionID)
                        {
                            //found it
                            retCode = aProcesses[i];
                            break;
                        }
                    }
                }
            }
        }
    }
    return retCode;
}


void RunAsSystem(const WCHAR* cmd_, DWORD* procDoneRetCode_ = NULL)
{
    std::wstring cmd = cmd_ ? cmd_ : L"";
    bool retCode = false;
    WCHAR* winlogon = L"winlogon.exe";
    WCHAR* privileges[] = {
        L"SeDebugPrivilege",
        L"SeAssignPrimaryTokenPrivilege",
        L"SeIncreaseQuotaPrivilege"
    };

    for (int i = 0; i < sizeof(privileges) / sizeof(privileges[0]); i++) {
        _SetPrivilege(privileges[i]);
    }

    DWORD sessionID = WTSGetActiveConsoleSessionId();
    if (sessionID != 0xFFFFFFFF)
    {
        DWORD processId = GetProcessIdByName(winlogon, sessionID);
        if (processId)
        {
            HANDLE hProc = OpenProcess(0x001F0FFF, FALSE, processId);
            if (hProc != NULL)
            {
                HANDLE hToken;
                if (OpenProcessToken(hProc, TOKEN_DUPLICATE, &hToken))
                {
                    HANDLE hDupToken;
                    if (DuplicateTokenEx(hToken, 0x001F0FFF, NULL, SecurityIdentification, TokenPrimary, &hDupToken))
                    {
                        STARTUPINFO si = { 0 };
                        PROCESS_INFORMATION pi = { 0 };
                        si.cb = sizeof(si);
                        si.lpDesktop = L"winsta0\\default";

                        typedef BOOL(WINAPI* CreateProcessWithTokenW_proto) (HANDLE hToken, DWORD dwLogonFlags, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
                        CreateProcessWithTokenW_proto CreateProcessWithTokenW_fn = NULL;
                        HMODULE hMod = LoadLibrary(L"ADVAPI32.dll");
                        if (hMod)
                        {
                            CreateProcessWithTokenW_fn = (CreateProcessWithTokenW_proto)GetProcAddress(hMod, "CreateProcessWithTokenW");
                        }

                        if (CreateProcessWithTokenW_fn == NULL || !CreateProcessWithTokenW_fn(hDupToken, LOGON_WITH_PROFILE, NULL, (LPWSTR)cmd.c_str(), NULL, NULL, NULL, &si, &pi))
                        {
                            //failed crating with token, try create as user
                            CreateProcessAsUserW(hDupToken, NULL, (LPWSTR)cmd.c_str(), NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi);
                        }
                        CloseHandle(hDupToken);
                    }
                    CloseHandle(hToken);
                }
                CloseHandle(hProc);
            }
        }
    }
}
