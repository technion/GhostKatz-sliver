#include <windows.h>

typedef NTSTATUS(NTAPI* fnRtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

BOOL EnablePrivilege(ULONG priv)
{
    fnRtlAdjustPrivilege pRtlAdjustPrivilege = (fnRtlAdjustPrivilege)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAdjustPrivilege");
    if (!pRtlAdjustPrivilege) return FALSE;

    BOOLEAN old = FALSE;
    NTSTATUS status = pRtlAdjustPrivilege(priv, TRUE, FALSE, &old);
    if (FAILED(status))
    {
        return FALSE;
    }

    return TRUE;
}