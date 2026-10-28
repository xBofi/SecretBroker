# Shared settings and helpers for install.ps1 / uninstall.ps1

$InstallDir  = Join-Path $env:ProgramFiles "SecretBroker"
$DataRoot    = Join-Path $env:ProgramData "SecretBroker"
$ServiceUser = "SecretBroker"
$TaskName    = "SecretBroker Service"
$Python      = Join-Path $InstallDir "python\python.exe"
$PythonW     = Join-Path $InstallDir "python\pythonw.exe"

function Test-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Step($text) { Write-Host "`n==> $text" -ForegroundColor Cyan }

# Windows PowerShell 5.1 turns anything a native program writes to stderr into an error, which
# with $ErrorActionPreference = "Stop" aborts the script. Run native tools with "Continue" and
# judge them by their exit code instead.
function Invoke-Native([scriptblock]$Command) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { & $Command 2>&1 | ForEach-Object { "$_" } }
    finally { $ErrorActionPreference = $previous }
}

# Grant / revoke user rights (logon rights) through the LSA API.
if (-not ("SecretBrokerLsa" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class SecretBrokerLsa {
    [StructLayout(LayoutKind.Sequential)]
    struct LSA_UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)]
    struct LSA_OBJECT_ATTRIBUTES { public int Length; public IntPtr RootDirectory; public IntPtr ObjectName; public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }

    [DllImport("advapi32.dll")] static extern uint LsaOpenPolicy(IntPtr systemName, ref LSA_OBJECT_ATTRIBUTES attributes, uint access, out IntPtr handle);
    [DllImport("advapi32.dll")] static extern uint LsaAddAccountRights(IntPtr handle, byte[] sid, LSA_UNICODE_STRING[] rights, uint count);
    [DllImport("advapi32.dll")] static extern uint LsaRemoveAccountRights(IntPtr handle, byte[] sid, bool allRights, LSA_UNICODE_STRING[] rights, uint count);
    [DllImport("advapi32.dll")] static extern uint LsaClose(IntPtr handle);
    [DllImport("advapi32.dll")] static extern int LsaNtStatusToWinError(uint status);

    static byte[] Sid(string account) {
        var sid = (SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier));
        var bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);
        return bytes;
    }

    static IntPtr Open() {
        var attributes = new LSA_OBJECT_ATTRIBUTES();
        IntPtr handle;
        uint status = LsaOpenPolicy(IntPtr.Zero, ref attributes, 0x000F0FFF, out handle);
        if (status != 0) throw new Win32Exception(LsaNtStatusToWinError(status));
        return handle;
    }

    public static void Add(string account, string right) {
        var text = new LSA_UNICODE_STRING();
        text.Buffer = Marshal.StringToHGlobalUni(right);
        text.Length = (ushort)(right.Length * 2);
        text.MaximumLength = (ushort)(text.Length + 2);
        IntPtr handle = Open();
        try {
            uint status = LsaAddAccountRights(handle, Sid(account), new[] { text }, 1);
            if (status != 0) throw new Win32Exception(LsaNtStatusToWinError(status));
        } finally {
            Marshal.FreeHGlobal(text.Buffer);
            LsaClose(handle);
        }
    }

    public static void RemoveAll(string account) {
        IntPtr handle = Open();
        try { LsaRemoveAccountRights(handle, Sid(account), true, null, 0); }
        finally { LsaClose(handle); }
    }
}
"@
}

function Stop-SecretBrokerProcesses([string]$PathFragment) {
    Get-CimInstance Win32_Process |
        Where-Object { ($_.CommandLine -like "*secretbroker*") -and ($_.ExecutablePath -like "*$PathFragment*") } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}
