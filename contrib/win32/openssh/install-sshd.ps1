# @manojampalam - authored initial script
# @friism - Fixed issue with invalid SDDL on Set-Acl
# @manojampalam - removed ntrights.exe dependency
# @bingbing8 - removed secedit.exe dependency

$scriptpath = $MyInvocation.MyCommand.Path
$scriptdir = Split-Path $scriptpath

$sshdpath = Join-Path $scriptdir "sshd.exe"
$sshagentpath = Join-Path $scriptdir "ssh-agent.exe"
$logsdir = Join-Path $scriptdir "logs"

$sshdAccount = "NT SERVICE\SSHD"
$sshdSid = "S-1-5-80-3847866527-469524349-687026318-516638107-1125189541"

#Idea borrowed from https://gallery.technet.microsoft.com/scriptcenter/Grant-Revoke-Query-user-26e259b0
$definition = @'
using System;

namespace MyLsaWrapper
{
    using System.Runtime.InteropServices;
    using System.Security;    
    using System.ComponentModel;    
    using System.Security.Principal;

    using LSA_HANDLE = IntPtr;

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_OBJECT_ATTRIBUTES
    {
        internal int Length;
        internal IntPtr RootDirectory;
        internal IntPtr ObjectName;
        internal int Attributes;
        internal IntPtr SecurityDescriptor;
        internal IntPtr SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct LSA_UNICODE_STRING
    {
        internal ushort Length;
        internal ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string Buffer;
    }
    sealed class Win32Sec
    {
        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaOpenPolicy(
        LSA_UNICODE_STRING[] SystemName,
        ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
        int AccessMask,
        out IntPtr PolicyHandle
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaAddAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            LSA_UNICODE_STRING[] UserRights,
            int CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaRemoveAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            bool AllRights,
            LSA_UNICODE_STRING[] UserRights,
            int CountOfRights
        );

        [DllImport("advapi32")]
        internal static extern int LsaNtStatusToWinError(int NTSTATUS);

        [DllImport("advapi32")]
        internal static extern int LsaClose(IntPtr PolicyHandle);
    }

    internal sealed class Sid : IDisposable
    {
        public IntPtr pSid = IntPtr.Zero;
        public System.Security.Principal.SecurityIdentifier sid = null;

        public Sid(string account)
        {
            try { sid = new SecurityIdentifier(account); }
            catch { sid = (SecurityIdentifier)(new NTAccount(account)).Translate(typeof(SecurityIdentifier)); }
            Byte[] buffer = new Byte[sid.BinaryLength];
            sid.GetBinaryForm(buffer, 0);

            pSid = Marshal.AllocHGlobal(sid.BinaryLength);
            Marshal.Copy(buffer, 0, pSid, sid.BinaryLength);
        }

        public void Dispose()
        {
            if (pSid != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pSid);
                pSid = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~Sid() { Dispose(); }
    }

    public sealed class LsaWrapper : IDisposable
    {
        enum Access : int
        {
            POLICY_READ = 0x20006,
            POLICY_ALL_ACCESS = 0x00F0FFF,
            POLICY_EXECUTE = 0X20801,
            POLICY_WRITE = 0X207F8
        }
        const uint STATUS_ACCESS_DENIED = 0xc0000022;
        const uint STATUS_INSUFFICIENT_RESOURCES = 0xc000009a;
        const uint STATUS_NO_MEMORY = 0xc0000017;
        const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xc0000034;
        const uint STATUS_NO_MORE_ENTRIES = 0x8000001a;

        IntPtr lsaHandle;

        public LsaWrapper() : this(null) { } // local system if systemName is null
        public LsaWrapper(string systemName)
        {
            LSA_OBJECT_ATTRIBUTES lsaAttr;
            lsaAttr.RootDirectory = IntPtr.Zero;
            lsaAttr.ObjectName = IntPtr.Zero;
            lsaAttr.Attributes = 0;
            lsaAttr.SecurityDescriptor = IntPtr.Zero;
            lsaAttr.SecurityQualityOfService = IntPtr.Zero;
            lsaAttr.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            lsaHandle = IntPtr.Zero;
            LSA_UNICODE_STRING[] system = null;
            if (systemName != null)
            {
                system = new LSA_UNICODE_STRING[1];
                system[0] = InitLsaString(systemName);
            }

            uint ret = Win32Sec.LsaOpenPolicy(system, ref lsaAttr, (int)Access.POLICY_ALL_ACCESS, out lsaHandle);
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void AddPrivilege(string account, string privilege)
        {
            uint ret = 0;
            using (Sid sid = new Sid(account))
            {
                LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
                privileges[0] = InitLsaString(privilege);
                ret = Win32Sec.LsaAddAccountRights(lsaHandle, sid.pSid, privileges, 1);
            }
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void RemovePrivilege(string account, string privilege)
        {
            uint ret = 0;
            using (Sid sid = new Sid(account))
            {
                LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
                privileges[0] = InitLsaString(privilege);
                ret = Win32Sec.LsaRemoveAccountRights(lsaHandle, sid.pSid, false, privileges, 1);
            }
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void Dispose()
        {
            if (lsaHandle != IntPtr.Zero)
            {
                Win32Sec.LsaClose(lsaHandle);
                lsaHandle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~LsaWrapper() { Dispose(); }

        // helper functions:
        static LSA_UNICODE_STRING InitLsaString(string s)
        {
            // Unicode strings max. 32KB
            if (s.Length > 0x7ffe) throw new ArgumentException("String too long");
            LSA_UNICODE_STRING lus = new LSA_UNICODE_STRING();
            lus.Buffer = s;
            lus.Length = (ushort)(s.Length * sizeof(char));
            lus.MaximumLength = (ushort)(lus.Length + sizeof(char));
            return lus;
        }
    }
    public class LsaWrapperCaller
    {
        public static void AddPrivilege(string account, string privilege)
        {
            using (LsaWrapper lsaWrapper = new LsaWrapper())
            {
                lsaWrapper.AddPrivilege(account, privilege);
            }
        }
        public static void RemovePrivilege(string account, string privilege)
        {
            using (LsaWrapper lsaWrapper = new LsaWrapper())
            {
                lsaWrapper.RemovePrivilege(account, privilege);
            }
        }
    }
}
'@
$references = @()
if(($psversiontable.Containskey("psedition")) -and ($psversiontable.PSEdition -ieq "core"))
{
    $references = "System.Security.Principal.Windows", "Microsoft.Win32.Primitives"
}

try {
    $null = [MyLsaWrapper.LsaWrapperCaller]
}
catch {
    $types = Add-Type $definition -ref $references -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
}


function Add-Privilege
{
    param(
    [ValidateNotNullOrEmpty()]
    [string] $Account,
    
    [ValidateSet("SeAssignPrimaryTokenPrivilege", "SeServiceLogonRight")]
    [string] $Privilege
    )

    [MyLsaWrapper.LsaWrapperCaller]::AddPrivilege($Account, $Privilege)    
}


if (-not (Test-Path $sshdpath)) {
    throw "sshd.exe is not present in script path"
}

if (Get-Service sshd -ErrorAction SilentlyContinue) 
{
   Stop-Service sshd
   sc.exe delete sshd 1>$null
}

if (Get-Service ssh-agent -ErrorAction SilentlyContinue) 
{
   Stop-Service ssh-agent
   sc.exe delete ssh-agent 1>$null
}

New-Service -Name ssh-agent -BinaryPathName $sshagentpath -Description "SSH Agent" -StartupType Manual | Out-Null
cmd.exe /c 'sc.exe sdset ssh-agent D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RP;;;AU)'

New-Service -Name sshd -BinaryPathName $sshdpath -Description "SSH Daemon" -StartupType Manual -DependsOn ssh-agent | Out-Null
sc.exe config sshd obj= $sshdAccount
sc.exe privs sshd SeAssignPrimaryTokenPrivilege

Add-Privilege -Account $sshdSid -Privilege SeAssignPrimaryTokenPrivilege

if(-not (test-path $logsdir -PathType Container))
{
    $null = New-Item $logsdir -ItemType Directory -Force -ErrorAction Stop
}
$rights = [System.Security.AccessControl.FileSystemRights]"Read, Write"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($sshdAccount, $rights, "ContainerInherit,ObjectInherit", "None", "Allow")
$acl = Get-Acl -Path $logsdir
$Acl.SetAccessRule($accessRule)
Set-Acl -Path $logsdir -AclObject $acl
Write-Host -ForegroundColor Green "sshd and ssh-agent services successfully installed"
