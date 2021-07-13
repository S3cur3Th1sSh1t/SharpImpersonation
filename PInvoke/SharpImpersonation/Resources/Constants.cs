using System;
using System.Runtime.InteropServices;

using BOOL = System.Boolean;

using WORD = System.UInt16;
using DWORD = System.UInt32;
using QWORD = System.UInt64;
using LONG = System.UInt32;

using ULONGLONG = System.UInt64;
using LARGE_INTEGER = System.UInt64;

using PSID = System.IntPtr;

using PVOID = System.IntPtr;
using LPVOID = System.IntPtr;
using DWORD_PTR = System.IntPtr;
using SIZE_T = System.IntPtr;

using USHORT = System.UInt16;

using ULONG = System.UInt32;

using PWSTR = System.IntPtr;


using UCHAR = System.Byte;

namespace SharpImpersonation
{

    class Constants
    {
        //Process Security and Access Rights
        //https://docs.microsoft.com/en-us/windows/desktop/procthread/process-security-and-access-rights
        internal const UInt32 DELETE = 0x00010000;
        internal const UInt32 READ_CONTROL = 0x00020000;
        internal const UInt32 SYNCHRONIZE = 0x00100000;
        internal const UInt32 WRITE_DAC = 0x00040000;
        internal const UInt32 WRITE_OWNER = 0x00080000;
        //https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
        internal const UInt32 PROCESS_ALL_ACCESS = 0;
        internal const UInt32 PROCESS_CREATE_PROCESS = 0x0080;
        internal const UInt32 PROCESS_CREATE_THREAD = 0x0002;
        internal const UInt32 PROCESS_DUP_HANDLE = 0x0040;
        internal const UInt32 PROCESS_QUERY_INFORMATION = 0x0400;
        internal const UInt32 PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        internal const UInt32 PROCESS_SET_INFORMATION = 0x0200;
        internal const UInt32 PROCESS_SET_QUOTA = 0x0100;
        internal const UInt32 PROCESS_SUSPEND_RESUME = 0x0800;
        internal const UInt32 PROCESS_TERMINATE = 0x0001;
        internal const UInt32 PROCESS_VM_OPERATION = 0x0008;
        internal const UInt32 PROCESS_VM_READ = 0x0010;
        internal const UInt32 PROCESS_VM_WRITE = 0x0020;

        //Token 

        //https://docs.microsoft.com/en-us/windows/desktop/secauthz/standard-access-rights
        internal const UInt32 STANDARD_RIGHTS_ALL = (DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE);
        internal const UInt32 STANDARD_RIGHTS_EXECUTE = READ_CONTROL;
        internal const UInt32 STANDARD_RIGHTS_READ = READ_CONTROL;
        internal const UInt32 STANDARD_RIGHTS_REQUIRED = (DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER);//0x000F0000;
        internal const UInt32 STANDARD_RIGHTS_WRITE = READ_CONTROL;

        //http://www.pinvoke.net/default.aspx/advapi32.openprocesstoken
        internal const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
        internal const UInt32 TOKEN_DUPLICATE = 0x0002;
        internal const UInt32 TOKEN_IMPERSONATE = 0x0004;
        internal const UInt32 TOKEN_QUERY = 0x0008;
        internal const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
        internal const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
        internal const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
        internal const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
        internal const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
        internal const UInt32 TOKEN_EXECUTE = (STANDARD_RIGHTS_EXECUTE | TOKEN_IMPERSONATE);
        internal const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        internal const UInt32 TOKEN_WRITE = (STANDARD_RIGHTS_READ | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT);
        internal const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID);
        internal const UInt32 TOKEN_ALT = (TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY);
        internal const UInt32 TOKEN_ALT2 = (TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID);

        internal const Int32 ANYSIZE_ARRAY = 1;

        //https://msdn.microsoft.com/en-us/library/windows/desktop/aa446619(v=vs.85).aspx
        //https://docs.microsoft.com/en-us/windows/desktop/secauthz/privilege-constants
        internal const String SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
        internal const String SE_BACKUP_NAME = "SeBackupPrivilege";
        internal const String SE_DEBUG_NAME = "SeDebugPrivilege";
        internal const String SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";
        internal const String SE_TCB_NAME = "SeTcbPrivilege";

        internal const UInt64 SE_GROUP_ENABLED = 0x00000004L;
        internal const UInt64 SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002L;
        internal const UInt64 SE_GROUP_INTEGRITY = 0x00000020L;
        internal const UInt32 SE_GROUP_INTEGRITY_32 = 0x00000020;
        internal const UInt64 SE_GROUP_INTEGRITY_ENABLED = 0x00000040L;
        internal const UInt64 SE_GROUP_LOGON_ID = 0xC0000000L;
        internal const UInt64 SE_GROUP_MANDATORY = 0x00000001L;
        internal const UInt64 SE_GROUP_OWNER = 0x00000008L;
        internal const UInt64 SE_GROUP_RESOURCE = 0x20000000L;
        internal const UInt64 SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010L;

        //https://msdn.microsoft.com/en-us/library/windows/desktop/aa446583%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
        internal const UInt32 DISABLE_MAX_PRIVILEGE = 0x1;
        internal const UInt32 SANDBOX_INERT = 0x2;
        internal const UInt32 LUA_TOKEN = 0x4;
        internal const UInt32 WRITE_RESTRICTED = 0x8;
    }

    public class Token
    {
        //Token 
        //http://www.pinvoke.net/default.aspx/advapi32.openprocesstoken
        public const DWORD STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const DWORD STANDARD_RIGHTS_READ = 0x00020000;
        public const DWORD TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const DWORD TOKEN_DUPLICATE = 0x0002;
        public const DWORD TOKEN_IMPERSONATE = 0x0004;
        public const DWORD TOKEN_QUERY = 0x0008;
        public const DWORD TOKEN_QUERY_SOURCE = 0x0010;
        public const DWORD TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const DWORD TOKEN_ADJUST_GROUPS = 0x0040;
        public const DWORD TOKEN_ADJUST_DEFAULT = 0x0080;
        public const DWORD TOKEN_ADJUST_SESSIONID = 0x0100;
        public const DWORD TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        public const DWORD TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID);
        public const DWORD TOKEN_ALT = (TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY);

        //TOKEN_PRIVILEGES
        //https://msdn.microsoft.com/en-us/library/windows/desktop/aa379630(v=vs.85).aspx
        public const DWORD SE_PRIVILEGE_ENABLED = 0x2;
        public const DWORD SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1;
        public const DWORD SE_PRIVILEGE_REMOVED = 0x4;
        public const DWORD SE_PRIVILEGE_USED_FOR_ACCESS = 0x3;

        public const Int32 ANYSIZE_ARRAY = 1;

        //https://msdn.microsoft.com/en-us/library/windows/desktop/aa446619(v=vs.85).aspx
        public const String SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
        public const String SE_BACKUP_NAME = "SeBackupPrivilege";
        public const String SE_DEBUG_NAME = "SeDebugPrivilege";
        public const String SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";
        public const String SE_TCB_NAME = "SeTcbPrivilege";

        public const QWORD SE_GROUP_ENABLED = 0x00000004L;
        public const QWORD SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002L;
        public const QWORD SE_GROUP_INTEGRITY = 0x00000020L;
        public const QWORD SE_GROUP_INTEGRITY_32 = 0x00000020;
        public const QWORD SE_GROUP_INTEGRITY_ENABLED = 0x00000040L;
        public const QWORD SE_GROUP_LOGON_ID = 0xC0000000L;
        public const QWORD SE_GROUP_MANDATORY = 0x00000001L;
        public const QWORD SE_GROUP_OWNER = 0x00000008L;
        public const QWORD SE_GROUP_RESOURCE = 0x20000000L;
        public const QWORD SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010L;

        public const Int32 PRIVILEGE_SET_ALL_NECESSARY = 1;

        //https://msdn.microsoft.com/en-us/library/windows/desktop/aa446583%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
        public const DWORD DISABLE_MAX_PRIVILEGE = 0x1;
        public const DWORD SANDBOX_INERT = 0x2;
        public const DWORD LUA_TOKEN = 0x4;
        public const DWORD WRITE_RESTRICTED = 0x8;

        private const DWORD EXCEPTION_MAXIMUM_PARAMETERS = 15;

        [Flags]
        //https://msdn.microsoft.com/en-us/library/windows/desktop/aa379630(v=vs.85).aspx
        public enum TokenPrivileges : uint
        {
            SE_PRIVILEGE_NONE = 0x0,
            SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1,
            SE_PRIVILEGE_ENABLED = 0x2,
            SE_PRIVILEGE_REMOVED = 0x4,
            SE_PRIVILEGE_USED_FOR_ACCESS = 0x3
        }
    }

    //https://msdn.microsoft.com/en-us/library/windows/desktop/ms682434(v=vs.85).aspx
    [Flags]
    public enum CREATION_FLAGS : uint
    {
        NONE = 0x0,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NEW_CONSOLE = 0x00000010,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_SEPARATE_WOW_VDM = 0x00000800,
        CREATE_SUSPENDED = 0x00000004,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000
    }

    [Flags]
    public enum INFO_PROCESSOR_ARCHITECTURE : ushort
    {
        PROCESSOR_ARCHITECTURE_INTEL = 0,
        PROCESSOR_ARCHITECTURE_ARM = 5,
        PROCESSOR_ARCHITECTURE_IA64 = 6,
        PROCESSOR_ARCHITECTURE_AMD64 = 9,
        PROCESSOR_ARCHITECTURE_ARM64 = 12,
        PROCESSOR_ARCHITECTURE_UNKNOWN = 0xffff
    }

    [Flags]
    public enum OPEN_MODE : uint
    {
        PIPE_ACCESS_INBOUND = 0x00000001,
        PIPE_ACCESS_OUTBOUND = 0x00000002,
        PIPE_ACCESS_DUPLEX = 0x00000003,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000,
        ACCESS_SYSTEM_SECURITY = 0x01000000,
        FILE_FLAG_OVERLAPPED = 0x40000000,
        FILE_FLAG_WRITE_THROUGH = 0x80000000
    }

    [Flags]
    public enum PIPE_MODE : uint
    {
        PIPE_TYPE_BYTE = 0x00000000,
        PIPE_TYPE_MESSAGE = 0x00000004,
        PIPE_READMODE_BYTE = 0x00000000,
        PIPE_READMODE_MESSAGE = 0x00000002,
        PIPE_WAIT = 0x00000000,
        PIPE_NOWAIT = 0x00000001,
        PIPE_ACCEPT_REMOTE_CLIENTS = 0x00000000,
        PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
    }

    [Flags]
    public enum LOGON_FLAGS
    {
        LOGON_WITH_PROFILE = 0x00000001,
        LOGON_NETCREDENTIALS_ONLY = 0x00000002
    }

    //https://msdn.microsoft.com/en-us/library/windows/desktop/ms684873(v=vs.85).aspx
    [StructLayout(LayoutKind.Sequential)]
    public struct _PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public UInt32 dwProcessId;
        public UInt32 dwThreadId;
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct _SECURITY_ATTRIBUTES
    {
        public DWORD nLength;
        public LPVOID lpSecurityDescriptor;
        public BOOL bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _STARTUPINFO
    {
        public UInt32 cb;
        public String lpReserved;
        public String lpDesktop;
        public String lpTitle;
        public UInt32 dwX;
        public UInt32 dwY;
        public UInt32 dwXSize;
        public UInt32 dwYSize;
        public UInt32 dwXCountChars;
        public UInt32 dwYCountChars;
        public UInt32 dwFillAttribute;
        public UInt32 dwFlags;
        public UInt16 wShowWindow;
        public UInt16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    };

    [Flags]
    public enum TOKEN_ELEVATION_TYPE
    {
        TokenElevationTypeDefault = 1,
        TokenElevationTypeFull,
        TokenElevationTypeLimited
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _SID
    {
        public UCHAR Revision;
        public UCHAR SubAuthorityCount;
        public _SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public ULONG[] SubAuthority;
    }
    //SID, *PISID

    [StructLayout(LayoutKind.Sequential)]
    public struct _SID_IDENTIFIER_AUTHORITY
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = UnmanagedType.I1)]
        public Byte[] Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _TOKEN_GROUPS
    {
        public ULONG GroupCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 230)]
        public _SID_AND_ATTRIBUTES[] Groups;
    }
    //TOKEN_GROUPS, *PTOKEN_GROUPS


    [StructLayout(LayoutKind.Sequential)]
    public struct _TOKEN_OWNER
    {
        public PSID Owner;
    }
    //TOKEN_OWNER, *PTOKEN_OWNER


    [StructLayout(LayoutKind.Sequential)]
    public struct _TOKEN_USER
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public _SID_AND_ATTRIBUTES[] User;
    }
    //TOKEN_USER, *PTOKEN_USER

    [StructLayout(LayoutKind.Sequential)]
    public struct _SID_AND_ATTRIBUTES
    {
        public PSID Sid;
        public DWORD Attributes;
    }
    //https://msdn.microsoft.com/en-us/library/windows/desktop/ms686331(v=vs.85).aspx
    [StructLayout(LayoutKind.Sequential)]
    public struct _STARTUPINFOEX
    {
        _STARTUPINFO StartupInfo;
        // PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct _SYSTEM_INFO
    {
        public INFO_PROCESSOR_ARCHITECTURE wProcessorArchitecture;
        public WORD wReserved;
        public DWORD dwPageSize;
        public LPVOID lpMinimumApplicationAddress;
        public LPVOID lpMaximumApplicationAddress;
        public DWORD_PTR dwActiveProcessorMask;
        public DWORD dwNumberOfProcessors;
        public DWORD dwProcessorType;
        public DWORD dwAllocationGranularity;
        public WORD wProcessorLevel;
        public WORD wProcessorRevision;
    }

    [Flags]
    public enum _SID_NAME_USE
    {
        SidTypeUser = 1,
        SidTypeGroup,
        SidTypeDomain,
        SidTypeAlias,
        SidTypeWellKnownGroup,
        SidTypeDeletedAccount,
        SidTypeInvalid,
        SidTypeUnknown,
        SidTypeComputer,
        SidTypeLabel
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _LSA_UNICODE_STRING
    {
        public USHORT Length;
        public USHORT MaximumLength;
        public PWSTR Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _LSA_LAST_INTER_LOGON_INFO
    {
        public LARGE_INTEGER LastSuccessfulLogon;
        public LARGE_INTEGER LastFailedLogon;
        public ULONG FailedAttemptCountSinceLastSuccessfulLogon;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _SECURITY_LOGON_SESSION_DATA
    {
        public ULONG Size;
        public _LUID LogonId;
        public _LSA_UNICODE_STRING UserName;
        public _LSA_UNICODE_STRING LogonDomain;
        public _LSA_UNICODE_STRING AuthenticationPackage;
        public ULONG LogonType;
        public ULONG Session;
        public IntPtr Sid;
        public LARGE_INTEGER LogonTime;
        public _LSA_UNICODE_STRING LogonServer;
        public _LSA_UNICODE_STRING DnsDomainName;
        public _LSA_UNICODE_STRING Upn;
        /*
        public ULONG UserFlags;
        public _LSA_LAST_INTER_LOGON_INFO LastLogonInfo;
        public _LSA_UNICODE_STRING LogonScript;
        public _LSA_UNICODE_STRING ProfilePath;
        public _LSA_UNICODE_STRING HomeDirectory;
        public _LSA_UNICODE_STRING HomeDirectoryDrive;
        public LARGE_INTEGER LogoffTime;
        public LARGE_INTEGER KickOffTime;
        public LARGE_INTEGER PasswordLastSet;
        public LARGE_INTEGER PasswordCanChange;
        public LARGE_INTEGER PasswordMustChange;
        */
    }

    public enum CreationFlags
    {
        DefaultErrorMode = 0x04000000,
        NewConsole = 0x00000010,
        CREATE_NO_WINDOW = 0x08000000,
        NewProcessGroup = 0x00000200,
        SeparateWOWVDM = 0x00000800,
        Suspended = 0x00000004,
        UnicodeEnvironment = 0x00000400,
        ExtendedStartupInfoPresent = 0x00080000
    }
    public enum LogonFlags
    {
        WithProfile = 1,
        NetCredentialsOnly = 0
    }

    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROFILEINFO
    {
        public int dwSize;
        public int dwFlags;
        [MarshalAs(UnmanagedType.LPTStr)]
        public String lpUserName;
        [MarshalAs(UnmanagedType.LPTStr)]
        public String lpProfilePath;
        [MarshalAs(UnmanagedType.LPTStr)]
        public String lpDefaultPath;
        [MarshalAs(UnmanagedType.LPTStr)]
        public String lpServerName;
        [MarshalAs(UnmanagedType.LPTStr)]
        public String lpPolicyPath;
        public IntPtr hProfile;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct _TOKEN_STATISTICS
    {
        public _LUID TokenId;
        public _LUID AuthenticationId;
        public LARGE_INTEGER ExpirationTime;
        public _TOKEN_TYPE TokenType;
        public _SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
        public DWORD DynamicCharged;
        public DWORD DynamicAvailable;
        public DWORD GroupCount;
        public DWORD PrivilegeCount;
        public _LUID ModifiedId;
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct _PRIVILEGE_SET
    {
        public DWORD PrivilegeCount;
        public DWORD Control;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = (Int32)Token.ANYSIZE_ARRAY)]
        public _LUID_AND_ATTRIBUTES[] Privilege;
    }

    [Flags]
    public enum _TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        TokenIsAppContainer,
        TokenCapabilities,
        TokenAppContainerSid,
        TokenAppContainerNumber,
        TokenUserClaimAttributes,
        TokenDeviceClaimAttributes,
        TokenRestrictedUserClaimAttributes,
        TokenRestrictedDeviceClaimAttributes,
        TokenDeviceGroups,
        TokenRestrictedDeviceGroups,
        TokenSecurityAttributes,
        TokenIsRestricted,
        MaxTokenInfoClass
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _TOKEN_PRIVILEGES
    {
        public UInt32 PrivilegeCount;
        public _LUID_AND_ATTRIBUTES Privileges;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _TOKEN_PRIVILEGES_ARRAY
    {
        public UInt32 PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 30)]
        public _LUID_AND_ATTRIBUTES[] Privileges;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _LUID
    {
        public DWORD LowPart;
        public DWORD HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _LUID_AND_ATTRIBUTES
    {
        public _LUID Luid;
        public DWORD Attributes;
    }


    [Flags]
    public enum _SECURITY_IMPERSONATION_LEVEL : int
    {
        SecurityAnonymous = 0,
        SecurityIdentification = 1,
        SecurityImpersonation = 2,
        SecurityDelegation = 3
    };

    [Flags]
    public enum ProcessSecurityRights : long
    {
        PROCESS_TERMINATE = 0x0001,
        PROCESS_CREATE_THREAD = 0x0002,
        PROCESS_VM_OPERATION = 0x0008,
        PROCESS_VM_READ = 0x0010,
        PROCESS_VM_WRITE = 0x0020,
        PROCESS_DUP_HANDLE = 0x0040,
        PROCESS_CREATE_PROCESS = 0x0080,
        PROCESS_SET_QUOTA = 0x0100,
        PROCESS_SET_INFORMATION = 0x0200,
        PROCESS_QUERY_INFORMATION = 0x0400,
        PROCESS_SUSPEND_RESUME = 0x0800,
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
        PROCESS_ALL_ACCESS = 0x1FFFFF,

        DELETE = 0x00010000L,
        READ_CONTROL = 0x00020000L,
        WRITE_DAC = 0x00040000L,
        WRITE_OWNER = 0x00080000L,
        SYNCHRONIZE = 0x00100000L
    }



    [Flags]
    public enum ACCESS_MASK : uint
    {
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_READ = 0x00020000,
        STANDARD_RIGHTS_WRITE = 0x00020000,
        STANDARD_RIGHTS_EXECUTE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        SPECIFIC_RIGHTS_ALL = 0x0000FFF,
        ACCESS_SYSTEM_SECURITY = 0x01000000,
        MAXIMUM_ALLOWED = 0x02000000,
        GENERIC_READ = 0x80000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_ALL = 0x10000000,
        DESKTOP_READOBJECTS = 0x00000001,
        DESKTOP_CREATEWINDOW = 0x00000002,
        DESKTOP_CREATEMENU = 0x00000004,
        DESKTOP_HOOKCONTROL = 0x00000008,
        DESKTOP_JOURNALRECORD = 0x00000010,
        DESKTOP_JOURNALPLAYBACK = 0x00000020,
        DESKTOP_ENUMERATE = 0x00000040,
        DESKTOP_WRITEOBJECTS = 0x00000080,
        DESKTOP_SWITCHDESKTOP = 0x00000100,
        WINSTA_ENUMDESKTOPS = 0x00000001,
        WINSTA_READATTRIBUTES = 0x00000002,
        WINSTA_ACCESSCLIPBOARD = 0x00000004,
        WINSTA_CREATEDESKTOP = 0x00000008,
        WINSTA_WRITEATTRIBUTES = 0x00000010,
        WINSTA_ACCESSGLOBALATOMS = 0x00000020,
        WINSTA_EXITWINDOWS = 0x00000040,
        WINSTA_ENUMERATE = 0x00000100,
        WINSTA_READSCREEN = 0x00000200,
        WINSTA_ALL_ACCESS = 0x0000037F
    };

    [Flags]
    public enum _TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation
    }
}
