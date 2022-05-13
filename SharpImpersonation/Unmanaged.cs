using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpImpersonation
{

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean GetProcessInformation(IntPtr hProcess, _PROCESS_INFORMATION_CLASS processInformationClass, ref _PROCESS_PROTECTION_LEVEL_INFORMATION processInformation, uint processInformationSize);


    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean CloseHandle(IntPtr hProcess);


    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate InvokeItDynamically.Native.NTSTATUS NtOpenProcessToken(
        IntPtr ProcessHandle,
        UInt32 dwDesiredAccess,
        out IntPtr TokenHandle);

    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NtDuplicateToken2(
            IntPtr ExistingTokenHandle,
            ACCESS_MASK desiredAccess,
            IntPtr ObjectAttributes,
            Boolean EffectiveOnly,
            _TOKEN_TYPE TokenType,
            ref IntPtr NewTokenHandle);


    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NtDuplicateToken(
            IntPtr ExistingTokenHandle,
            TokenAccessFlags desiredAccess,
            ObjectAttributes ObjectAttributes,
            Boolean EffectiveOnly,
            _TOKEN_TYPE TokenType,
            ref IntPtr NewTokenHandle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtSetInformationThread(IntPtr threadHandle, ThreadInformationClass threadInformationClass, IntPtr threadInformation, int threadInformationLength);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate InvokeItDynamically.Native.NTSTATUS NtClose(
        IntPtr ProcessHandle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtQueryInformationToken(IntPtr TokenHandle, uint TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean LookupPrivilegeValue(String lpSystemName, String lpName, ref _LUID luid);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean AdjustTokenPrivileges(IntPtr TokenHandle,Boolean DisableAllPrivileges,ref _TOKEN_PRIVILEGES NewState,UInt32 BufferLengthInBytes,ref _TOKEN_PRIVILEGES PreviousState,out UInt32 ReturnLengthInBytes);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean LookupPrivilegeName(String lpSystemName, IntPtr lpLuid, StringBuilder lpName, ref Int32 cchName);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean GetTokenInformation(IntPtr TokenHandle, _TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, UInt32 TokenInformationLength, out UInt32 ReturnLength);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate UInt32 RtlNtStatusToDosError(UInt32 Status);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate UInt32 LsaGetLogonSessionData(IntPtr LogonId, out IntPtr ppLogonSessionData);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate bool LookupAccountSid(String lpSystemName, IntPtr Sid, StringBuilder lpName, ref UInt32 cchName, StringBuilder ReferencedDomainName, ref UInt32 cchReferencedDomainName, out _SID_NAME_USE peUse);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate bool LookupAccountSid2(String lpSystemName,IntPtr Sid,IntPtr lpName,ref UInt32 cchName, IntPtr ReferencedDomainName,ref UInt32 cchReferencedDomainName,out _SID_NAME_USE peUse);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate bool ConvertSidToStringSidA(IntPtr Sid, ref IntPtr StringSid);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean LookupPrivilegeNameA(String lpSystemName, IntPtr lpLuid, StringBuilder lpName, ref Int32 cchName);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate bool CreateProcessWithTokenW(IntPtr hToken, LogonFlags dwLogonFlags, Byte[] lpApplicationName, Byte[] lpCommandLine, CreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref _STARTUPINFO lpStartupInfo, out _PROCESS_INFORMATION lpProcessInformation);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate UInt32 SearchPath(String lpPath, String lpFileName, String lpExtension, UInt32 nBufferLength, StringBuilder lpBuffer, ref IntPtr lpFilePart);


    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean CreateProcessWithLogonW(
   String lpUsername,
   String lpDomain,
   String lpPassword,
   LOGON_FLAGS dwLogonFlags,
   Byte[] lpApplicationName,
   Byte[] lpCommandLine,
   CREATION_FLAGS dwCreationFlags,
   IntPtr lpEnvironment,
   String lpCurrentDirectory,
   ref _STARTUPINFO lpStartupInfo,
   out _PROCESS_INFORMATION lpProcessInformation
);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate InvokeItDynamically.Native.NTSTATUS NtOpenProcess(
ref IntPtr ProcessHandle,
uint DesiredAccess,
ref OBJECT_ATTRIBUTES ObjectAttributes,
ref CLIENT_ID ClientId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate InvokeItDynamically.Native.NTSTATUS NtAllocateVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        IntPtr ZeroBits,
        ref IntPtr RegionSize,
        uint AllocationType,
        uint Protect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate InvokeItDynamically.Native.NTSTATUS NtWriteVirtualMemory(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        IntPtr Buffer,
        uint BufferLength,
        ref uint BytesWritten);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate InvokeItDynamically.Native.NTSTATUS NtProtectVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        ref IntPtr RegionSize,
        uint NewProtect,
        ref uint OldProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate InvokeItDynamically.Native.NTSTATUS NtCreateThreadEx(
        out IntPtr threadHandle,
        InvokeItDynamically.Win32.WinNT.ACCESS_MASK desiredAccess,
        IntPtr objectAttributes,
        IntPtr processHandle,
        IntPtr startAddress,
        IntPtr parameter,
        bool createSuspended,
        int stackZeroBits,
        int sizeOfStack,
        int maximumStackSize,
        IntPtr attributeList);

    
    [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public uint RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public SecurityQualityOfService SecurityQualityOfService;
    }
    

    [StructLayout(LayoutKind.Sequential)]
    struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }

    public enum TokenAccessFlags : uint
    {
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_READ = 0x00020000,
        TOKEN_ASSIGN_PRIMARY = 0x0001,
        TOKEN_DUPLICATE = 0x0002,
        TOKEN_IMPERSONATE = 0x0004,
        TOKEN_QUERY = 0x0008,
        TOKEN_QUERY_SOURCE = 0x0010,
        TOKEN_ADJUST_PRIVILEGES = 0x0020,
        TOKEN_ADJUST_GROUPS = 0x0040,
        TOKEN_ADJUST_DEFAULT = 0x0080,
        TOKEN_ADJUST_SESSIONID = 0x0100,
        TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY),
        TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID)
    }

    public enum ThreadInformationClass
    {
        ThreadBasicInformation = 0,
        ThreadTimes = 1,
        ThreadPriority = 2,
        ThreadBasePriority = 3,
        ThreadAffinityMask = 4,
        ThreadImpersonationToken = 5,
        ThreadDescriptorTableEntry = 6,
        ThreadEnableAlignmentFaultFixup = 7,
        ThreadEventPair_Reusable = 8,
        ThreadQuerySetWin32StartAddress = 9,
        ThreadZeroTlsCell = 10,
        ThreadPerformanceCount = 11,
        ThreadAmILastThread = 12,
        ThreadIdealProcessor = 13,
        ThreadPriorityBoost = 14,
        ThreadSetTlsArrayAddress = 15,   // Obsolete
        ThreadIsIoPending = 16,
        ThreadHideFromDebugger = 17,
        ThreadBreakOnTermination = 18,
        ThreadSwitchLegacyState = 19,
        ThreadIsTerminated = 20,
        ThreadLastSystemCall = 21,
        ThreadIoPriority = 22,
        ThreadCycleTime = 23,
        ThreadPagePriority = 24,
        ThreadActualBasePriority = 25,
        ThreadTebInformation = 26,
        ThreadCSwitchMon = 27,   // Obsolete
        ThreadCSwitchPmu = 28,
        ThreadWow64Context = 29,
        ThreadGroupInformation = 30,
        ThreadUmsInformation = 31,   // UMS
        ThreadCounterProfiling = 32,
        ThreadIdealProcessorEx = 33,
        ThreadCpuAccountingInformation = 34,
        ThreadSuspendCount = 35,
        ThreadDescription = 38,
        ThreadActualGroupAffinity = 41,
        ThreadDynamicCodePolicy = 42,
    }

    public enum SecurityImpersonationLevel
    {
        Anonymous = 0,
        Identification = 1,
        Impersonation = 2,
        Delegation = 3
    }

    public enum SecurityContextTrackingMode : byte
    {
        Static = 0,
        Dynamic = 1
    }

    [StructLayout(LayoutKind.Sequential)]
    public sealed class SecurityQualityOfService
    {
        public int _length;
        private SecurityImpersonationLevel _imp_level;
        private SecurityContextTrackingMode _tracking_mode;
        [MarshalAs(UnmanagedType.U1)]
        private bool _effective_only;

        public SecurityImpersonationLevel ImpersonationLevel { get => _imp_level; set => _imp_level = value; }
        public SecurityContextTrackingMode ContextTrackingMode { get => _tracking_mode; set => _tracking_mode = value; }
        public bool EffectiveOnly { get => _effective_only; set => _effective_only = value; }

        public SecurityQualityOfService()
        {
            _length = Marshal.SizeOf(this);
        }

        public SecurityQualityOfService(SecurityImpersonationLevel imp_level,
            SecurityContextTrackingMode tracking_mode,
            bool effective_only) : this()
        {
            _imp_level = imp_level;
            _tracking_mode = tracking_mode;
            _effective_only = effective_only;
        }

        internal SecurityQualityOfServiceStruct ToStruct()
        {
            return new SecurityQualityOfServiceStruct(ImpersonationLevel, ContextTrackingMode, EffectiveOnly);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecurityQualityOfServiceStruct
    {
        public int Length;
        public SecurityImpersonationLevel ImpersonationLevel;
        public SecurityContextTrackingMode ContextTrackingMode;
        [MarshalAs(UnmanagedType.U1)]
        public bool EffectiveOnly;

        public SecurityQualityOfServiceStruct(SecurityImpersonationLevel impersonation_level,
            SecurityContextTrackingMode context_tracking_mode, bool effective_only)
        {
            Length = Marshal.SizeOf(typeof(SecurityQualityOfServiceStruct));
            ImpersonationLevel = impersonation_level;
            ContextTrackingMode = context_tracking_mode;
            EffectiveOnly = effective_only;
        }
    }

    /// <summary>
    /// Flags for OBJECT_ATTRIBUTES
    /// </summary>
    [Flags]
    public enum AttributeFlags : uint
    {
        /// <summary>
        /// None
        /// </summary>
        None = 0,
        /// <summary>
        /// Handle is protected from closing.
        /// </summary>
        ProtectClose = 0x00000001,
        /// <summary>
        /// The handle created can be inherited
        /// </summary>
        Inherit = 0x00000002,
        /// <summary>
        /// Audit handle close.
        /// </summary>
        AuditObjectClose = 0x00000004,
        /// <summary>
        /// The object created is marked as permanent
        /// </summary>
        Permanent = 0x00000010,
        /// <summary>
        /// The object must be created exclusively
        /// </summary>
        Exclusive = 0x00000020,
        /// <summary>
        /// The object name lookup should be done case insensitive
        /// </summary>
        CaseInsensitive = 0x00000040,
        /// <summary>
        /// Open the object if it already exists
        /// </summary>
        OpenIf = 0x00000080,
        /// <summary>
        /// Open the object as a link
        /// </summary>
        OpenLink = 0x00000100,
        /// <summary>
        /// Create as a kernel handle (not used in user-mode)
        /// </summary>
        KernelHandle = 0x00000200,
        /// <summary>
        /// Force an access check to occur (not used in user-mode)
        /// </summary>
        ForceAccessCheck = 0x00000400,
        /// <summary>
        /// Ignore impersonated device map when looking up object
        /// </summary>
        IgnoreImpersonatedDevicemap = 0x00000800,
        /// <summary>
        /// Fail if a reparse is encountered
        /// </summary>
        DontReparse = 0x00001000,
    }

    /// <summary>
    /// A class which represents OBJECT_ATTRIBUTES
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public sealed class ObjectAttributes
    {
        private readonly int Length;
        private readonly IntPtr RootDirectory;
        private readonly IntPtr ObjectName;
        private readonly AttributeFlags Attributes;
        private readonly IntPtr SecurityDescriptor;
        private readonly IntPtr SecurityQualityOfService;

      
        public ObjectAttributes(IntPtr object_name, AttributeFlags attributes, IntPtr root,
            SecurityQualityOfService sqos, IntPtr security_descriptor)
        {
            try
            {
                if (root == null)
                    throw new ArgumentNullException(nameof(root), "Use IntPtr.Zero for a null handle");
                Length = Marshal.SizeOf(this);
                ObjectName = object_name;
                Attributes = attributes;
                if (sqos != null)
                {
                    IntPtr sqosPointer = Marshal.AllocHGlobal((int)sqos._length);
                    Marshal.StructureToPtr(sqos, sqosPointer, false);
                    SecurityQualityOfService = sqosPointer;
                }
                else
                {
                    SecurityQualityOfService = IntPtr.Zero;
                }

                RootDirectory = IntPtr.Zero;
                security_descriptor = IntPtr.Zero;
            }
            catch
            {
                Console.WriteLine("Failed creating correct ObjectAttributes!"); ;
                throw;
            }
        }


    }



}
