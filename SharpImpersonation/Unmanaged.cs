using System;
using System.Runtime.InteropServices;
using System.Text;


namespace SharpImpersonation
{

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean OpenProcessToken(IntPtr hProcess, UInt32 dwDesiredAccess, out IntPtr hToken);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean CloseHandle(IntPtr hProcess);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean SetThreadToken(IntPtr ThreadHandle, IntPtr TokenHandle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, out IntPtr DuplicateTokenHandle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean DuplicateTokenEx(IntPtr hExistingToken, UInt32 dwDesiredAccess, IntPtr lpTokenAttributes, _SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, _TOKEN_TYPE TokenType, out IntPtr phNewToken);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean DuplicateTokenExLong(IntPtr hExistingToken, UInt32 dwDesiredAccess, ref _SECURITY_ATTRIBUTES lpTokenAttributes, _SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, _TOKEN_TYPE TokenType, out IntPtr phNewToken);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean ImpersonateLoggedOnUser(IntPtr hToken);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr OpenProcess(UInt32 dwDesiredAccess, Boolean bInheritHandle, UInt32 dwProcessId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr OpenProcessLong(ProcessSecurityRights dwDesiredAccess, Boolean bInheritHandle, UInt32 dwProcessId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr GetCurrentThread();

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean OpenThreadToken(IntPtr ThreadHandle, UInt32 DesiredAccess, Boolean OpenAsSelf, ref IntPtr TokenHandle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean ImpersonateSelf(_SECURITY_IMPERSONATION_LEVEL ImpersonationLevel);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean LookupPrivilegeValue(String lpSystemName, String lpName, ref _LUID luid);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean AdjustTokenPrivileges(IntPtr TokenHandle,Boolean DisableAllPrivileges,ref _TOKEN_PRIVILEGES NewState,UInt32 BufferLengthInBytes,ref _TOKEN_PRIVILEGES PreviousState,out UInt32 ReturnLengthInBytes);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean LookupPrivilegeName(String lpSystemName, IntPtr lpLuid, StringBuilder lpName, ref Int32 cchName);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean GetTokenInformation(IntPtr TokenHandle, _TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, UInt32 TokenInformationLength, out UInt32 ReturnLength);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean GetTokenInformation2(IntPtr TokenHandle, _TOKEN_INFORMATION_CLASS TokenInformationClass, ref _TOKEN_STATISTICS TokenInformation, UInt32 TokenInformationLength, out UInt32 ReturnLength);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean PrivilegeCheck(IntPtr ClientToken, _PRIVILEGE_SET RequiredPrivileges, IntPtr pfResult);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate Boolean PrivilegeCheck2(IntPtr ClientToken, ref _PRIVILEGE_SET RequiredPrivileges, out Int32 pfResult);

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

    [StructLayout(LayoutKind.Sequential, Pack = 0)]
    struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }

}
