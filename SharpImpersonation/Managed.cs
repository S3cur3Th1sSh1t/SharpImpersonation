using System;
using System.Runtime.InteropServices;



namespace SharpImpersonateUser
{
    class managed
    {

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean CloseHandle(IntPtr hProcess);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean OpenProcessToken(IntPtr hProcess, UInt32 dwDesiredAccess, out IntPtr hToken);
    }
}
