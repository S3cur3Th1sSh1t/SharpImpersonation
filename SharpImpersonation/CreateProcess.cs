using System;
using System.Runtime.InteropServices;
using System.Text;


namespace SharpImpersonation
{
    class CreateProcess
    {


        ////////////////////////////////////////////////////////////////////////////////
        // Wrapper for ProcessWithLogonW
        ////////////////////////////////////////////////////////////////////////////////


        public static Boolean CreateProcessWithLogonW(IntPtr phNewToken, String name, String arguments)
        {
            Console.WriteLine("Starting " + name);
            if (name.Contains("\\"))
            {
                Console.WriteLine("Starting " + name);
                name = System.IO.Path.GetFullPath(name);
                if (!System.IO.File.Exists(name))
                {
                    Console.WriteLine("[-] File Not Found");
                    return false;
                }
            }
            else
            {
                name = FindFilePath(name);
                Console.WriteLine("Starting " + name);
                if (String.Empty == name)
                {
                    Console.WriteLine("[-] Unable to find file");
                    return false;
                }
            }


            Console.WriteLine("[*] CreateProcessWithLogonW");
            _STARTUPINFO startupInfo = new _STARTUPINFO();
            startupInfo.cb = (UInt32)Marshal.SizeOf(typeof(_STARTUPINFO));
            _PROCESS_INFORMATION processInformation = new _PROCESS_INFORMATION();

            UnicodeEncoding unicode = new UnicodeEncoding();
            Byte[] unicodeapp = unicode.GetBytes(name);
            Byte[] unicodeargs = unicode.GetBytes(name + " " + arguments);

            object[] CreateProcessWithLogonWArgs =
            {
                "i", "j", "k",
                LOGON_FLAGS.LOGON_NETCREDENTIALS_ONLY,
                unicodeapp,
                unicodeargs,
                CREATION_FLAGS.CREATE_DEFAULT_ERROR_MODE,
                IntPtr.Zero,
                Environment.CurrentDirectory,
                startupInfo,
                processInformation
            };

            bool success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("advapi32.dll", "CreateProcessWithLogonW", typeof(CreateProcessWithLogonW), ref CreateProcessWithLogonWArgs, true, true);
            processInformation = (SharpImpersonation._PROCESS_INFORMATION)CreateProcessWithLogonWArgs[10];

            if (!(success))
            {
                Tokens.GetWin32Error("CreateProcessWithLogonW");
                return false;
            }

            Console.WriteLine(" [+] Created process: " + processInformation.dwProcessId);
            Console.WriteLine(" [+] Created thread: " + processInformation.dwThreadId);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Wrapper for CreateProcessWithTokenW
        ////////////////////////////////////////////////////////////////////////////////

        public static Boolean CreateProcessWithTokenW(IntPtr phNewToken, String name, String arguments)
        {
            if (name.Contains(@"\"))
            {
                name = System.IO.Path.GetFullPath(name);
                if (!System.IO.File.Exists(name))
                {
                    Console.WriteLine("File not found first");
                    Console.WriteLine("[-] File Not Found");
                    return false;
                }
            }
            else
            {
                name = FindFilePath(name);
                if (String.Empty == name)
                {
                    Console.WriteLine("[-] Unable to find file");
                    return false;
                }
            }
            
            STARTUPINFO sInfo = new STARTUPINFO();

            sInfo.cb = Marshal.SizeOf(sInfo);

            Console.WriteLine("[*] CreateProcessWithTokenW");
            _STARTUPINFO startupInfo = new _STARTUPINFO
            {
                cb = (UInt32)Marshal.SizeOf(typeof(_STARTUPINFO))
            };
            _PROCESS_INFORMATION processInformation = new _PROCESS_INFORMATION();
            
            Console.WriteLine("Starting " + name + " with arguments " + arguments);
            //Console.WriteLine("Directory: " + Environment.CurrentDirectory);
            

            // Error binary path not found
            UnicodeEncoding unicode = new UnicodeEncoding();
            Byte[] unicodeapp = unicode.GetBytes(name);
            Byte[] unicodeargs = unicode.GetBytes(name + " " + arguments);
            object[] CreateProcessWithTokenWArgs =
            {
                phNewToken,
                0,
                unicodeapp,
                unicodeargs,
                SharpImpersonation.CreationFlags.NewConsole,
                IntPtr.Zero,
                null,
                startupInfo,
                processInformation
            };

            bool success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("advapi32.dll", "CreateProcessWithTokenW", typeof(CreateProcessWithTokenW), ref CreateProcessWithTokenWArgs, true, true);
            processInformation = (_PROCESS_INFORMATION)CreateProcessWithTokenWArgs[8];

            Console.WriteLine("Tried starting process, return value is " + success);
            if (!(success))
            {
                Tokens.GetWin32Error("CreateProcessWithTokenW");
                return false;
            }
            Console.WriteLine(" [+] Created process: " + processInformation.dwProcessId);
            Console.WriteLine(" [+] Created thread: " + processInformation.dwThreadId);
            return true;
        }

        
        public static String FindFilePath(String name)
        {
            StringBuilder lpFileName = new StringBuilder(260);
            IntPtr lpFilePart = new IntPtr();

            object[] SearchPathArgs =
            {
                null, name, null, (UInt32)lpFileName.Capacity, lpFileName, lpFilePart
            };

            UInt32 result = (UInt32)InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "SearchPathA", typeof(SearchPath), ref SearchPathArgs, true, true);

            if (String.Empty == lpFileName.ToString())
            {
                Console.WriteLine(new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
                return String.Empty;
            }
            return lpFileName.ToString();
        }

    }
}