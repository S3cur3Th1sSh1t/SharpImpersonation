using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;



namespace SharpImpersonation
{
    class Enumeration
    {
        
        ////////////////////////////////////////////////////////////////////////////////
        // Converts a TokenStatistics Pointer array to User Name
        ////////////////////////////////////////////////////////////////////////////////

        public static Boolean ConvertTokenStatisticsToUsername(_TOKEN_STATISTICS tokenStatistics, ref String userName)
        {
            IntPtr lpLuid = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(_LUID)));
            Marshal.StructureToPtr(tokenStatistics.AuthenticationId, lpLuid, false);
            if (IntPtr.Zero == lpLuid)
            {
                return false;
            }
            
            IntPtr ppLogonSessionData = new IntPtr();

            object[] LsaGetLogonSessionDataArgs = {lpLuid, ppLogonSessionData};
            UInt32 result = 1;

            result = (UInt32)InvokeItDynamically.DynGen.DynamicAPIInvoke("sspicli.dll", "LsaGetLogonSessionData", typeof(LsaGetLogonSessionData), ref LsaGetLogonSessionDataArgs, true, true);
          
            //Console.WriteLine("LsaGetLogonSessionData result: " + result);
            if (0 != result)
            {
                return false;
            }
            else
            {
                // Only for D/Invoke
                ppLogonSessionData = (IntPtr)LsaGetLogonSessionDataArgs[1];
            }

            if (IntPtr.Zero == ppLogonSessionData)
            {
                return false;
            }

            _SECURITY_LOGON_SESSION_DATA securityLogonSessionData = (_SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(ppLogonSessionData, typeof(_SECURITY_LOGON_SESSION_DATA));
            if (IntPtr.Zero == securityLogonSessionData.Sid || IntPtr.Zero == securityLogonSessionData.UserName.Buffer || IntPtr.Zero == securityLogonSessionData.LogonDomain.Buffer)
            {
                return false;
            }

            if (Environment.MachineName + "$" == Marshal.PtrToStringUni(securityLogonSessionData.UserName.Buffer) && ConvertSidToName(securityLogonSessionData.Sid, out userName))
            {
                return true;

            }

            userName = String.Format("{0}\\{1}", Marshal.PtrToStringUni(securityLogonSessionData.LogonDomain.Buffer), Marshal.PtrToStringUni(securityLogonSessionData.UserName.Buffer));
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Converts a SID Byte array to User Name
        ////////////////////////////////////////////////////////////////////////////////

        public static Boolean ConvertSidToName(IntPtr sid, out String userName)
        {
            StringBuilder sbUserName = new StringBuilder();
            StringBuilder lpName = new StringBuilder();
            UInt32 cchName = (UInt32)lpName.Capacity;
            StringBuilder lpReferencedDomainName = new StringBuilder();
            UInt32 cchReferencedDomainName = (UInt32)lpReferencedDomainName.Capacity;
            _SID_NAME_USE sidNameUse = new _SID_NAME_USE();
            object[] LookupAccountSidArgs =
            {
                    String.Empty, sid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, sidNameUse
            };

            //LookupAccountSid(String.Empty, sid, lpName, ref cchName, lpReferencedDomainName, ref cchReferencedDomainName, out sidNameUse);
            InvokeItDynamically.DynGen.DynamicAPIInvoke("advapi32.dll", "LookupAccountSidA", typeof(LookupAccountSid), ref LookupAccountSidArgs, true, true);
            sidNameUse = (_SID_NAME_USE)LookupAccountSidArgs[6];


            lpName.EnsureCapacity((Int32)cchName + 1);
            lpReferencedDomainName.EnsureCapacity((Int32)cchReferencedDomainName + 1);

            object[] LookupAccountSidArgs2 =
            {
                    String.Empty, sid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, sidNameUse
            };
            //LookupAccountSid(String.Empty, sid, lpName, ref cchName, lpReferencedDomainName, ref cchReferencedDomainName, out sidNameUse);
            InvokeItDynamically.DynGen.DynamicAPIInvoke("advapi32.dll", "LookupAccountSidA", typeof(LookupAccountSid), ref LookupAccountSidArgs2, true, true);
            sidNameUse = (_SID_NAME_USE)LookupAccountSidArgs2[6];

            if (lpReferencedDomainName.Length > 0)
            {
                sbUserName.Append(lpReferencedDomainName);
            }

            if (sbUserName.Length > 0)
            {
                sbUserName.Append(@"\");
            }

            if (lpName.Length > 0)
            {
                sbUserName.Append(lpName);
            }

            userName = sbUserName.ToString();

            if (String.IsNullOrEmpty(userName))
            {
                return false;
            }
            else
            {
                return true;
            }
        }
        /////////////////////////////////////////////////////////////////////////////
        // Find user via Process ID
        ////////////////////////////////////////////////////////////////////////////////
        public static Dictionary<String, UInt32> WMIEnumerateUserforProcID(int ProcID)
        {
            Dictionary<String, UInt32> users = new Dictionary<String, UInt32>();
            List<ManagementObject> systemProcesses = new List<ManagementObject>();
            ManagementScope scope = new ManagementScope("\\\\.\\root\\cimv2");
            scope.Connect();
            if (!scope.IsConnected)
            {
                Console.WriteLine("[-] Failed to connect to WMI");
            }

            ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_Process");
            ManagementObjectSearcher objectSearcher = new ManagementObjectSearcher(scope, query);
            ManagementObjectCollection objectCollection = objectSearcher.Get();
            Console.WriteLine("[*] Examining " + objectCollection.Count + " processes");
            foreach (ManagementObject managementObject in objectCollection)
            {
                try
                {
                    String[] owner = new String[2];
                    managementObject.InvokeMethod("GetOwner", (object[])owner);
                    if (!users.ContainsKey((owner[1] + "\\" + owner[0]).ToUpper()))
                    {
                        if ((UInt32)managementObject["ProcessId"] == ProcID)
                        {
                            users.Add((owner[1] + "\\" + owner[0]).ToUpper(), (UInt32)managementObject["ProcessId"]);
                        }
                    }
                }
                catch (ManagementException error)
                {
                    Console.WriteLine("[-] " + error);
                }
            }
            return users;
        }
        ////////////////////////////////////////////////////////////////////////////////
        // Finds a process per user discovered
        // ToDo: check if token is a primary token
        ////////////////////////////////////////////////////////////////////////////////
        public static Dictionary<String, UInt32> EnumerateTokens(Boolean findElevation)
        {
            Dictionary<String, UInt32> users = new Dictionary<String, UInt32>();
            foreach (Process p in Process.GetProcesses())
            {


                // NtOpenProcess
                IntPtr stub = InvokeItDynamically.DynGen.GetSyscallStub("NtOpenProcess");
                NtOpenProcess OpenProc = (NtOpenProcess)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtOpenProcess));

                IntPtr hProcess = IntPtr.Zero;
                OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();

                CLIENT_ID ci = new CLIENT_ID
                {
                    UniqueProcess = (IntPtr)((UInt32)p.Id)
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

                if (IntPtr.Zero == hProcess)
                {

                    Console.WriteLine("[-] Proc Handle not valid");

                    continue;
                }
#endif
                IntPtr hToken = IntPtr.Zero;
                // NtOpenProcessToken
                stub = InvokeItDynamically.DynGen.GetSyscallStub("NtOpenProcessToken");
                NtOpenProcessToken NtOpenProcTok = (NtOpenProcessToken)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtOpenProcessToken));

                statusresult = NtOpenProcTok(
                    hProcess,
                    (UInt32)ACCESS_MASK.MAXIMUM_ALLOWED,
                    out hToken);
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

                if (findElevation)
                {
                    if (!CheckPrivileges.CheckElevation(hToken))
                    {
                        continue;
                    }
                }


                _TOKEN_STATISTICS tokenStatistics = new _TOKEN_STATISTICS();
                //Split up impersonation and primary tokens
                if (_TOKEN_TYPE.TokenImpersonation == tokenStatistics.TokenType)
                {
                    continue;
                }


                // NtQueryInformationToken
                stub = InvokeItDynamically.DynGen.GetSyscallStub("NtQueryInformationToken");
                NtQueryInformationToken NtQueryInformationTok = (NtQueryInformationToken)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtQueryInformationToken));
                int ReturnLength;
                //IntPtr buffer = IntPtr.Zero;
                var uintresult = NtQueryInformationTok(hToken, 10 /*TokenStatistics*/, IntPtr.Zero, 0, out ReturnLength);
                #if DEBUG
                if (uintresult == 0)
                {
                    Console.WriteLine("\r\n[+] NtQueryInformationToken Success!");
                }
                else
                {
                    Console.WriteLine("[-] NtQueryInformationToken failed - error code: " + uintresult);
                }
#endif

                IntPtr buffer = Marshal.AllocHGlobal((int)ReturnLength);

                if (uintresult >= 0)
                {
                    uintresult = NtQueryInformationTok(hToken, 10 /*TokenStatistics*/, buffer, ReturnLength, out ReturnLength);
                    if (uintresult == 0)
                    {
                        #if DEBUG
                        Console.WriteLine("[+] NtQueryInformationToken Success!");
#endif
                        tokenStatistics = (_TOKEN_STATISTICS)Marshal.PtrToStructure(buffer, typeof(_TOKEN_STATISTICS));
                    }
                    else
                    {
                        Console.WriteLine("[-] NtQueryInformationToken failed: {0}", Marshal.GetLastWin32Error());
                        continue;
                    }
                    Marshal.FreeHGlobal(buffer);

                }
                else
                {
                    tokenStatistics = (_TOKEN_STATISTICS)Marshal.PtrToStructure(buffer, typeof(_TOKEN_STATISTICS));
                }

                // NtClose
                stub = InvokeItDynamically.DynGen.GetSyscallStub("NtClose");
                NtClose NtClose = (NtClose)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtClose));
                statusresult = NtClose(hToken);
#if DEBUG
                if (statusresult == 0)
                {
                    Console.WriteLine("\r\n[+] NtClose Success!");
                }
                else
                {
                    Console.WriteLine("[-] NtClose failed - error code: " + statusresult);
                }
#endif
               

                String userName = String.Empty;
                if (!ConvertTokenStatisticsToUsername(tokenStatistics, ref userName))
                {
                    continue;
                }

                if (!users.ContainsKey(userName))
                {
                    ////////////////////////////////////////////////////////////////////////////////
                    // Finds a process with the SYSTEM token that is NOT protected (0xFFFFFFFE)
                    // https://bit.ly/37ITNWi
                    // (bitly link for Process Protection entry at docs.microsoft.com)
                    ////////////////////////////////////////////////////////////////////////////////

                    
                    if (userName != null)//"NT AUTHORITY\\SYSTEM" || userName == "NT-AUTORITÄT\\SYSTEM")
                    {
                        /* Allocate memory for a new PS_PROTECTION */
                        _PROCESS_PROTECTION_LEVEL_INFORMATION psProtection = new _PROCESS_PROTECTION_LEVEL_INFORMATION();
                        IntPtr outLong = Marshal.AllocHGlobal(sizeof(long));

                        /* Prepare the Args for GetProcessInformation */
                        object[] ProtectionInformationArgs =
                        {
                            hProcess, _PROCESS_INFORMATION_CLASS.ProcessProtectionLevelInfo, psProtection, (uint)Marshal.SizeOf(typeof(_PROCESS_PROTECTION_LEVEL_INFORMATION))
                        };

                        /* Call GetProcessInformation and output Process Protection Level Info */
                        var result = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "GetProcessInformation", typeof(GetProcessInformation), ref ProtectionInformationArgs, true, true);

                        if (!result)
                        {
                            Console.WriteLine("GetProcessInformation: {0}", Marshal.GetLastWin32Error());
                            continue;
                        }

                        /* Ensure that the Process Protection Level is casted and saved to 'psProtection' */
                        psProtection = (_PROCESS_PROTECTION_LEVEL_INFORMATION)ProtectionInformationArgs[2];

                        /* String Format protHex and IF 'PROTECTION_LEVEL_NONE' (0xFFFFFFFE), then add to 'users' dictionary */
                        string protHex = psProtection.ProtectionLevel.ToString("x8");
                        protHex = protHex.ToUpper();
                        // Console.WriteLine(string.Format("[+] Protection for PID {0} is 0x{1}", (UInt32)p.Id, protHex));

                        if (protHex == "FFFFFFFE")
                        {
                            users.Add(userName, (UInt32)p.Id);
                        }
                    }
                    else
                    {
                        users.Add(userName, (UInt32)p.Id);
                    }
                }


                // NtClose
                statusresult = NtClose(hProcess);
#if DEBUG
                if (statusresult == 0)
                {
                    Console.WriteLine("\r\n[+] NtClose Success!");
                }
                else
                {
                    Console.WriteLine("[-] NtClose failed - error code: " + statusresult);
                }
#endif

            }
            return users;
        }

        /////////////////////////////////////////////////////////////////////////////
        // Lists tokens via WMI
        ////////////////////////////////////////////////////////////////////////////////
        public static Dictionary<String, UInt32> EnumerateTokensWMI()
        {
            Dictionary<String, UInt32> users = new Dictionary<String, UInt32>();
            List<ManagementObject> systemProcesses = new List<ManagementObject>();
            ManagementScope scope = new ManagementScope("\\\\.\\root\\cimv2");
            scope.Connect();
            if (!scope.IsConnected)
            {
                Console.WriteLine("[-] Failed to connect to WMI");
            }

            ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_Process");
            ManagementObjectSearcher objectSearcher = new ManagementObjectSearcher(scope, query);
            ManagementObjectCollection objectCollection = objectSearcher.Get();
            Console.WriteLine("[*] Examining " + objectCollection.Count + " processes");
            foreach (ManagementObject managementObject in objectCollection)
            {
                try
                {
                    String[] owner = new String[2];
                    managementObject.InvokeMethod("GetOwner", (object[])owner);
                    if (!users.ContainsKey((owner[1] + "\\" + owner[0]).ToUpper()))
                    {
                        users.Add((owner[1] + "\\" + owner[0]).ToUpper(), (UInt32)managementObject["ProcessId"]);
                    }
                }
                catch (ManagementException error)
                {
                    Console.WriteLine("[-] " + error);
                }
            }
            return users;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Find processes for a user via Tokens
        ////////////////////////////////////////////////////////////////////////////////

        public static Dictionary<String, UInt32> EnumerateUserProcesses(Boolean findElevation, String userAccount)
        {
            Dictionary<String, UInt32> users = new Dictionary<String, UInt32>();
            Process[] pids = Process.GetProcesses();
            Console.WriteLine("[*] Examining {0} processes", pids.Length);
            foreach (Process p in pids)
            {

                bool endsearch = false;
                // NtOpenProcess
                IntPtr stub = InvokeItDynamically.DynGen.GetSyscallStub("NtOpenProcess");
                NtOpenProcess OpenProc = (NtOpenProcess)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtOpenProcess));

                IntPtr hProcess = IntPtr.Zero;
                OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();

                CLIENT_ID ci = new CLIENT_ID
                {
                    UniqueProcess = (IntPtr)((UInt32)p.Id)
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


                if (IntPtr.Zero == hProcess)
                {
                    continue;
                }
                IntPtr hToken = IntPtr.Zero;

                // NtOpenProcessToken
                stub = InvokeItDynamically.DynGen.GetSyscallStub("NtOpenProcessToken");
                NtOpenProcessToken NtOpenProcTok = (NtOpenProcessToken)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtOpenProcessToken));

                statusresult = NtOpenProcTok(
                    hProcess,
                    (UInt32)ACCESS_MASK.MAXIMUM_ALLOWED,
                    out hToken);
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


                // NtClose
                stub = InvokeItDynamically.DynGen.GetSyscallStub("NtClose");
                NtClose NtClose = (NtClose)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtClose));

                //statusresult = NtClose(hProcess);
#if DEBUG
                if (statusresult == 0)
                {
                    Console.WriteLine("\r\n[+] NtClose Success!");
                }
                else
                {
                    Console.WriteLine("[-] NtClose failed - error code: " + statusresult);
                }
#endif

                if (findElevation && !CheckPrivileges.CheckElevation(hToken))
                {
                    continue;
                }


                _TOKEN_STATISTICS tokenStatistics = new _TOKEN_STATISTICS();


                // NtQueryInformationToken
                stub = InvokeItDynamically.DynGen.GetSyscallStub("NtQueryInformationToken");
                NtQueryInformationToken NtQueryInformationTok = (NtQueryInformationToken)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtQueryInformationToken));
                int ReturnLength;
                //IntPtr buffer = IntPtr.Zero;
                var uintresult = NtQueryInformationTok(hToken, 10 /*TokenStatistics*/, IntPtr.Zero, 0, out ReturnLength);
#if DEBUG
                if (uintresult == 0)
                {
                    Console.WriteLine("\r\n[+] NtQueryInformationToken Success!");
                }
                else
                {
                    Console.WriteLine("[-] NtQueryInformationToken failed - error code: " + uintresult);
                }
#endif

                IntPtr buffer = Marshal.AllocHGlobal((int)ReturnLength);

                if (uintresult >= 0)
                {
                    uintresult = NtQueryInformationTok(hToken, 10 /*TokenStatistics*/, buffer, ReturnLength, out ReturnLength);
                    if (uintresult == 0)
                    {
                        tokenStatistics = (_TOKEN_STATISTICS)Marshal.PtrToStructure(buffer, typeof(_TOKEN_STATISTICS));
                    }
                    else
                    {
                        Console.WriteLine("[-] NtQueryInformationToken failed: {0}", Marshal.GetLastWin32Error());
                        continue;
                    }
                    Marshal.FreeHGlobal(buffer);

                }
                else
                {
                    tokenStatistics = (_TOKEN_STATISTICS)Marshal.PtrToStructure(buffer, typeof(_TOKEN_STATISTICS));
                }


                statusresult = NtClose(hToken);
#if DEBUG
                if (statusresult == 0)
                {
                    Console.WriteLine("\r\n[+] NtClose Success!");
                }
                else
                {
                    Console.WriteLine("[-] NtClose failed - error code: " + statusresult);
                }
#endif


                if (_TOKEN_TYPE.TokenImpersonation == tokenStatistics.TokenType)
                {
                    continue;
                }


                String userName = String.Empty;
                if (!ConvertTokenStatisticsToUsername(tokenStatistics, ref userName))
                {
                    continue;
                }


                if (!users.ContainsKey(userName))
                {
                    ////////////////////////////////////////////////////////////////////////////////
                    // Finds a process with the SYSTEM token that is NOT protected (0xFFFFFFFE)
                    // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_protection_level_information
                    ////////////////////////////////////////////////////////////////////////////////

                    if (userName != null)
                    {
                        /* Allocate memory for a new PS_PROTECTION */
                        _PROCESS_PROTECTION_LEVEL_INFORMATION psProtection = new _PROCESS_PROTECTION_LEVEL_INFORMATION();
                        IntPtr outLong = Marshal.AllocHGlobal(sizeof(long));

                        /* Prepare the Args for GetProcessInformation */
                        object[] ProtectionInformationArgs =
                        {
                            hProcess, _PROCESS_INFORMATION_CLASS.ProcessProtectionLevelInfo, psProtection, (uint)Marshal.SizeOf(typeof(_PROCESS_PROTECTION_LEVEL_INFORMATION))
                        };

                        /* Call GetProcessInformation and output Process Protection Level Info */
                        var result = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "GetProcessInformation", typeof(GetProcessInformation), ref ProtectionInformationArgs, true, true);

                        if (!result)
                        {
                            Console.WriteLine("GetProcessInformation: {0}", Marshal.GetLastWin32Error());
                            continue;
                        }

                        /* Ensure that the Process Protection Level is casted and saved to 'psProtection' */
                        psProtection = (_PROCESS_PROTECTION_LEVEL_INFORMATION)ProtectionInformationArgs[2];

                        /* String Format protHex and IF 'PROTECTION_LEVEL_NONE' (0xFFFFFFFE), then add to 'users' dictionary */
                        string protHex = psProtection.ProtectionLevel.ToString("x8");
                        protHex = protHex.ToUpper();
                        
                        if (userName.ToUpper() == userAccount.ToUpper() && (p.ProcessName != "svchost"))
                        {
                            Console.WriteLine("[+] Process found");
                            Console.WriteLine("[+] Process: " + p.ProcessName + " with ID: " + (UInt32)p.Id);
                            if (protHex == "FFFFFFFE")
                            {
                                users.Add(p.ProcessName, (UInt32)p.Id);
                                endsearch = true;
                            }
                        }
                        
                    }
                    else
                    {
                        Console.WriteLine("Invalid username");
                    }
                    if (endsearch)
                    {
                        break;
                    }
                }


                if (findElevation)
                {
                    return users;
                }
                


            }
            
            Dictionary<String, UInt32> sorted = new Dictionary<String, UInt32>();
            foreach (var user in users.OrderBy(u => u.Value))
            {
                sorted.Add(user.Key, user.Value);
            }

            return sorted;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Find processes for user via WMI
        ////////////////////////////////////////////////////////////////////////////////
        public static Dictionary<UInt32, String> EnumerateUserProcessesWMI(String userAccount)
        {
            Dictionary<UInt32, String> processes = new Dictionary<UInt32, String>();
            List<ManagementObject> systemProcesses = new List<ManagementObject>();
            ManagementScope scope = new ManagementScope("\\\\.\\root\\cimv2");
            scope.Connect();
            if (!scope.IsConnected)
            {
                Console.WriteLine("[-] Failed to connect to WMI");
            }

            ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_Process");
            ManagementObjectSearcher objectSearcher = new ManagementObjectSearcher(scope, query);
            ManagementObjectCollection objectCollection = objectSearcher.Get();
            Console.WriteLine("[*] Examining " + objectCollection.Count + " processes");
            foreach (ManagementObject managementObject in objectCollection)
            {
                try
                {
                    String[] owner = new String[2];
                    managementObject.InvokeMethod("GetOwner", (object[])owner);
                    if ((owner[1] + "\\" + owner[0]).ToUpper() == userAccount.ToUpper())
                    {
                        processes.Add((UInt32)managementObject["ProcessId"], (String)managementObject["Name"]);
                    }
                }
                catch (ManagementException error)
                {
                    Console.WriteLine("[-] " + error);
                }
            }
            Console.WriteLine("[*] Discovered {0} processes", processes.Count);
            return processes;
        }
    }
}

