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
                object[] OpenProcessArgs = { Constants.PROCESS_QUERY_LIMITED_INFORMATION, true, (UInt32)p.Id };
                IntPtr hProcess = (IntPtr)InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "OpenProcess", typeof(OpenProcess), ref OpenProcessArgs, true, true);

                if (IntPtr.Zero == hProcess)
                {
                    Debug.WriteLine("[-] Open Process failed");
                    continue;
                }
                IntPtr hToken = IntPtr.Zero;

                object[] OpenProcessTokenArgs = { hProcess, (UInt32)ACCESS_MASK.MAXIMUM_ALLOWED, hToken };

                bool success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "OpenProcessToken", typeof(OpenProcessToken), ref OpenProcessTokenArgs, true, true);
                hToken = (IntPtr)OpenProcessTokenArgs[2];

                if (!(success))
                {
                    Console.WriteLine("[-] OpenProcessToken failed");
                    continue;
                }

                object[] CloseHandleArgs = { hProcess };
                InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "CloseHandle", typeof(CloseHandle), ref CloseHandleArgs, true, true);

                if (findElevation)
                {
                    if (!CheckPrivileges.CheckElevation(hToken))
                    {
                        continue;
                    }
                }

                UInt32 dwLength = 0;
                _TOKEN_STATISTICS tokenStatistics = new _TOKEN_STATISTICS();
                //Split up impersonation and primary tokens
                if (_TOKEN_TYPE.TokenImpersonation == tokenStatistics.TokenType)
                {
                    continue;
                }

                uint newLength = 0;
                object[] GetTokenInformationArgs =
                {
                    hToken, _TOKEN_INFORMATION_CLASS.TokenStatistics, tokenStatistics, dwLength, newLength
                };
                bool result = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("advapi32.dll", "GetTokenInformation", typeof(GetTokenInformation2), ref GetTokenInformationArgs, true, true);
                dwLength = (UInt32)GetTokenInformationArgs[4];
                tokenStatistics = (_TOKEN_STATISTICS)GetTokenInformationArgs[2];
                
                if (!result)
                {
                    object[] GetTokenInformationArgs2 =
                    {
                        hToken, _TOKEN_INFORMATION_CLASS.TokenStatistics, tokenStatistics, dwLength, newLength
                    };
                    dwLength = (UInt32)GetTokenInformationArgs2[4];
                    tokenStatistics = (_TOKEN_STATISTICS)GetTokenInformationArgs2[2];
                    result = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("advapi32.dll", "GetTokenInformation", typeof(GetTokenInformation2), ref GetTokenInformationArgs2, true, true);
                    dwLength = (UInt32)GetTokenInformationArgs2[4];
                    tokenStatistics = (_TOKEN_STATISTICS)GetTokenInformationArgs2[2];
                    if (!result)
                    {
                        Console.WriteLine("GetTokenInformation: {0}", Marshal.GetLastWin32Error());
                        continue;
                    }
                }

                object[] CloseHandleTokenArgs = { hToken };
                InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "CloseHandle", typeof(CloseHandle), ref CloseHandleTokenArgs, true, true);


                String userName = String.Empty;
                if (!ConvertTokenStatisticsToUsername(tokenStatistics, ref userName))
                {
                    continue;
                }

                if (!users.ContainsKey(userName))
                {
                    users.Add(userName, (UInt32)p.Id);
                }
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

        public static Dictionary<UInt32, String> EnumerateUserProcesses(Boolean findElevation, String userAccount)
        {
            Dictionary<UInt32, String> users = new Dictionary<UInt32, String>();
            Process[] pids = Process.GetProcesses();
            Console.WriteLine("[*] Examining {0} processes", pids.Length);
            foreach (Process p in pids)
            {
                object[] OpenProcessArgs = { Constants.PROCESS_QUERY_LIMITED_INFORMATION, true, (UInt32)p.Id };
                IntPtr hProcess = (IntPtr)InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "OpenProcess", typeof(OpenProcess), ref OpenProcessArgs, true, true);
                if (IntPtr.Zero == hProcess)
                {
                    continue;
                }
                IntPtr hToken = IntPtr.Zero;

                object[] OpenProcessTokenArgs = { hProcess, (UInt32)ACCESS_MASK.MAXIMUM_ALLOWED, hToken };

                bool success = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "OpenProcessToken", typeof(OpenProcessToken), ref OpenProcessTokenArgs, true, true);
                hToken = (IntPtr)OpenProcessTokenArgs[2];

                if (!(success))
                {
                    continue;
                }


                object[] CloseHandleArgs = { hProcess };
                InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "CloseHandle", typeof(CloseHandle), ref CloseHandleArgs, true, true);

                if (findElevation && !CheckPrivileges.CheckElevation(hToken))
                {
                    continue;
                }


                UInt32 dwLength = 0;
                _TOKEN_STATISTICS tokenStatistics = new _TOKEN_STATISTICS();

                uint newLength = 0;
                object[] GetTokenInformationArgs =
                {
                    hToken, _TOKEN_INFORMATION_CLASS.TokenStatistics, tokenStatistics, dwLength, newLength
                };
                bool result = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("advapi32.dll", "GetTokenInformation", typeof(GetTokenInformation2), ref GetTokenInformationArgs, true, true);
                dwLength = (UInt32)GetTokenInformationArgs[4];
                tokenStatistics = (_TOKEN_STATISTICS)GetTokenInformationArgs[2];
                //Console.WriteLine(result);
                if (!result)
                {
                    object[] GetTokenInformationArgs2 =
                    {
                        hToken, _TOKEN_INFORMATION_CLASS.TokenStatistics, tokenStatistics, dwLength, newLength
                    };
                    dwLength = (UInt32)GetTokenInformationArgs2[4];
                    tokenStatistics = (_TOKEN_STATISTICS)GetTokenInformationArgs2[2];
                    result = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("advapi32.dll", "GetTokenInformation", typeof(GetTokenInformation2), ref GetTokenInformationArgs2, true, true);
                    dwLength = (UInt32)GetTokenInformationArgs2[4];
                    tokenStatistics = (_TOKEN_STATISTICS)GetTokenInformationArgs2[2];
                    if (!result)
                    {
                        Console.WriteLine("GetTokenInformation: {0}", Marshal.GetLastWin32Error());
                        continue;
                    }
                }

                object[] CloseHandleTokenArgs = { hToken };
                InvokeItDynamically.DynGen.DynamicAPIInvoke("kernel32.dll", "CloseHandle", typeof(CloseHandle), ref CloseHandleTokenArgs, true, true);


                if (_TOKEN_TYPE.TokenImpersonation == tokenStatistics.TokenType)
                {
                    continue;
                }


                String userName = String.Empty;
                if (!ConvertTokenStatisticsToUsername(tokenStatistics, ref userName))
                {
                    continue;
                }
                if (userName.ToUpper() == userAccount.ToUpper())
                {
                    users.Add((UInt32)p.Id, p.ProcessName);
                    if (findElevation)
                    {
                        return users;
                    }
                }
            }
            Console.WriteLine("[*] Discovered {0} processes", users.Count);

            Dictionary<UInt32, String> sorted = new Dictionary<UInt32, String>();
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

