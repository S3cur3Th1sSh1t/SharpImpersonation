using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpImpersonation
{
    class CheckPrivileges
    {

        ////////////////////////////////////////////////////////////////////////////////
        //https://blogs.msdn.microsoft.com/cjacks/2006/10/08/how-to-determine-if-a-user-is-a-member-of-the-administrators-group-with-uac-enabled-on-windows-vista/
        ////////////////////////////////////////////////////////////////////////////////
        public static Boolean CheckElevation(IntPtr hToken)
        {
            Int32 output = -1;
            if (!_QueryTokenInformation(hToken, _TOKEN_INFORMATION_CLASS.TokenElevationType, ref output))
            {
                Tokens.GetWin32Error("TokenElevationType");
                return false;
            }

            switch ((TOKEN_ELEVATION_TYPE)output)
            {
                case TOKEN_ELEVATION_TYPE.TokenElevationTypeDefault:
                    ;
                    return false;
                case TOKEN_ELEVATION_TYPE.TokenElevationTypeFull:
                    return true;
                case TOKEN_ELEVATION_TYPE.TokenElevationTypeLimited:
                    return false;
                default:
                    return true;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Private function to query a token with an enumeration result
        ////////////////////////////////////////////////////////////////////////////////
        private static Boolean _QueryTokenInformation(IntPtr hToken, _TOKEN_INFORMATION_CLASS informationClass, ref Int32 dwTokenInformation)
        {
            UInt32 tokenInformationLength = (UInt32)Marshal.SizeOf(typeof(UInt32));
            IntPtr lpTokenInformation = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UInt32)));
            try
            {
                UInt32 returnLength = 0;

                object[] GetTokenInformationArgs =
                {
                    hToken, informationClass, lpTokenInformation, tokenInformationLength, returnLength
                };
                bool result = (bool)InvokeItDynamically.DynGen.DynamicAPIInvoke("advapi32.dll", "GetTokenInformation", typeof(GetTokenInformation), ref GetTokenInformationArgs, true, true);
                returnLength = (UInt32)GetTokenInformationArgs[4];

                if (!(result))
                {
                    Tokens.GetWin32Error("GetTokenInformation");
                    return false;
                }
                dwTokenInformation = Marshal.ReadInt32(lpTokenInformation);
            }
            catch (Exception ex)
            {
                Tokens.GetWin32Error("GetTokenInformation");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }
            finally
            {
                Marshal.FreeHGlobal(lpTokenInformation);
            }
            return true;
        }
    }
}

