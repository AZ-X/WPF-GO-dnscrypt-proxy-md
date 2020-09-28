using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Windows;
using Microsoft.Win32.SafeHandles;

namespace WPF_dnscrypt_proxy_md
{
    /// <summary>
    /// Partially occupied for GO TEST //Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        public static dynamic GuiShow;
        public static dynamic GridShow;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
        }

        protected override void OnExit(ExitEventArgs e)
        {
            base.OnExit(e);
        }
    }

    public static class MyGreatGoTest
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct GoString
        {
            //or Marshal.StringToCoTaskMemUTF8
            [MarshalAs(UnmanagedType.LPUTF8Str)] public string p;
            public Int64 n;
            public static implicit operator GoString(string s)
            {
                return new GoString { n = s.Length, p = s };
            }
        }

        [SecurityPermission(SecurityAction.InheritanceDemand, UnmanagedCode = true)]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public class CStringHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            private CStringHandle() : base(true){}
            public static implicit operator string(CStringHandle s)
            {
                return s.IsInvalid || s.IsClosed ? null : Marshal.PtrToStringUTF8(s.handle);
            }
            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
            override protected bool ReleaseHandle()
            {
                GO_Free(this.handle);
                return true;
            }
        }

        [DllImport("kernel32.dll")]
        public static extern void AllocConsole();
        
        [DllImport("kernel32.dll")]
        public static extern void FreeConsole();

        [DllImport("stammel_go.dll", EntryPoint = "EXP_CreateSign", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        public static extern bool GO_CreateSign(GoString file);

        [DllImport("stammel_go.dll", EntryPoint = "EXP_CheckSignature", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        public static extern bool GO_CheckSignature(GoString file);
        
        [DllImport("stammel_go.dll", EntryPoint = "EXP_Free", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        public static extern void GO_Free(IntPtr ptr);

        [DllImport("stammel_go.dll", EntryPoint = "EXP_WriteStamp", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        public static extern CStringHandle GO_WriteStamp(GoString stampStr);

        [DllImport("stammel_go.dll", EntryPoint = "EXP_ReadStamp", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        public static extern CStringHandle GO_ReadStamp(GoString stampStr);
    }
}