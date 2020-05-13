using System;
using System.Collections.Immutable;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Windows;
using Microsoft.DocAsCode.MarkdownLite;
using Microsoft.DocAsCode.MarkdownLite.Matchers;
using Microsoft.Win32.SafeHandles;
using Newtonsoft.Json;
using static WPF_dnscrypt_proxy_md.MyGreatGoTest;

namespace WPF_dnscrypt_proxy_md
{
    /// <summary>
    ///    Occupied for GO TEST //Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        public static dynamic GuiShow;
        public static dynamic GridShow;

        protected override void OnStartup(StartupEventArgs e)
        {
            string sdns = "sdns://AgcAAAAAAAAADTIxNy4xNjkuMjAuMjMgPhoaD2xT8-l6SS1XCEtbmAcFnuBXqxUFh2_YP9o9uDgNZG5zLmFhLm5ldC51awovZG5zLXF1ZXJ5";
            try
            {
                // create C:\TEST\public-resolvers.pub and C:\TEST\public-resolvers.md.minisig from origin in advance
                var PASS = GO_CheckSignature(@"C:\TEST\public-resolvers.md");
                Debug.Assert(PASS);
                // can delete C:\TEST\public-resolvers.pub and C:\TEST\public-resolvers.md.minisig now if hit a break
                PASS = GO_CreateSign(@"C:\TEST\public-resolvers.md");
                Debug.Assert(PASS);
                PASS = GO_CheckSignature(@"C:\TEST\public-resolvers.md");
                Debug.Assert(PASS);
                string jStr;
                using (var json = GO_ReadStamp(sdns))
                {
                    var stamp = JsonConvert.DeserializeObject(json);
                    jStr = JsonConvert.SerializeObject(stamp);
                    GuiShow = stamp;
                }
                var rt = GO_WriteStamp(jStr);
                Debug.Assert(rt == sdns);
            }
            catch(Exception ex)
            {
                Debug.Write(ex);
            }
            var meb = new MarkdownEngineBuilder(new Options {
            });
            // BELOW essential codes copy from Microsoft Team SH(MingHang) ZI-ZHU, not so good, but works
            var builder = ImmutableList.CreateBuilder<IMarkdownRule>();
            builder.Add(new MarkdownNewLineBlockRule());
            builder.Add(new MarkdownHeadingBlockRule());
            builder.Add(new MarkdownLHeadingBlockRule());
            builder.Add(new MarkdownDefBlockRule());
            builder.Add(new SDNSBlockRule());
            builder.Add(new MarkdownTextBlockRule());
            meb.BlockRules = builder.ToImmutable();
            builder = ImmutableList.CreateBuilder<IMarkdownRule>();
            builder.Add(new MarkdownEscapeInlineRule());
            builder.Add(new MarkdownTagInlineRule());
            builder.Add(new MarkdownLinkInlineRule());
            builder.Add(new MarkdownStrongInlineRule());
            builder.Add(new MarkdownEmInlineRule());
            builder.Add(new MarkdownBrInlineRule());
            builder.Add(new MarkdownEscapedTextInlineRule());
            builder.Add(new MarkdownTextInlineRule());
            meb.InlineRules = builder.ToImmutable();
            var me = meb.CreateEngine(null);
            try
            {
                var tokens = me.Parser.Tokenize(SourceInfo.Create(File.ReadAllText(@"C:\TEST\public-resolvers.md"), null));
                MarkdownHeadingBlockToken hToken = null;
                IMarkdownToken convert(IMarkdownToken t) =>
                    t is TwoPhaseBlockToken ? ((TwoPhaseBlockToken)t).Extract(me.Parser) as MarkdownHeadingBlockToken : t;
                MarkdownHeadingBlockToken pop(IMarkdownToken t) => t is MarkdownHeadingBlockToken ? hToken = (MarkdownHeadingBlockToken)t : hToken;
                var q = from item in tokens
                        let header = pop(convert(item))
                        group item by header into g
                        select new { g.Key, Subs = g };
                string strSdns = null;
                string popSub(IMarkdownToken t) => t is SDNSBlockToken ? strSdns = ((SDNSBlockToken)t).Text : null;
                string reset() => strSdns = null;
                dynamic stamp(string j){using (var json = GO_ReadStamp(j)) {return json.IsInvalid ? null:JsonConvert.DeserializeObject((string)json); }}
                var refined = from item in q
                              let text = ((MarkdownTextToken)item.Key.Content.Tokens[0]).Content
                              let n = reset()
                              let description = string.Concat(from sub in item.Subs
                                                              let t = popSub(sub)
                                                              let content = sub is MarkdownTextToken ? ((MarkdownTextToken)sub).Content : "\r\n"
                                                              select content)
                              let ostamp = strSdns == null ? null : stamp(strSdns)
                              select new { Name = text, Description = description, Server= ostamp==null ? null:ostamp.ServerAddrStr, STAMP = ostamp };
                var sdnss = from item in tokens where item is SDNSBlockToken select item;
                Debug.WriteLine("found sdns in total:" + sdnss.Count());
                GridShow = refined.ToList();
            }
            catch (Exception ex)
            {
                Debug.Write(ex);
            }
            base.OnStartup(e);
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
    public class SDNSBlockToken : IMarkdownToken
    {
        public SDNSBlockToken(IMarkdownRule rule, IMarkdownContext context, SourceInfo sourceInfo, string text)
        {
            Rule = rule;
            Context = context;
            SourceInfo = sourceInfo;
            Text = text;
        }

        public IMarkdownRule Rule { get; }

        public IMarkdownContext Context { get; }

        public SourceInfo SourceInfo { get; }

        public string Text { get; }
    }
    public class SDNSBlockRule : IMarkdownRule
    {
        private static readonly Matcher _sdnsMatcher =
            Matcher.WhiteSpacesOrEmpty +
            (Matcher.String("sdns://").Repeat(1, 1) + 
            (Matcher.Char('-') 
            | Matcher.Char('_')
            | Matcher.AnyCharInRange('a', 'z')
            | Matcher.AnyCharInRange('A', 'Z')
            | Matcher.AnyCharInRange('0', '9')).RepeatAtLeast(13)).ToGroup("text") +
            Matcher.Char('\n');

        public virtual string Name => "SDNS";

        public virtual IMarkdownToken TryMatch(IMarkdownParser parser, IMarkdownParsingContext context)
        {
            var match = context.Match(_sdnsMatcher);
            return match?.Length > 0 ? new SDNSBlockToken(
                    this,
                    parser.Context,
                    context.Consume(match.Length),
                    match.GetGroup("text").Value.GetValue()) : null;
        }
    }
}