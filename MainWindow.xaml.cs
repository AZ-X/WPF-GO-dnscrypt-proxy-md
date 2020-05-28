using Microsoft.DocAsCode.MarkdownLite;
using Microsoft.Win32;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Media;
using static WPF_dnscrypt_proxy_md.MyGreatGoTest;


namespace WPF_dnscrypt_proxy_md
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        static IEnumerable<ChildT> FindVisualChild<ChildT>(DependencyObject obj) where ChildT : DependencyObject
        {
            for (int i = 0; i < VisualTreeHelper.GetChildrenCount(obj); i++)
            {
                DependencyObject child = VisualTreeHelper.GetChild(obj, i);
                if (child is ChildT ct)
                    yield return ct;
                else
                {
                    foreach (var item in FindVisualChild<ChildT>(child))
                    {
                        yield return item;
                    }
                }
            }
        }

        private void IconButton_Click_1(object sender, RoutedEventArgs e)
        {
            var ofd = new OpenFileDialog
            {
                Filter = "Markdown Files (*.md)|*.md"
            };
            if (ofd.ShowDialog() == true)
            {
                this.FileName.Text = ofd.FileName;
                var meb = new MarkdownEngineBuilder(new Options
                {
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
                // End
                var me = meb.CreateEngine(null);
                try
                {

                    var tokens = me.Parser.Tokenize(SourceInfo.Create(File.ReadAllText(ofd.FileName), null));
                    MarkdownHeadingBlockToken hToken = null;
                    IMarkdownToken convert(IMarkdownToken t) =>
                        t is TwoPhaseBlockToken tpbt ? tpbt.Extract(me.Parser) as MarkdownHeadingBlockToken : t;
                    MarkdownHeadingBlockToken pop(IMarkdownToken t) => t is MarkdownHeadingBlockToken mdh ? hToken = mdh : hToken;
                    var q = from item in tokens
                            let header = pop(convert(item))
                            group item by header into g
                            select new { g.Key, Subs = g };
                    string strSdns = null;
                    string popSub(IMarkdownToken t) => t is SDNSBlockToken sdn ? strSdns = sdn.Text : null;
                    string reset() => strSdns = null;
                    //fidelity test
                    //bool? test(string j) { using (var json = GO_ReadStamp(j)) { using (var rt = GO_WriteStamp((string)json)) { using (var h = GO_ReadStamp((string)rt)) { return h.IsInvalid; } } } }
                    dynamic stamp(string j) { using (var json = GO_ReadStamp(j)) { return json.IsInvalid ? null : JsonConvert.DeserializeObject((string)json); }}
                    var refined = from item in q
                                  let text = ((MarkdownTextToken)item.Key.Content.Tokens[0]).Content
                                  let n = reset()
                                  let description = string.Concat(from sub in item.Subs
                                                                  let t = popSub(sub)
                                                                  let content = sub is MarkdownTextToken mtt ? mtt.Content : "\r\n"
                                                                  select content)
                                  let ostamp = strSdns == null ? null : stamp(strSdns)
                                  //let T = strSdns == null ? null : test(strSdns)
                                  select new { Name = text, Description = description, STAMP = ostamp };
                    App.GridShow = refined.ToList();
                    MyGrid.ItemsSource = App.GridShow;
                }
                catch (Exception ex)
                {
                    Xceed.Wpf.Toolkit.MessageBox.Show(ex.ToString());
                }
            }
        }

        private void IconButton_Click_2(object sender, RoutedEventArgs e)
        {
            try
            {
                Xceed.Wpf.Toolkit.MessageBox.Show($"Signature with its key pair is {(GO_CheckSignature(this.FileName.Text)? "valid" : "invalid or missing" )}.", "Result");
            }
            catch (Exception ex)
            {
                Xceed.Wpf.Toolkit.MessageBox.Show(ex.ToString());
            }

        }

        private void IconButton_Click_3(object sender, RoutedEventArgs e)
        {
            try
            {
                var sfd = new SaveFileDialog
                {
                    Filter = "Markdown Files (*.md)|*.md"
                };
                if (sfd.ShowDialog() == true)
                {
                    //count up null: 25
                    //Let's pretend to know a little about markdown 'lite' instead of manipulating string template which will make Team SH real clever
                    var result = StringBuffer.Empty;
                    var mdra = new MarkdownRendererAdapter(null, new InsetSDNSMarkdownRenderer(), null, null);
                    var rthToken = new InlineContent(
                        ImmutableArray.Create((IMarkdownToken)new MarkdownTextToken(null, null, null, SourceInfo.Create($"{sfd.SafeFileName} generated by WPF_dnscrypt_proxy_md", null))));
                    var rhToken = new MarkdownHeadingBlockToken(null, null, rthToken, null, 1, SourceInfo.Create(null, null));
                    result += mdra.Render(rhToken);
                    foreach (dynamic item in lv.Items)
                    {
                        var thToken = new InlineContent(ImmutableArray.Create((IMarkdownToken)new MarkdownTextToken(null, null, null, SourceInfo.Create(item.Name, null))));
                        var hToken = new MarkdownHeadingBlockToken(null, null, thToken, null, 2, SourceInfo.Create(null, null));
                        result += mdra.Render(hToken);
                        using (var stamp = GO_WriteStamp(JsonConvert.SerializeObject(item.STAMP)))
                        {
                            var sToken = new SDNSBlockToken(null, null, SourceInfo.Create(null, null), stamp);
                            result += mdra.Render(sToken);
                        }
                    }
                    File.WriteAllText(sfd.FileName, result);
                    if(!GO_CreateSign(sfd.FileName))
                        Xceed.Wpf.Toolkit.MessageBox.Show("Failed to create signature.");
                    else
                        Xceed.Wpf.Toolkit.MessageBox.Show("Saved.");
                }
            }
            catch (Exception ex)
            {
                Xceed.Wpf.Toolkit.MessageBox.Show(ex.ToString());
            }
        }
    }
}
