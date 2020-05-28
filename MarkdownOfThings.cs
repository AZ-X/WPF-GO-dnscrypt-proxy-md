using Microsoft.DocAsCode.MarkdownLite;
using Microsoft.DocAsCode.MarkdownLite.Matchers;

namespace WPF_dnscrypt_proxy_md
{
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

    /// <summary>
    /// let's insist on the original style of ms renderer. have fun :)
    /// </summary>
    public class InsetSDNSMarkdownRenderer : MarkdownRenderer
    {
        public virtual StringBuffer Render(IMarkdownRenderer render, SDNSBlockToken token, IMarkdownContext context)
        {
            return $"{token.Text}\n";
        }
    }
}
