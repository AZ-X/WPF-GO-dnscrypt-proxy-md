using DataGridExtensions;
using System;
using System.Windows;

namespace WPF_dnscrypt_proxy_md
{
    /// <summary>
    /// Interaction logic for PopupEnumFilter.xaml
    /// </summary>
    public partial class PopupEnumFilter
    {
        public PopupEnumFilter()
        {
            InitializeComponent();
        }

        public int? FlagsValue
        {
            get { return (int?)GetValue(FlagsValueProperty); }
            set { SetValue(FlagsValueProperty, value); }
        }
        /// <summary>
        /// Identifies the Value dependency property
        /// </summary>
        public static readonly DependencyProperty FlagsValueProperty = DependencyProperty.Register("FlagsValue", typeof(int?), typeof(PopupEnumFilter)
                , new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.BindsTwoWayByDefault, (sender, e) => ((PopupEnumFilter)sender).FlagsValue_Changed()));


        public int? ProtocolValue
        {
            get { return (int?)GetValue(ProtocolValueProperty); }
            set { SetValue(ProtocolValueProperty, value); }
        }
        /// <summary>
        /// Identifies the Value dependency property
        /// </summary>
        public static readonly DependencyProperty ProtocolValueProperty = DependencyProperty.Register("ProtocolValue", typeof(int?), typeof(PopupEnumFilter)
                , new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.BindsTwoWayByDefault, (sender, e) => ((PopupEnumFilter)sender).ProtocolValue_Changed()));



        public IContentFilter Filter
        {
            get { return (IContentFilter)GetValue(FilterProperty); }
            set { SetValue(FilterProperty, value); }
        }

        /// <summary>
        /// Identifies the Filter dependency property
        /// </summary>
        public static readonly DependencyProperty FilterProperty =
            DependencyProperty.Register("Filter", typeof(IContentFilter), typeof(PopupEnumFilter), new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.BindsTwoWayByDefault));


        private void FlagsValue_Changed()
        {
            Filter = FlagsValue.HasValue ? new ContentFilter(FlagsValue, true) : null;
        }

        private void ProtocolValue_Changed()
        {
            Filter = ProtocolValue.HasValue ? new ContentFilter(ProtocolValue, false) : null;
        }

        class ContentFilter : IContentFilter
        {
            private readonly int? _val;
            bool Flags { get; set; }
            public ContentFilter(int? value, bool flags)
            {
                _val = value;
                Flags = flags;
            }

            public int? Value
            {
                get
                {
                    return _val;
                }
            }

            public bool IsMatch(object value)
            {
                return value==null?false: Flags?(Convert.ToInt32(value)&Value) == Value: Convert.ToInt32(value) == Value;
            }
        }

    }
}
