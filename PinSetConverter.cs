using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Data;
using System.Windows.Markup;

namespace WPF_dnscrypt_proxy_md
{
    public class PinSetConverter : MarkupExtension, IValueConverter
    {
        public PinSetConverter() { }
        public object Convert(object value, Type targetType, object parameter,
                              System.Globalization.CultureInfo culture)
        {
            if(value is JArray ja)
            {
                return ja.ToString();
            }
            return null;
        }

        public object ConvertBack(object value, Type targetType, object parameter,
                                  System.Globalization.CultureInfo culture)
        {
            if(value is string json)
            {
                return JArray.Parse(json);
            }
            return new JArray();
        }

        public override object ProvideValue(IServiceProvider serviceProvider)
        {
            return this;
        }
    }

}
