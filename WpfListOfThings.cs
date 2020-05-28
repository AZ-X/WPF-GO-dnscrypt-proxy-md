using System;
using System.Dynamic;
using System.Globalization;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Markup;

namespace WPF_dnscrypt_proxy_md
{
    public class IndexConverter : MarkupExtension, IValueConverter
    {
        public object Convert(object value, Type TargetType, object parameter, CultureInfo culture)
        {
            var item = (ListViewItem)value;
            var listView = ItemsControl.ItemsControlFromItemContainer(item) as ListView;
            var index = listView.ItemContainerGenerator.IndexFromContainer(item) + 1;
            return index.ToString();
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }

        public override object ProvideValue(IServiceProvider serviceProvider)
        {
            return this;
        }
    }

    public class NamesRule : ValidationRule
    {
        public ListView Source { get; set; }
        public object Current { get; set; }
        public override ValidationResult Validate(object value, CultureInfo cultureInfo)
        {
            foreach (dynamic item in Source.Items)
            {
                if (value is BindingExpression be && be.DataItem is ExpandoObject eo)
                {
                    if (item != be.DataItem && item.Name == (string)((dynamic)(eo)).Name)
                        return new ValidationResult(false, "duplicate name");
                }
            }
            return ValidationResult.ValidResult;
        }
    }
}
