using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Markup;
using System.Windows.Media;

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

    public static class Extensions
    {
        public static IEnumerable<ChildT> FindVisualChild<ChildT>(this DependencyObject obj) where ChildT : DependencyObject
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
    }

    public class NamesRule : ValidationRule
    {
        public const string Error = "duplicate name";
        public ListView Source { get; set; }
        public object Current { get; set; }
        public override ValidationResult Validate(object value, CultureInfo cultureInfo)
        {
            if (null != cultureInfo)
                (App.Current.MainWindow as MainWindow).ValidateListViewItems();
            foreach (dynamic item in Source.Items)
            {
                if (value is BindingExpression be && be.DataItem is ExpandoObject eo)
                {
                    if (item != be.DataItem && item.Name == (string)((dynamic)(eo)).Name)
                        return new ValidationResult(false, Error);
                }
            }
            return ValidationResult.ValidResult;
        }
    }
}
