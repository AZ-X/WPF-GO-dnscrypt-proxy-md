using GongSolutions.Wpf.DragDrop;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Dynamic;
using System.Globalization;
using System.Linq.Expressions;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Markup;

namespace WPF_dnscrypt_proxy_md
{
    public class ListDropTarget : MarkupExtension, IDropTarget
    {
        public void DragOver(IDropInfo dropInfo)
        {
            if(dropInfo.Data is IEnumerable)
            {
                foreach(dynamic item in dropInfo.Data as IEnumerable)
                {
                    if (null == item.STAMP)
                    {
                        dropInfo.NotHandled = false;
                        break;
                    }
                    dropInfo.NotHandled = true;
                }
            }
            else
            {
                dynamic item = dropInfo.Data;
                dropInfo.NotHandled = null != item.STAMP;
            }
        }

        public void Drop(IDropInfo dropInfo)
        {
            var ic = dropInfo.TargetCollection as ItemCollection;
            void Add (dynamic item) {
                dynamic eo = new ExpandoObject();
                eo.Name = item.Name;
                eo.STAMP = item.STAMP;
                ic.Add(eo);
            };
            if (dropInfo.Data is IEnumerable)
            {
                foreach (dynamic item in dropInfo.Data as IEnumerable)
                {
                    Add(item);
                }
            }
            else
            {
                Add(dropInfo.Data);
            }
        }

        public override object ProvideValue(IServiceProvider serviceProvider)
        {
            return this;
        }
    }
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
}
