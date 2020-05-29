using GongSolutions.Wpf.DragDrop;
using System;
using System.Collections;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Dynamic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;

namespace WPF_dnscrypt_proxy_md
{
    public class ListDropTarget : MarkupExtension, IDropTarget
    {
        public void DragOver(IDropInfo dropInfo)
        {
            if(dropInfo.Data is IEnumerable data)
            {
                foreach(dynamic item in data)
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
                dropInfo.NotHandled = !(item is DataObject) && null != item.STAMP;
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
            if (dropInfo.Data is IEnumerable data)
            {
                foreach (dynamic item in data)
                {
                    Add(item);
                }
            }
            else
            {
                Add(dropInfo.Data);
            }
            ((MainWindow)App.Current.MainWindow).ValidateListViewItems();
        }

        public override object ProvideValue(IServiceProvider serviceProvider)
        {
            return this;
        }
    }
}
