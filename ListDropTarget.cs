using GongSolutions.Wpf.DragDrop;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Windows.Controls;
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
            if (dropInfo.Data is IEnumerable)
            {
                foreach (var item in dropInfo.Data as IEnumerable)
                {
                    ic.Add(item);
                }
            }
            else
            {
                ic.Add(dropInfo.Data);
            }
        }

        public override object ProvideValue(IServiceProvider serviceProvider)
        {
            return this;
        }
    }
}
