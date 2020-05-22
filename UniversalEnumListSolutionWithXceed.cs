using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Windows.Data;
using System.Windows.Markup;

namespace WPF_dnscrypt_proxy_md
{
    /* I was feckly waiting on for half an hour for git pulling of Xceed.Wpf.Toolkit from github(depth=1)
     * I attached it and converted it to netcoreapp3.1 wpf profile in less than 5 minutes
     * I have to figure out the internal mystery of the Selector class
     * I have to modify it since I had named this frankly new cs file 'UniversalEnumListSolutionWithXceed' in the first place
     * Now feel free to copy all around to your business working codes, I just did it.
     * Happy ending
     */
    [Flags]
    public enum ServerFlag
    {
        DNSSEC = 1,
        [DisplayString("No Log")]
        NoLog = 1 << 1,
        [DisplayString("No Filter")]
        NoFilter = 1 << 2,
    }

    public enum Protocol
    {
        Plain = 0,
        DNSCrypt,
        DoH,
        TLS,
        DNSCryptRelay = 0x83,
    }

    public class EnumConverter : MarkupExtension, IValueConverter
    {
        public EnumConverter() {}
        public object Convert(object value, Type targetType, object parameter,
                              System.Globalization.CultureInfo culture)
        {
            if (parameter is Type && null != value && value.ToString() != string.Empty)
            {
                var enumValue = (Enum)Enum.Parse((Type)parameter, value.ToString());
                string getDisplayText(string itemString, Type t){
                    var field = t.GetField(itemString);
                    if (null == field) return null; //out scope of mapping
                    var attribs = field.GetCustomAttributes(typeof(DisplayStringAttribute), false);
                    return null != attribs && attribs.Length > 0 ? ((DisplayStringAttribute)attribs[0]).Value : itemString;
                }
                var list = (from str in enumValue.ToString().Split(',')
                            let itemString = str.Trim()
                            let t= (Type)parameter
                            let text = getDisplayText(itemString, t)
                            select new KeyValuePair<long?, string>(
                            System.Convert.ToInt64(Enum.Parse((Type)parameter, itemString)), text)).ToList();
                return list;
            }
            else
            {
                return new List<KeyValuePair<long?, string>>();
            }
        }

        public object ConvertBack(object value, Type targetType, object parameter,
                                  System.Globalization.CultureInfo culture)
        {
            Int64? returnValue = null;
            if (null == value)
                return null;
            if (parameter is Type)
            {
                var list = value as IList<KeyValuePair<long?, string>>;
                returnValue = (from item in list select item.Key).DefaultIfEmpty(null).Aggregate((a, b) => a | b);
            }
            return returnValue;
        }

        public override object ProvideValue(IServiceProvider serviceProvider)
        {
            return this;
        }
    }


    [AttributeUsage(AttributeTargets.Field)]
    public sealed class DisplayStringAttribute : Attribute
    {
        private readonly string value;
        public string Value
        {
            get { return value; }
        }

        public string ResourceKey { get; set; }

        public DisplayStringAttribute(string v)
        {
            this.value = v;
        }

        public DisplayStringAttribute()
        {
        }
    }
    

    /// <summary>
    /// Markup extension that provides a list of the members of a given enum.
    /// </summary>
    public class EnumListExtension : MarkupExtension
    {
        #region Member Variables


        private Type _enumType;
        private bool _asString;


        #endregion //Member Variables


        #region Constructor
        /// <summary>
        /// Initializes a new <see cref=”EnumListExtension”/>
        /// </summary>
        public EnumListExtension()
        {
        }


        /// <summary>
        /// Initializes a new <see cref=”EnumListExtension”/>
        /// </summary>
        /// <param name=”enumType”>The type of enum whose members are to be returned.</param>
        public EnumListExtension(Type enumType)
        {
            this.EnumType = enumType;
        }
        #endregion //Constructor


        #region Properties
        /// <summary>
        /// Gets/sets the type of enumeration to return 
        /// </summary>
        public Type EnumType
        {
            get { return this._enumType; }
            set
            {
                if (value != this._enumType)
                {
                    if (null != value)
                    {
                        Type enumType = Nullable.GetUnderlyingType(value) ?? value;

                        if (enumType.IsEnum == false)
                            throw new ArgumentException("Type must be for an Enum.");
                    }


                    this._enumType = value;
                }
            }
        }

        public bool DBNull { get; set; }

        /// <summary>
        /// Gets/sets a value indicating whether to display the enumeration members as strings using the Description on the member if available.
        /// </summary>
        public bool AsString
        {
            get { return this._asString; }
            set { this._asString = value; }
        }
        #endregion //Properties

        #region Base class overrides
        /// <summary>
        /// Returns a list of items for the specified <see cref=”EnumType”/>. Depending on the <see cref=”AsString”/> property, the 
        /// items will be returned as the enum member value or as strings.
        /// </summary>
        /// <param name=”serviceProvider”>An object that provides services for the markup extension.</param>
        /// <returns></returns>
        public override object ProvideValue(IServiceProvider serviceProvider)
        {
            if (null == this._enumType)
                throw new InvalidOperationException("The EnumType must be specified.");

            Type actualEnumType = Nullable.GetUnderlyingType(this._enumType) ?? this._enumType;
            Array enumValues = Enum.GetValues(actualEnumType);

            // if the object itself is to be returned then just use GetValues
            // 
            if (this._asString == false)
            {
                if (actualEnumType == this._enumType)
                    return enumValues;

                Array tempArray = Array.CreateInstance(actualEnumType, enumValues.Length + 1);
                enumValues.CopyTo(tempArray, 1);
                return tempArray;
            }
            var items = new Dictionary<long?, string>();
            if (actualEnumType != this._enumType)
                items.Add(null, string.Empty);

            // otherwise we must process the list
            foreach (object item in (from object v in Enum.GetValues(this._enumType) orderby (int)v select v))
            {
                string itemString = item.ToString();
                FieldInfo field = this._enumType.GetField(itemString);
                object[] attribs = field.GetCustomAttributes(typeof(DisplayStringAttribute), false);

                if (null != attribs && attribs.Length > 0)
                    itemString = ((DisplayStringAttribute)attribs[0]).Value;
                if (item.ToString().ToLower() == "none" && DBNull)
                {
                    items.Add(null, string.Empty);
                    continue;
                }
                items.Add(Convert.ToInt64(item), itemString);
            }
            return items;
        }
        #endregion //Base class overrides
    }
}