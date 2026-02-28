using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace SecureDesktopLock.Utils
{
    /// <summary>
    /// Converts <c>bool</c> → <see cref="Visibility"/>.
    ///   <c>true</c>  → <see cref="Visibility.Visible"/>
    ///   <c>false</c> → <see cref="Visibility.Collapsed"/>
    /// </summary>
    [ValueConversion(typeof(bool), typeof(Visibility))]
    public sealed class BoolToVisibilityConverter : IValueConverter
    {
        public static readonly BoolToVisibilityConverter Default =
            new BoolToVisibilityConverter();

        public object Convert(object value, Type targetType,
            object parameter, CultureInfo culture)
        {
            return value is bool b && b
                ? Visibility.Visible
                : Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType,
            object parameter, CultureInfo culture) =>
            value is Visibility v && v == Visibility.Visible;
    }

    /// <summary>
    /// Converts <c>bool</c> → negated <c>bool</c>.
    ///   Used to bind <c>IsEnabled = !IsUnlocking</c>.
    /// </summary>
    [ValueConversion(typeof(bool), typeof(bool))]
    public sealed class BoolNegationConverter : IValueConverter
    {
        public static readonly BoolNegationConverter Default =
            new BoolNegationConverter();

        public object Convert(object value, Type targetType,
            object parameter, CultureInfo culture) =>
            value is bool b && !b;

        public object ConvertBack(object value, Type targetType,
            object parameter, CultureInfo culture) =>
            value is bool b && !b;
    }
}
