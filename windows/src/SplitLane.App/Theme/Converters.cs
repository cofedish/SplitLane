using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace SplitLane.App.Theme;

/// <summary>Shows or hides an element from a boolean.</summary>
public sealed class BoolToVisibilityConverter : IValueConverter
{
    /// <summary>When true, a true value hides rather than shows.</summary>
    public bool Invert { get; set; }

    /// <inheritdoc />
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var flag = value is bool b && b;
        if (Invert)
        {
            flag = !flag;
        }

        return flag ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Picks the colour for a lane label.
/// </summary>
/// <remarks>
/// Driven by the label text, not by the enum, because the label is what a user reads and the two
/// must never be able to disagree. Colour reinforces the word here; it never replaces it.
/// </remarks>
public sealed class LaneBrushConverter : IValueConverter
{
    /// <inheritdoc />
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => Lookup(value as string, tint: false);

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();

    internal static Brush Lookup(string? label, bool tint)
    {
        var key = label switch
        {
            "PROXY" => tint ? "ProxyTintBrush" : "ProxyBrush",
            "BLOCKED" => tint ? "BlockedTintBrush" : "BlockedBrush",
            "OFF" => tint ? "DirectTintBrush" : "DirectBrush",
            _ => tint ? "DirectTintBrush" : "DirectBrush",
        };

        return Application.Current.TryFindResource(key) as Brush ?? Brushes.Gray;
    }
}

/// <summary>Picks the faint background behind a lane label.</summary>
public sealed class LaneTintConverter : IValueConverter
{
    /// <inheritdoc />
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => LaneBrushConverter.Lookup(value as string, tint: true);

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Compares a bound enum to a literal, for radio-style selection.</summary>
public sealed class EnumEqualsConverter : IValueConverter
{
    /// <inheritdoc />
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is not null && parameter is not null &&
           string.Equals(value.ToString(), parameter.ToString(), StringComparison.Ordinal);

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        // Only a checked radio writes back; an unchecked one must leave the value alone, or the
        // group would clear itself as selection moves between members.
        if (value is bool selected && selected && parameter is not null)
        {
            return Enum.Parse(Nullable.GetUnderlyingType(targetType) ?? targetType, parameter.ToString()!);
        }

        return Binding.DoNothing;
    }
}
