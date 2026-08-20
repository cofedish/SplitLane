using System.Windows;

namespace SplitLane.App.Infrastructure;

/// <summary>
/// Hint text shown in an empty input.
/// </summary>
/// <remarks>
/// WPF has no watermark. An unlabelled empty box is the commonest way a clean-looking interface
/// stops telling the user what it wants, so this exists rather than leaving a bare rectangle on the
/// Applications and picker screens.
/// </remarks>
public static class Placeholder
{
    /// <summary>Backing store for the attached hint text.</summary>
    public static readonly DependencyProperty TextProperty =
        DependencyProperty.RegisterAttached(
            "Text", typeof(string), typeof(Placeholder), new PropertyMetadata(string.Empty));

    /// <summary>Reads the hint text.</summary>
    public static string GetText(DependencyObject element)
    {
        ArgumentNullException.ThrowIfNull(element);
        return (string)element.GetValue(TextProperty);
    }

    /// <summary>Sets the hint text.</summary>
    public static void SetText(DependencyObject element, string value)
    {
        ArgumentNullException.ThrowIfNull(element);
        element.SetValue(TextProperty, value);
    }
}
