using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace SplitLane.App.Infrastructure;

/// <summary>
/// A sidebar entry: a radio button that also carries an icon and an optional count.
/// </summary>
/// <remarks>
/// A derived control rather than attached properties, so the nav template can bind to real
/// dependency properties and the markup for each entry stays one line.
/// </remarks>
public sealed class NavButton : RadioButton
{
    /// <summary>Backing store for <see cref="Icon"/>.</summary>
    public static readonly DependencyProperty IconProperty =
        DependencyProperty.Register(nameof(Icon), typeof(Geometry), typeof(NavButton));

    /// <summary>Backing store for <see cref="BadgeText"/>.</summary>
    public static readonly DependencyProperty BadgeTextProperty =
        DependencyProperty.Register(
            nameof(BadgeText), typeof(string), typeof(NavButton),
            new PropertyMetadata(null, OnBadgeTextChanged));

    private static readonly DependencyPropertyKey HasBadgePropertyKey =
        DependencyProperty.RegisterReadOnly(
            nameof(HasBadge), typeof(bool), typeof(NavButton), new PropertyMetadata(false));

    /// <summary>Backing store for <see cref="HasBadge"/>.</summary>
    public static readonly DependencyProperty HasBadgeProperty = HasBadgePropertyKey.DependencyProperty;

    /// <summary>Glyph shown to the left of the label.</summary>
    public Geometry? Icon
    {
        get => (Geometry?)GetValue(IconProperty);
        set => SetValue(IconProperty, value);
    }

    /// <summary>Count shown on the right, or null for none.</summary>
    public string? BadgeText
    {
        get => (string?)GetValue(BadgeTextProperty);
        set => SetValue(BadgeTextProperty, value);
    }

    /// <summary>
    /// Whether the badge is worth drawing.
    /// </summary>
    /// <remarks>
    /// A count of zero is not information — an empty pill next to "Applications" says nothing and
    /// costs a glance. Computed here rather than with a converter so the template stays declarative.
    /// </remarks>
    public bool HasBadge
    {
        get => (bool)GetValue(HasBadgeProperty);
        private set => SetValue(HasBadgePropertyKey, value);
    }

    private static void OnBadgeTextChanged(DependencyObject sender, DependencyPropertyChangedEventArgs e)
    {
        if (sender is not NavButton button)
        {
            return;
        }

        var text = e.NewValue as string;
        button.HasBadge = !string.IsNullOrWhiteSpace(text) && text != "0";
    }
}
