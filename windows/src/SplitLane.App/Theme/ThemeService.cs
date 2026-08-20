using System.Collections.Generic;
using System.Windows;
using System.Windows.Media;

namespace SplitLane.App.Theme;

/// <summary>Which look the application wears.</summary>
public enum AppTheme
{
    /// <summary>Whatever Windows is set to, and follows it when it changes.</summary>
    System,

    /// <summary>Always light.</summary>
    Light,

    /// <summary>Always dark.</summary>
    Dark,
}

/// <summary>
/// Repaints the application without rebuilding it.
/// </summary>
/// <remarks>
/// <para>
/// Every colour in the interface comes from a brush in <c>Palette.xaml</c>, and the templates reach
/// those brushes with <c>DynamicResource</c>. That is load-bearing rather than stylistic. WPF
/// freezes the brushes it finds in a resource dictionary, so they cannot be repainted in place, and
/// a <c>StaticResource</c> reference is resolved once at load and never looks again - between them,
/// the first attempt at this changed the dictionary and left every pixel on screen exactly as it
/// was.
/// </para>
/// <para>
/// So a theme here is a table of colours keyed by resource name, and applying it replaces those
/// entries. No restart, no rebuilt visual tree, and no second copy of the styles to keep in step
/// with the first.
/// </para>
/// <para>
/// The light palette is not the dark one inverted. Inverting produces grey text on white and washed
/// accents; the two are chosen separately, and the accent is darkened for light because a colour
/// that reads clearly against near-black does not read against near-white.
/// </para>
/// </remarks>
public static class ThemeService
{
    /// <summary>The theme currently painted, with System already resolved to Light or Dark.</summary>
    public static AppTheme Resolved { get; private set; } = AppTheme.Dark;

    /// <summary>Raised after a repaint, so a window can match its frame to the new look.</summary>
    public static event Action<AppTheme>? Changed;

    /// <summary>Paints the application in a theme, resolving System against Windows.</summary>
    public static void Apply(AppTheme theme)
    {
        var resolved = theme == AppTheme.System ? SystemTheme.Current() : theme;
        var colours = resolved == AppTheme.Light ? Light : Dark;
        var resources = Application.Current?.Resources;

        if (resources is null)
        {
            return;
        }

        foreach (var (key, value) in colours)
        {
            // A few entries are Colors rather than Brushes, because an animation interpolates a
            // colour and cannot be handed a brush.
            if (resources[key] is Color)
            {
                resources[key] = value;
                continue;
            }

            // Replaced rather than repainted. WPF freezes the brushes it finds in a resource
            // dictionary, so assigning to Color on one throws - which is why the templates reach
            // them through DynamicResource, so that a replacement is picked up.
            //
            // Translucency is part of the theme, not a constant.
            //
            // The dark surfaces are glass: 55% over an acrylic backdrop, which is what gives them
            // depth. The same 55% on light lets a dark desktop through and turns every card grey,
            // so light asks for more of itself and less of what is behind it.
            var opacity = Opacities.TryGetValue(key, out var perTheme)
                ? (resolved == AppTheme.Light ? perTheme.Light : perTheme.Dark)
                : resources[key] is SolidColorBrush existing ? existing.Opacity : 1.0;

            resources[key] = new SolidColorBrush(value) { Opacity = opacity };
        }

        ApplyGradients(resources, resolved);

        Resolved = resolved;
        Changed?.Invoke(resolved);
    }

    /// <summary>
    /// Repaints the gradients, which carry more than one colour each.
    /// </summary>
    /// <remarks>
    /// The glass edge is a white highlight along a panel's upper edge - the thing that makes a
    /// translucent surface look like a physical one. On a light ground white is invisible, so light
    /// borrows the same idea in reverse: a faint dark edge where the surface meets what is behind it.
    /// </remarks>
    private static void ApplyGradients(ResourceDictionary resources, AppTheme resolved)
    {
        var light = resolved == AppTheme.Light;

        SetStops(resources, "GlassEdgeBrush", light
            ? [Colour("#26FFFFFF"), Colour("#0E000000"), Colour("#00000000")]
            : [Colour("#40FFFFFF"), Colour("#14FFFFFF"), Colour("#00FFFFFF")]);

        SetStops(resources, "GlassSheenBrush", light
            ? [Colour("#0A000000"), Colour("#00000000")]
            : [Colour("#0EFFFFFF"), Colour("#00FFFFFF")]);

        SetStops(resources, "AccentFillBrush", light
            ? [Colour("#4C7DE6"), Colour("#3560CC")]
            : [Colour("#7FA8FF"), Colour("#5A85F5")]);

        SetStops(resources, "AccentFillHoverBrush", light
            ? [Colour("#5F8DF0"), Colour("#4670DA")]
            : [Colour("#96BAFF"), Colour("#6E95FF")]);

        SetStops(resources, "ProxyFillBrush", light
            ? [Colour("#1FB877"), Colour("#12945C")]
            : [Colour("#54E39B"), Colour("#2FC97B")]);
    }

    private static void SetStops(ResourceDictionary resources, string key, Color[] colours)
    {
        if (resources[key] is not LinearGradientBrush existing)
        {
            return;
        }

        var replacement = new LinearGradientBrush
        {
            StartPoint = existing.StartPoint,
            EndPoint = existing.EndPoint,
        };

        for (var i = 0; i < existing.GradientStops.Count; i++)
        {
            var colour = i < colours.Length ? colours[i] : existing.GradientStops[i].Color;
            replacement.GradientStops.Add(new GradientStop(colour, existing.GradientStops[i].Offset));
        }

        resources[key] = replacement;
    }

    private static Color Colour(string hex) => (Color)ColorConverter.ConvertFromString(hex);

    private static readonly Dictionary<string, (double Dark, double Light)> Opacities = new()
    {
        ["SurfaceBrush"] = (0.55, 0.86),
        ["SurfaceRaisedBrush"] = (0.80, 0.94),
        ["SurfaceHoverBrush"] = (0.85, 0.94),
        ["BorderBrush"] = (0.85, 1.00),
        ["AccentTintBrush"] = (0.16, 0.14),
        ["ProxyTintBrush"] = (0.16, 0.14),
        ["DirectTintBrush"] = (0.16, 0.14),
        ["BlockedTintBrush"] = (0.16, 0.14),
        ["WarningTintBrush"] = (0.16, 0.14),
    };

    private static readonly Dictionary<string, Color> Dark = new()
    {
        ["BackgroundBrush"] = Colour("#0B0D12"),
        ["SidebarBrush"] = Colour("#0E1016"),
        ["SurfaceBrush"] = Colour("#181C24"),
        ["SurfaceSolidBrush"] = Colour("#181C24"),
        ["SurfaceRaisedBrush"] = Colour("#20252F"),
        ["SurfaceHoverBrush"] = Colour("#272D39"),
        ["BorderBrush"] = Colour("#2A303C"),
        ["BorderStrongBrush"] = Colour("#3B4353"),

        ["TextBrush"] = Colour("#EDF0F7"),
        ["TextMutedBrush"] = Colour("#A0AABF"),
        ["TextFaintBrush"] = Colour("#717B90"),

        ["AccentBrush"] = Colour("#6D9BFF"),
        ["AccentHoverBrush"] = Colour("#8CB2FF"),
        ["AccentPressedBrush"] = Colour("#5480E6"),
        ["AccentTintBrush"] = Colour("#6D9BFF"),
        ["ProxyBrush"] = Colour("#3DDC8C"),
        ["ProxyTintBrush"] = Colour("#3DDC8C"),
        ["DirectBrush"] = Colour("#939DB1"),
        ["DirectTintBrush"] = Colour("#939DB1"),
        ["BlockedBrush"] = Colour("#FF8071"),
        ["BlockedTintBrush"] = Colour("#FF8071"),
        ["WarningBrush"] = Colour("#F5BC63"),
        ["WarningTintBrush"] = Colour("#F5BC63"),

        ["WindowBaseBrush"] = Colour("#C2080A0F"),
        ["WindowScrimBrush"] = Colour("#CC090B0F"),
        ["SidebarScrimBrush"] = Colour("#3A05070B"),
        ["FieldFillBrush"] = Colour("#33000000"),
        ["PopoverBrush"] = Colour("#F21A1F29"),
        ["OnAccentBrush"] = Colour("#08111F"),
        ["OverlaySoftBrush"] = Colour("#12FFFFFF"),
        ["OverlayBrush"] = Colour("#1AFFFFFF"),
        ["OverlayStrongBrush"] = Colour("#1FFFFFFF"),
        ["EdgeSoftBrush"] = Colour("#38FFFFFF"),
        ["EdgeBrush"] = Colour("#42FFFFFF"),
        ["EdgeStrongBrush"] = Colour("#4DFFFFFF"),
        ["OverlayAnimationColor"] = Colour("#1AFFFFFF"),
    };

    private static readonly Dictionary<string, Color> Light = new()
    {
        // A cool near-white rather than paper white: the accent is blue, and a ground with a little
        // of the same hue in it stops the interface reading as two unrelated halves.
        ["BackgroundBrush"] = Colour("#F3F5F9"),
        ["SidebarBrush"] = Colour("#E9ECF3"),
        ["SurfaceBrush"] = Colour("#FFFFFF"),
        ["SurfaceSolidBrush"] = Colour("#FFFFFF"),
        ["SurfaceRaisedBrush"] = Colour("#FFFFFF"),
        ["SurfaceHoverBrush"] = Colour("#E4E8F1"),
        ["BorderBrush"] = Colour("#D3D8E4"),
        ["BorderStrongBrush"] = Colour("#B9C1D2"),

        ["TextBrush"] = Colour("#111621"),
        ["TextMutedBrush"] = Colour("#4C5464"),
        ["TextFaintBrush"] = Colour("#767E90"),

        // Darker than the dark theme's accent, and deliberately so: #6D9BFF is legible on near-black
        // and turns to pastel on near-white.
        ["AccentBrush"] = Colour("#3D6FE0"),
        ["AccentHoverBrush"] = Colour("#5484EC"),
        ["AccentPressedBrush"] = Colour("#2F5AC0"),
        ["AccentTintBrush"] = Colour("#3D6FE0"),
        ["ProxyBrush"] = Colour("#12945C"),
        ["ProxyTintBrush"] = Colour("#12945C"),
        ["DirectBrush"] = Colour("#6B7488"),
        ["DirectTintBrush"] = Colour("#6B7488"),
        ["BlockedBrush"] = Colour("#CF3D30"),
        ["BlockedTintBrush"] = Colour("#CF3D30"),
        ["WarningBrush"] = Colour("#9A6100"),
        ["WarningTintBrush"] = Colour("#9A6100"),

        // The ground is light and nearly solid. Left translucent it shows the acrylic backdrop -
        // a blurred desktop - which is depth on a dark theme and grey mud under white cards.
        ["WindowBaseBrush"] = Colour("#F7F3F5F9"),

        // The modal dim still darkens, because that is its job whatever the ground is.
        ["WindowScrimBrush"] = Colour("#59101623"),
        // Nearly opaque, unlike its dark counterpart. On dark the sidebar is a sheet of glass over
        // the acrylic backdrop and reads as depth; on light the same sheet just shows a blurred
        // desktop through it, and the result is a muddy slate panel beside white cards.
        ["SidebarScrimBrush"] = Colour("#EDE9ECF3"),
        ["FieldFillBrush"] = Colour("#0F101623"),
        ["PopoverBrush"] = Colour("#FAFFFFFF"),
        ["OnAccentBrush"] = Colour("#FFFFFF"),

        // Overlays go dark. A white wash over white is not a hover state.
        ["OverlaySoftBrush"] = Colour("#0A101623"),
        ["OverlayBrush"] = Colour("#12101623"),
        ["OverlayStrongBrush"] = Colour("#1A101623"),
        ["EdgeSoftBrush"] = Colour("#1A101623"),
        ["EdgeBrush"] = Colour("#24101623"),
        ["EdgeStrongBrush"] = Colour("#30101623"),
        ["OverlayAnimationColor"] = Colour("#12101623"),
    };
}
