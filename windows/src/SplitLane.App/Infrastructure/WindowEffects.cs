using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;

namespace SplitLane.App.Infrastructure;

/// <summary>Which desktop-composition backdrop a window asks for.</summary>
public enum Backdrop
{
    /// <summary>Let the system decide.</summary>
    Auto = 0,

    /// <summary>No backdrop; the window paints its own background.</summary>
    None = 1,

    /// <summary>Mica: a soft, desaturated tint of the desktop wallpaper. Calm, opaque-feeling.</summary>
    Mica = 2,

    /// <summary>Acrylic: a live blur of whatever is behind the window. The glass look.</summary>
    Acrylic = 3,

    /// <summary>Mica Alt, the tabbed-window variant.</summary>
    MicaAlt = 4,
}

/// <summary>
/// Desktop-composition effects that WPF has no managed API for.
/// </summary>
/// <remarks>
/// <para>
/// Three things happen here, and all three are what separate a window that looks designed from one
/// that looks like a WPF app: a dark caption, rounded corners, and a real composition backdrop
/// behind the content.
/// </para>
/// <para>
/// Every call is best-effort. On a build that does not know an attribute, DWM returns a failure code
/// and the window simply renders without that effect — which is why the interface also carries an
/// opaque fallback layer underneath the glass. A design that is unreadable when the blur is missing
/// is a design that breaks on Windows 10, in a remote session, and whenever a user turns
/// transparency off in Accessibility settings.
/// </para>
/// </remarks>
public static class WindowEffects
{
    private const int UseImmersiveDarkModeLegacy = 19;
    private const int UseImmersiveDarkMode = 20;
    private const int WindowCornerPreference = 33;
    private const int SystemBackdropType = 38;

    /// <summary>DWMWCP_ROUND.</summary>
    private const int CornerRound = 2;

    /// <summary>
    /// Switches the window's frame between light and dark without touching anything else.
    /// </summary>
    /// <remarks>
    /// Needed on its own because the theme can change while the window is open - the person chose a
    /// different one, or Windows did. Re-applying the whole effect would also re-extend the frame
    /// and reset the backdrop, which flickers for no reason.
    /// </remarks>
    public static void SetCaptionTheme(Window window, bool dark)
    {
        ArgumentNullException.ThrowIfNull(window);

        var handle = new WindowInteropHelper(window).Handle;
        if (handle != nint.Zero)
        {
            SetCaption(handle, dark);
        }
    }

    private static void SetCaption(nint handle, bool dark)
    {
        var enabled = dark ? 1 : 0;
        if (DwmSetWindowAttribute(handle, UseImmersiveDarkMode, ref enabled, sizeof(int)) != 0)
        {
            // The attribute was renumbered between Windows 10 1809 and 20H1.
            DwmSetWindowAttribute(handle, UseImmersiveDarkModeLegacy, ref enabled, sizeof(int));
        }
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(nint window, int attribute, ref int value, int size);

    [DllImport("dwmapi.dll")]
    private static extern int DwmExtendFrameIntoClientArea(nint window, ref Margins margins);

    [StructLayout(LayoutKind.Sequential)]
    private struct Margins
    {
        public int Left;
        public int Right;
        public int Top;
        public int Bottom;
    }

    /// <summary>
    /// Applies the caption colour, rounded corners and a composition backdrop to a window.
    /// </summary>
    /// <returns>True when the backdrop was accepted, so the caller can decide how opaque to be.</returns>
    public static bool Apply(Window window, Backdrop backdrop, bool dark = true)
    {
        ArgumentNullException.ThrowIfNull(window);

        var handle = new WindowInteropHelper(window).Handle;
        if (handle == nint.Zero)
        {
            return false;
        }

        SetCaption(handle, dark);

        var corner = CornerRound;
        DwmSetWindowAttribute(handle, WindowCornerPreference, ref corner, sizeof(int));

        // The backdrop is only composited where the frame extends into the client area, so this has
        // to happen even though the window draws all of its own chrome.
        var margins = new Margins { Left = -1, Right = -1, Top = -1, Bottom = -1 };
        DwmExtendFrameIntoClientArea(handle, ref margins);

        var type = (int)backdrop;
        var applied = DwmSetWindowAttribute(handle, SystemBackdropType, ref type, sizeof(int)) == 0;

        if (applied)
        {
            // With a backdrop the HWND background must not be painted, or the composition is hidden
            // behind it. The interface's own translucent layer supplies the tint.
            var source = HwndSource.FromHwnd(handle);
            if (source is not null)
            {
                source.CompositionTarget.BackgroundColor = Colors.Transparent;
            }
        }

        return applied;
    }
}
