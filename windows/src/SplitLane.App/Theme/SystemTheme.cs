using Microsoft.Win32;

namespace SplitLane.App.Theme;

/// <summary>
/// What Windows itself is set to, and a way to hear about it changing.
/// </summary>
/// <remarks>
/// Read from the registry rather than from a framework helper, because the value SplitLane wants is
/// the one that governs applications - <c>AppsUseLightTheme</c> - and not the separate setting for
/// the taskbar and Start menu, which people quite often set the other way round.
/// </remarks>
public static class SystemTheme
{
    private const string PersonalizeKey =
        @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";

    /// <summary>Raised when Windows switches between light and dark.</summary>
    public static event Action? Changed;

    private static bool _listening;

    /// <summary>What Windows is set to now. Dark if it cannot be read.</summary>
    public static AppTheme Current()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(PersonalizeKey);
            var value = key?.GetValue("AppsUseLightTheme");

            return value is int light && light != 0 ? AppTheme.Light : AppTheme.Dark;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
        {
            // Dark is the design's home ground, so it is the safer thing to be wrong about.
            return AppTheme.Dark;
        }
    }

    /// <summary>Starts watching for the user changing their Windows theme.</summary>
    public static void StartListening()
    {
        if (_listening)
        {
            return;
        }

        SystemEvents.UserPreferenceChanged += (_, e) =>
        {
            // General covers the personalisation change. It fires for a good deal else besides, and
            // re-reading a registry value costs nothing worth avoiding.
            if (e.Category == UserPreferenceCategory.General)
            {
                Changed?.Invoke();
            }
        };

        _listening = true;
    }
}
