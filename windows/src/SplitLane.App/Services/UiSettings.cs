using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using SplitLane.App.Theme;

namespace SplitLane.App.Services;

/// <summary>Preferences that belong to the window rather than to the routing engine.</summary>
/// <param name="Theme">Which look the application wears.</param>
public sealed record UiPreferences(
    [property: JsonConverter(typeof(JsonStringEnumConverter))] AppTheme Theme = AppTheme.System);

/// <summary>
/// Where the window's own preferences live.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately not in the engine's configuration. That file is a routing decision the engine acts
/// on, it is written by an elevated service, and it is read by a component with no interface at all;
/// a colour scheme has no business travelling through it. This is per-user, unprivileged, and
/// nothing outside the window reads it.
/// </para>
/// <para>
/// A missing or unreadable file is not an error worth reporting. Somebody opening SplitLane for the
/// first time has no preferences, and that is indistinguishable from a file that failed to parse -
/// in both cases the right answer is the default and no interruption.
/// </para>
/// </remarks>
public static class UiSettings
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    /// <summary>The file backing these preferences.</summary>
    public static string Path { get; } = System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "SplitLane",
        "ui.json");

    /// <summary>Reads the preferences, falling back to defaults.</summary>
    public static UiPreferences Load()
    {
        try
        {
            if (!File.Exists(Path))
            {
                return new UiPreferences();
            }

            return JsonSerializer.Deserialize<UiPreferences>(File.ReadAllText(Path), Options)
                   ?? new UiPreferences();
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            return new UiPreferences();
        }
    }

    /// <summary>Writes the preferences. Failure is silent by design; see the remarks on the class.</summary>
    public static void Save(UiPreferences preferences)
    {
        ArgumentNullException.ThrowIfNull(preferences);

        try
        {
            var directory = System.IO.Path.GetDirectoryName(Path);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(Path, JsonSerializer.Serialize(preferences, Options));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }
}
