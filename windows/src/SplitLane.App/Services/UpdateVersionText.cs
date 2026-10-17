namespace SplitLane.App.Services;

/// <summary>Formats product versions displayed after a user reopens the updated application.</summary>
public static class UpdateVersionText
{
    /// <summary>The version without its build metadata.</summary>
    public static string DisplayVersion(string? version)
        => string.IsNullOrEmpty(version) ? "unknown" : version.Split('+')[0];
}
