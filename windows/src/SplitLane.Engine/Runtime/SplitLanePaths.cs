namespace SplitLane.Engine.Runtime;

/// <summary>
/// Where SplitLane keeps its state on disk.
/// </summary>
/// <remarks>
/// <para>
/// Configuration lives under <c>%ProgramData%</c>, not under the user's profile. The engine runs as
/// a service or elevated process and the app runs as the user; a per-user path would be readable by
/// exactly one of them. <c>%ProgramData%\SplitLane</c> is the one location both can agree on.
/// </para>
/// <para>
/// This means the configuration is machine-wide, and on a shared machine every user's rules are
/// visible to every other user. That is a real property, not an oversight: the divert layer itself is
/// machine-wide, so per-user rules would be a promise the engine could not keep.
/// </para>
/// </remarks>
public static class SplitLanePaths
{
    /// <summary>Root of SplitLane's machine-wide state.</summary>
    public static string Root { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SplitLane");

    /// <summary>The configuration document.</summary>
    public static string ConfigurationFile => Path.Combine(Root, "configuration.json");

    /// <summary>The DPAPI-protected proxy credential.</summary>
    public static string CredentialFile => Path.Combine(Root, "credential.bin");

    /// <summary>Engine log.</summary>
    public static string EngineLog => Path.Combine(Root, "logs", "engine.log");

    /// <summary>App log.</summary>
    public static string AppLog => Path.Combine(Root, "logs", "app.log");

    /// <summary>Creates the directory tree if it is not already there.</summary>
    public static void EnsureCreated()
    {
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(Path.Combine(Root, "logs"));
    }
}
