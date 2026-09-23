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

    /// <summary>The configuration document, schema 2 and later.</summary>
    /// <remarks>
    /// A file of its own rather than a new version of the old one. A build from before schema 2 refuses
    /// a document stamped with a newer schema and would start with no rules at all; left alone, the
    /// schema 1 file beside this one is what such a build finds if it is installed as a rollback.
    /// </remarks>
    public static string ConfigurationFile => Path.Combine(Root, "configuration.v2.json");

    /// <summary>The schema 1 document. Read to migrate from, never written by this build.</summary>
    public static string LegacyConfigurationFile => Path.Combine(Root, "configuration.json");

    /// <summary>
    /// The managed policy, placed by an administrator or by device management.
    /// </summary>
    /// <remarks>
    /// In a folder of its own because the folder above is writable by every user; the service creates
    /// this one with inheritance cut and only SYSTEM and Administrators able to write. See
    /// <see cref="PolicyStore"/> and <see cref="PolicyFileTrust"/>.
    /// </remarks>
    public static string PolicyFile => Path.Combine(Root, "Policy", "policy.json");

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
