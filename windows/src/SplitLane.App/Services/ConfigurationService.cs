using System.IO;
using System.Security.Cryptography;
using System.Text;
using SplitLane.Core.Configuration;
using SplitLane.Core.Models;
using SplitLane.Platform;

namespace SplitLane.App.Services;

/// <summary>
/// Reads and writes the shared configuration document from the app's side.
/// </summary>
/// <remarks>
/// <para>
/// The app writes the file itself rather than going through the engine for everything. That is
/// deliberate: a user must be able to set their rules up before the engine has ever been started,
/// and an app that could only be configured while an elevated service was running would be
/// unusable at exactly the moment someone is trying to get started.
/// </para>
/// <para>
/// Once written, the engine is asked to reload. If it is not running there is nothing to tell, and
/// it will read the file when it starts.
/// </para>
/// <para>
/// Which file is read follows the engine's rule exactly (<c>ConfigurationStore.SourcePath</c>). If
/// the two ever disagreed, the app would show one set of rules while the engine routed another, and
/// the screen would be the last place anyone looked for the difference.
/// </para>
/// </remarks>
public sealed class ConfigurationService
{
    private readonly Lock _gate = new();

    /// <summary>Root of the machine-wide state, shared with the engine.</summary>
    public static string Root { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SplitLane");

    /// <summary>The configuration document, schema 2 and later. The only one this build writes.</summary>
    /// <remarks>
    /// A file of its own rather than a new version of the old one: a build from before schema 2 refuses
    /// a document stamped with a newer schema and would start with no rules at all. Left alone, the
    /// schema 1 file is what such a build finds if it is installed as a rollback.
    /// </remarks>
    public string ConfigurationPath { get; } = Path.Combine(Root, "configuration.v2.json");

    /// <summary>The schema 1 document. Read to migrate from, never written.</summary>
    public string LegacyConfigurationPath { get; } = Path.Combine(Root, "configuration.json");

    /// <summary>The protected proxy credential.</summary>
    public string CredentialPath { get; } = Path.Combine(Root, "credential.bin");

    /// <summary>Where the engine writes its log.</summary>
    public string EngineLogPath { get; } = Path.Combine(Root, "logs", "engine.log");

    /// <summary>
    /// The document to read: the schema 2 one, unless the schema 1 one is newer.
    /// </summary>
    /// <remarks>
    /// The schema 1 file is newer when a build from before schema 2 was installed as a rollback and
    /// the user changed their rules with it. Those changes are the latest thing the user asked for, so
    /// they are what gets shown and migrated, rather than silently losing to an older schema 2 file.
    /// </remarks>
    public string SourcePath
    {
        get
        {
            if (!File.Exists(LegacyConfigurationPath))
            {
                return ConfigurationPath;
            }

            if (!File.Exists(ConfigurationPath))
            {
                return LegacyConfigurationPath;
            }

            return File.GetLastWriteTimeUtc(LegacyConfigurationPath) > File.GetLastWriteTimeUtc(ConfigurationPath)
                ? LegacyConfigurationPath
                : ConfigurationPath;
        }
    }

    /// <summary>Loads the configuration, or defaults when there is nothing to load.</summary>
    /// <remarks>
    /// Returns rules exactly as stored, schema 1 path rules included. Migrating them reads and verifies
    /// every file they name, which is seconds, so it is a separate step: see <see cref="MigrateAsync"/>.
    /// </remarks>
    public RuntimeConfiguration Load(out string? error)
    {
        error = null;

        try
        {
            lock (_gate)
            {
                var source = SourcePath;
                if (!File.Exists(source))
                {
                    return RuntimeConfiguration.Empty;
                }

                var json = File.ReadAllText(source, Encoding.UTF8);
                return ConfigurationValidator.Sanitize(ConfigurationCodec.DecodeFromJson(json));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                       or ConfigurationValidationException
                                       or System.Text.Json.JsonException)
        {
            error = ex.Message;
            return RuntimeConfiguration.Empty;
        }
    }

    /// <summary>Whether a loaded configuration still has rules that recognise an application by path.</summary>
    public static bool NeedsMigration(RuntimeConfiguration configuration) =>
        ConfigurationMigrator.NeedsMigration(configuration);

    /// <summary>
    /// Migrates path rules to identity rules on a worker thread. Nothing is written.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Off the UI thread because it verifies the signature of every file a rule names - about a second
    /// and a half for one large executable read cold - and the window would freeze for all of it.
    /// </para>
    /// <para>
    /// Not saved here. The engine performs the same migration when it loads the document and saves
    /// the result itself; the app shows its own copy so the rules on screen are the ones that will
    /// route, and writes it only when the user saves.
    /// </para>
    /// </remarks>
    public static Task<MigrationResult> MigrateAsync(RuntimeConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        return Task.Run(() => ConfigurationMigrator.Migrate(configuration, WindowsImageInspector.Instance));
    }

    /// <summary>Validates and writes the configuration, advancing the generation.</summary>
    /// <remarks>
    /// Always to <see cref="ConfigurationPath"/>, never to <see cref="LegacyConfigurationPath"/>, even
    /// when that is where the configuration was read from. Overwriting the schema 1 file with a schema 2
    /// document would leave a rolled-back build with nothing it can read.
    /// </remarks>
    public RuntimeConfiguration Save(RuntimeConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var next = configuration.WithNextGeneration();
        ConfigurationValidator.Validate(next);

        lock (_gate)
        {
            Directory.CreateDirectory(Root);
            Directory.CreateDirectory(Path.Combine(Root, "logs"));

            var temporary = ConfigurationPath + ".tmp";
            File.WriteAllText(temporary, ConfigurationCodec.EncodeToJson(next), Encoding.UTF8);

            if (File.Exists(ConfigurationPath))
            {
                File.Replace(temporary, ConfigurationPath, null, ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(temporary, ConfigurationPath);
            }
        }

        return next;
    }

    /// <summary>Stores the proxy password where only this machine can read it.</summary>
    public void SaveCredential(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        lock (_gate)
        {
            Directory.CreateDirectory(Root);

            var protectedBytes = ProtectedData.Protect(
                Encoding.UTF8.GetBytes(password), null, DataProtectionScope.LocalMachine);

            File.WriteAllBytes(CredentialPath, protectedBytes);
        }
    }

    /// <summary>Removes the stored password.</summary>
    public void ClearCredential()
    {
        lock (_gate)
        {
            if (File.Exists(CredentialPath))
            {
                File.Delete(CredentialPath);
            }
        }
    }

    /// <summary>Whether a password has been stored. The password itself is never returned to the UI.</summary>
    public bool HasStoredCredential => File.Exists(CredentialPath);
}
