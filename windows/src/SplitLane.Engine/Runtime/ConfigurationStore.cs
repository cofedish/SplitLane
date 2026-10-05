using System.Security.Cryptography;
using System.Text;
using SplitLane.Core.Configuration;
using SplitLane.Core.Logging;
using SplitLane.Core.Models;
using SplitLane.Core.Proxy.Socks5;

namespace SplitLane.Engine.Runtime;

/// <summary>
/// Reads and writes the configuration document and the protected credential.
/// </summary>
/// <remarks>
/// <para>
/// The two are stored separately. The document is plain JSON that a user can read and a support
/// request can include. The password is held by <see cref="ProxyCredentialStore"/>, where only the
/// service can read it, bound to the proxy it was entered for (SL-SEC-006).
/// </para>
/// <para>
/// Writes are atomic. A configuration half-written when the machine loses power would otherwise be a
/// configuration the engine refuses to load, which on the next boot means no routing at all with no
/// obvious cause.
/// </para>
/// </remarks>
public sealed class ConfigurationStore
{
    private const string LogCategory = "config";

    /// <summary>
    /// The largest configuration read. A thousand rules with every identity field is under a megabyte.
    /// </summary>
    internal const long MaxConfigurationBytes = 8 * 1024 * 1024;
    private readonly Lock _gate = new();

    /// <summary>Builds a store over the standard paths.</summary>
    public ConfigurationStore()
        : this(SplitLanePaths.ConfigurationFile, SplitLanePaths.CredentialFile, SplitLanePaths.LegacyConfigurationFile,
            new ProxyCredentialStore())
    {
    }

    /// <summary>Builds a store over explicit paths. Used by tests and by <c>--explain --config</c>.</summary>
    /// <param name="configurationPath">The schema 2 document, read and written.</param>
    /// <param name="credentialPath">Where an old, user-readable password file may be, to migrate from.</param>
    /// <param name="legacyConfigurationPath">The schema 1 document, read only; null for none.</param>
    /// <param name="credentials">
    /// Where the password is kept; by default a protected directory beside the configuration.
    /// </param>
    public ConfigurationStore(
        string configurationPath,
        string credentialPath,
        string? legacyConfigurationPath = null,
        ProxyCredentialStore? credentials = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(configurationPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialPath);

        ConfigurationPath = configurationPath;
        CredentialPath = credentialPath;
        LegacyConfigurationPath = legacyConfigurationPath;
        Credentials = credentials ?? new ProxyCredentialStore(new ProtectedDirectory(
            Path.Combine(Path.GetDirectoryName(Path.GetFullPath(configurationPath))!, "Secrets"), UserAccess.None));
    }

    /// <summary>Where the proxy password is kept.</summary>
    public ProxyCredentialStore Credentials { get; }

    /// <summary>Where the document lives.</summary>
    public string ConfigurationPath { get; }

    /// <summary>Where a schema 1 document is read from, if there is one to read.</summary>
    public string? LegacyConfigurationPath { get; }

    /// <summary>
    /// The document to read: the schema 2 one, unless the schema 1 one is newer.
    /// </summary>
    /// <remarks>
    /// The schema 1 file is newer when a build from before schema 2 was installed as a rollback and
    /// the user changed their rules with it. Those changes are the latest thing the user asked for, so
    /// they are what gets migrated, rather than silently losing to an older schema 2 file.
    /// </remarks>
    public string SourcePath
    {
        get
        {
            var legacy = LegacyConfigurationPath;
            if (legacy is null || !File.Exists(legacy))
            {
                return ConfigurationPath;
            }

            if (!File.Exists(ConfigurationPath))
            {
                return legacy;
            }

            return File.GetLastWriteTimeUtc(legacy) > File.GetLastWriteTimeUtc(ConfigurationPath)
                ? legacy
                : ConfigurationPath;
        }
    }

    /// <summary>Where an old, user-readable password file may be (SL-SEC-006). Migrated from, then deleted.</summary>
    public string CredentialPath { get; }

    /// <summary>
    /// Loads the configuration, falling back to defaults when there is nothing to load.
    /// </summary>
    /// <remarks>
    /// A missing file is normal — it is what a first run looks like. A corrupt file is not, and it is
    /// reported rather than silently replaced, because silently replacing it would throw away every
    /// rule the user had created.
    /// </remarks>
    public RuntimeConfiguration Load()
    {
        lock (_gate)
        {
            var source = SourcePath;
            if (!File.Exists(source))
            {
                return RuntimeConfiguration.Empty;
            }

            // Any user can write this file and ask the engine to read it, so its size is checked before
            // it is read: a file of gigabytes would otherwise take the LocalSystem service down, and
            // every selected application's traffic with it.
            if (new FileInfo(source).Length > MaxConfigurationBytes)
            {
                throw new IOException($"{source} is larger than {MaxConfigurationBytes} bytes");
            }

            var json = File.ReadAllText(source, Encoding.UTF8);
            var configuration = ConfigurationCodec.DecodeFromJson(json);
            return ConfigurationValidator.Sanitize(configuration);
        }
    }

    /// <summary>Loads the configuration, or returns defaults and reports why.</summary>
    public RuntimeConfiguration LoadOrDefault(out string? error)
    {
        try
        {
            error = null;
            return Load();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                       or ConfigurationValidationException
                                       or System.Text.Json.JsonException)
        {
            error = $"Could not read {SourcePath}: {ex.Message}";
            SplitLaneLog.Error(LogCategory, error);
            return RuntimeConfiguration.Empty;
        }
    }

    /// <summary>Validates and writes the configuration atomically.</summary>
    public void Save(RuntimeConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ConfigurationValidator.Validate(configuration);

        lock (_gate)
        {
            var directory = Path.GetDirectoryName(ConfigurationPath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            // A fresh, unpredictable name, created exclusively. The folder lets every user create
            // files, and a fixed ".tmp" name was one a user could create first and keep control of
            // while the service wrote through it (SL-SEC-007).
            var temporary = $"{ConfigurationPath}.{Guid.NewGuid():N}.tmp";

            try
            {
                using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (var writer = new StreamWriter(file, Encoding.UTF8))
                {
                    writer.Write(ConfigurationCodec.EncodeToJson(configuration));
                }

                // Replace rather than delete-then-move: the file is never absent at any instant, so a
                // reader racing the write sees either the old document or the new one.
                if (File.Exists(ConfigurationPath))
                {
                    File.Replace(temporary, ConfigurationPath, null, ignoreMetadataErrors: true);
                }
                else
                {
                    File.Move(temporary, ConfigurationPath);
                }
            }
            finally
            {
                if (File.Exists(temporary))
                {
                    File.Delete(temporary);
                }
            }
        }
    }

    /// <summary>
    /// The credential for a configuration's proxy, or null when none is configured or none is stored
    /// for exactly that proxy and account (SL-SEC-006).
    /// </summary>
    public Socks5Credential? ResolveCredential(ProxyConfiguration proxy)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        return proxy.Credential is { Username: { Length: > 0 } } ? Credentials.Resolve(proxy) : null;
    }
}
