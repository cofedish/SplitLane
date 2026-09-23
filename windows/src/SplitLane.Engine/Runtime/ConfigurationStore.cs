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
/// The two are stored separately and that separation is the whole security story. The document is
/// plain JSON that a user can read and a support request can include; the credential is a DPAPI blob
/// scoped to the local machine, so it is meaningless if copied elsewhere and it never appears in the
/// file anyone would think to attach to a bug report.
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
        : this(SplitLanePaths.ConfigurationFile, SplitLanePaths.CredentialFile, SplitLanePaths.LegacyConfigurationFile)
    {
    }

    /// <summary>Builds a store over explicit paths. Used by tests and by <c>--explain --config</c>.</summary>
    /// <param name="configurationPath">The schema 2 document, read and written.</param>
    /// <param name="credentialPath">The protected credential.</param>
    /// <param name="legacyConfigurationPath">The schema 1 document, read only; null for none.</param>
    public ConfigurationStore(string configurationPath, string credentialPath, string? legacyConfigurationPath = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(configurationPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialPath);

        ConfigurationPath = configurationPath;
        CredentialPath = credentialPath;
        LegacyConfigurationPath = legacyConfigurationPath;
    }

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

    /// <summary>Where the protected credential lives.</summary>
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

            var temporary = ConfigurationPath + ".tmp";
            File.WriteAllText(temporary, ConfigurationCodec.EncodeToJson(configuration), Encoding.UTF8);

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
    }

    /// <summary>
    /// Stores the proxy password, protected to this machine.
    /// </summary>
    /// <remarks>
    /// <c>LocalMachine</c> scope rather than <c>CurrentUser</c>, because the engine reads it as a
    /// service account and the app writes it as the interactive user. LocalMachine scope means any
    /// process on this machine that can read the file can decrypt it, and no code here narrows the
    /// file's ACL, so it inherits the folder's; the encryption only keeps it away from a copied disk.
    /// Tightening that is on the fleet plan (docs/ENTERPRISE_READINESS.md, P1-5).
    /// </remarks>
    public void SaveCredential(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        lock (_gate)
        {
            var directory = Path.GetDirectoryName(CredentialPath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

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

    /// <summary>Reads the proxy password, or null when there is none.</summary>
    public string? LoadPassword()
    {
        lock (_gate)
        {
            if (!File.Exists(CredentialPath))
            {
                return null;
            }

            try
            {
                var unprotected = ProtectedData.Unprotect(
                    File.ReadAllBytes(CredentialPath), null, DataProtectionScope.LocalMachine);

                return Encoding.UTF8.GetString(unprotected);
            }
            catch (CryptographicException)
            {
                // The blob was written on another machine, or the machine key changed. There is
                // nothing to recover; the user has to re-enter the password.
                SplitLaneLog.Warning(LogCategory, "stored proxy credential could not be decrypted on this machine");
                return null;
            }
            catch (IOException ex)
            {
                SplitLaneLog.Warning(LogCategory, $"stored proxy credential is unreadable: {ex.Message}");
                return null;
            }
        }
    }

    /// <summary>Builds the SOCKS5 credential for a configuration, or null when none is configured.</summary>
    public Socks5Credential? ResolveCredential(ProxyConfiguration proxy)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        if (proxy.Credential is not { } reference || string.IsNullOrEmpty(reference.Username))
        {
            return null;
        }

        var password = LoadPassword();
        return password is null ? null : new Socks5Credential(reference.Username, password);
    }
}
