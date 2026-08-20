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
    private readonly Lock _gate = new();

    /// <summary>Builds a store over the standard paths.</summary>
    public ConfigurationStore()
        : this(SplitLanePaths.ConfigurationFile, SplitLanePaths.CredentialFile)
    {
    }

    /// <summary>Builds a store over explicit paths. Used by tests.</summary>
    public ConfigurationStore(string configurationPath, string credentialPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(configurationPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialPath);

        ConfigurationPath = configurationPath;
        CredentialPath = credentialPath;
    }

    /// <summary>Where the document lives.</summary>
    public string ConfigurationPath { get; }

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
            if (!File.Exists(ConfigurationPath))
            {
                return RuntimeConfiguration.Empty;
            }

            var json = File.ReadAllText(ConfigurationPath, Encoding.UTF8);
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
            error = $"Could not read {ConfigurationPath}: {ex.Message}";
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
    /// service account and the app writes it as the interactive user. The file's ACL is what keeps it
    /// away from other users; the encryption is what keeps it away from a copied disk.
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
