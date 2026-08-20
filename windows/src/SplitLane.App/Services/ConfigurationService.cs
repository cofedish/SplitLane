using System.IO;
using System.Security.Cryptography;
using System.Text;
using SplitLane.Core.Configuration;
using SplitLane.Core.Models;

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
/// </remarks>
public sealed class ConfigurationService
{
    private readonly Lock _gate = new();

    /// <summary>Root of the machine-wide state, shared with the engine.</summary>
    public static string Root { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SplitLane");

    /// <summary>The configuration document.</summary>
    public string ConfigurationPath { get; } = Path.Combine(Root, "configuration.json");

    /// <summary>The protected proxy credential.</summary>
    public string CredentialPath { get; } = Path.Combine(Root, "credential.bin");

    /// <summary>Where the engine writes its log.</summary>
    public string EngineLogPath { get; } = Path.Combine(Root, "logs", "engine.log");

    /// <summary>Loads the configuration, or defaults when there is nothing to load.</summary>
    public RuntimeConfiguration Load(out string? error)
    {
        error = null;

        try
        {
            lock (_gate)
            {
                if (!File.Exists(ConfigurationPath))
                {
                    return RuntimeConfiguration.Empty;
                }

                var json = File.ReadAllText(ConfigurationPath, Encoding.UTF8);
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

    /// <summary>Validates and writes the configuration, advancing the generation.</summary>
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
