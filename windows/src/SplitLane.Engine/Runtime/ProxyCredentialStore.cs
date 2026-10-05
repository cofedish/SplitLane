using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SplitLane.Core.Logging;
using SplitLane.Core.Models;
using SplitLane.Core.Proxy.Socks5;

namespace SplitLane.Engine.Runtime;

/// <summary>Which proxy a stored password belongs to.</summary>
/// <param name="Type">The protocol it was entered for.</param>
/// <param name="Host">The proxy host it was entered for.</param>
/// <param name="Port">The proxy port it was entered for.</param>
/// <param name="Username">The account it is the password of.</param>
public sealed record ProxyCredentialBinding(ProxyProtocolType Type, string Host, ushort Port, string Username)
{
    /// <summary>The binding a configuration would need, or null when it names no account.</summary>
    public static ProxyCredentialBinding? For(ProxyConfiguration proxy)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        return proxy.Credential is { Username: { Length: > 0 } username }
            ? new ProxyCredentialBinding(proxy.Type, proxy.Endpoint.Host.Trim(), proxy.Endpoint.Port, username.Trim())
            : null;
    }

    /// <summary>
    /// Whether this password may be used for a configuration: same protocol, host, port and account.
    /// </summary>
    public bool Matches(ProxyConfiguration proxy) =>
        For(proxy) is { } wanted &&
        wanted.Type == Type &&
        string.Equals(wanted.Host, Host, StringComparison.OrdinalIgnoreCase) &&
        wanted.Port == Port &&
        string.Equals(wanted.Username, Username, StringComparison.Ordinal);

    /// <summary>For logs and the window. Never contains the password.</summary>
    public string Display => $"{Username} at {(Host.Contains(':') ? $"[{Host}]" : Host)}:{Port} ({Type.DisplayName()})";
}

/// <summary>
/// The proxy password, held by the service where only the service can read it (SL-SEC-006).
/// </summary>
/// <remarks>
/// <para>
/// It used to be <c>%ProgramData%\SplitLane\credential.bin</c>, written by the window as the user and
/// protected with DPAPI's LocalMachine scope. That scope makes a blob useless on another machine and
/// nothing more: any process on this one that can read the file can decrypt it, and the file inherited
/// read access for every user. And the password was not tied to anything - whoever could change the
/// proxy address (every interactive user, through the control channel) could have the engine send it
/// to a host of their choosing.
/// </para>
/// <para>Now:</para>
/// <list type="bullet">
/// <item>the window hands the password to the service over the authenticated control channel and
/// never writes it anywhere;</item>
/// <item>the service keeps it in a <see cref="ProtectedDirectory"/> no ordinary user can list or read,
/// still DPAPI-protected, with entropy, so a copied disk is not enough either;</item>
/// <item>it is stored with the protocol, host, port and account it was entered for, and used only for
/// a proxy that matches all four. Pointing the proxy somewhere else does not take the password with
/// it; the user has to enter it again for the new place.</item>
/// </list>
/// <para>
/// An administrator can still read it - DPAPI LocalMachine and the directory's permissions both admit
/// them - which is the boundary the engine itself runs inside.
/// </para>
/// </remarks>
public sealed class ProxyCredentialStore
{
    private const string LogCategory = "credential";
    private const string FileName = "proxy-credential.json";
    private const long MaxFileBytes = 64 * 1024;

    /// <summary>Longest password accepted. Far beyond any real one.</summary>
    public const int MaxPasswordLength = 1024;

    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("SplitLane proxy credential v1");

    private readonly ProtectedDirectory _directory;
    private readonly Lock _gate = new();

    /// <summary>The store in the service's protected secrets directory.</summary>
    public ProxyCredentialStore()
        : this(new ProtectedDirectory(SplitLanePaths.SecretsDirectory, UserAccess.None))
    {
    }

    /// <summary>A store in an explicit protected directory. Used by tests.</summary>
    internal ProxyCredentialStore(ProtectedDirectory directory)
    {
        _directory = directory ?? throw new ArgumentNullException(nameof(directory));
    }

    private string FilePath => Path.Combine(_directory.Path, FileName);

    /// <summary>Stores a password for one proxy, replacing whatever was stored.</summary>
    /// <exception cref="ArgumentException">The password or binding is not acceptable.</exception>
    public void Save(ProxyCredentialBinding binding, string password, bool allowPlaintextBasic = false)
    {
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(password);

        if (password.Length is 0 or > MaxPasswordLength || password.Contains('\0', StringComparison.Ordinal))
        {
            throw new ArgumentException("The password is empty, too long, or contains a NUL character.", nameof(password));
        }

        if (string.IsNullOrWhiteSpace(binding.Host) || string.IsNullOrWhiteSpace(binding.Username) || binding.Port == 0)
        {
            throw new ArgumentException("A stored password must name the proxy and account it is for.", nameof(binding));
        }

        var secret = ProtectedData.Protect(Encoding.UTF8.GetBytes(password), Entropy, DataProtectionScope.LocalMachine);
        var document = JsonSerializer.SerializeToUtf8Bytes(new StoredCredential(
            binding.Type, binding.Host, binding.Port, binding.Username, Convert.ToBase64String(secret), allowPlaintextBasic));

        lock (_gate)
        {
            var directory = _directory.Ensure();

            // Written under a new random name with CreateNew, then moved over the old one: the directory
            // is SYSTEM-only, so nobody can prepare either name, and a reader sees one file or the other.
            var temporary = Path.Combine(directory, $"{FileName}.{Guid.NewGuid():N}.tmp");
            using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                file.Write(document);
                file.Flush(flushToDisk: true);
            }

            File.Move(temporary, FilePath, overwrite: true);
        }

        SplitLaneLog.Info(LogCategory, $"a proxy password is stored for {binding.Display}");
    }

    /// <summary>Forgets the stored password.</summary>
    public void Clear()
    {
        lock (_gate)
        {
            if (Trusted() && File.Exists(FilePath))
            {
                File.Delete(FilePath);
            }
        }
    }

    /// <summary>What the stored password is for, or null when there is none. Never the password.</summary>
    public ProxyCredentialBinding? Binding => Read()?.Binding;

    /// <summary>Whether the stored password may be sent with HTTP Basic to a proxy elsewhere.</summary>
    public bool AllowsPlaintextBasic => Read()?.AllowPlaintextBasic ?? false;

    /// <summary>
    /// The credential for a proxy - only if a password is stored for exactly that protocol, host, port
    /// and account.
    /// </summary>
    public Socks5Credential? Resolve(ProxyConfiguration proxy)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        if (Read() is not { } stored)
        {
            return null;
        }

        if (!stored.Binding.Matches(proxy))
        {
            if (ProxyCredentialBinding.For(proxy) is { } wanted)
            {
                SplitLaneLog.Warning(
                    LogCategory,
                    $"the stored proxy password is for {stored.Binding.Display}, not {wanted.Display}; " +
                    "it is not used - enter the password again for the new proxy");
            }

            return null;
        }

        try
        {
            var password = Encoding.UTF8.GetString(
                ProtectedData.Unprotect(Convert.FromBase64String(stored.Secret), Entropy, DataProtectionScope.LocalMachine));
            return new Socks5Credential(stored.Binding.Username, password) { AllowPlaintextBasic = stored.AllowPlaintextBasic };
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            SplitLaneLog.Warning(LogCategory, "the stored proxy password could not be decrypted on this machine");
            return null;
        }
    }

    /// <summary>
    /// Moves a password from the old, user-readable <c>credential.bin</c> into this store, bound to the
    /// proxy configured now, and deletes the old file whatever happens.
    /// </summary>
    /// <returns>Whether a password was moved.</returns>
    public bool MigrateLegacy(string legacyPath, ProxyConfiguration current)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(legacyPath);
        ArgumentNullException.ThrowIfNull(current);

        if (!File.Exists(legacyPath))
        {
            return false;
        }

        var migrated = false;

        try
        {
            if (Binding is null && ProxyCredentialBinding.For(current) is { } binding && ReadLegacy(legacyPath) is { } blob)
            {
                var password = Encoding.UTF8.GetString(
                    ProtectedData.Unprotect(blob, null, DataProtectionScope.LocalMachine));
                Save(binding, password);
                migrated = true;
            }
        }
        catch (Exception ex) when (ex is CryptographicException or IOException or UnauthorizedAccessException or ArgumentException)
        {
            SplitLaneLog.Warning(LogCategory, $"the old proxy password could not be moved: {ex.Message}");
        }
        finally
        {
            try
            {
                // Deleted either way: every local user could read and decrypt it.
                File.Delete(legacyPath);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                SplitLaneLog.Error(LogCategory, $"the old, readable proxy password at {legacyPath} could not be deleted: {ex.Message}");
            }
        }

        SplitLaneLog.Warning(
            LogCategory,
            migrated
                ? "the proxy password was moved to storage only the service can read; it was readable by every " +
                  "local user before, so consider changing it"
                : "an old proxy password file, readable by every local user, was deleted");
        return migrated;
    }

    /// <summary>
    /// The old file's bytes, read through one handle that is checked to be a regular file with a
    /// single name - not a link to something else - and not oversized. Null otherwise.
    /// </summary>
    private static byte[]? ReadLegacy(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            return null;
        }

        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (!Platform.ImageInspectionNative.GetFileInformationByHandle(file.SafeFileHandle, out var information) ||
            (information.FileAttributes & 0x400) != 0 || information.NumberOfLinks != 1 || file.Length > MaxFileBytes)
        {
            return null;
        }

        var blob = new byte[file.Length];
        file.ReadExactly(blob);
        return blob;
    }

    private bool Trusted()
    {
        try
        {
            return Directory.Exists(_directory.Path) && _directory.Problem(_directory.Path) is null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // An unelevated reader (--explain) may not even look; it has no business with the password.
            return false;
        }
    }

    private Stored? Read()
    {
        lock (_gate)
        {
            try
            {
                // Read only from a directory that is still what the service made it: a password file
                // somebody else could have put there is not the user's password.
                if (!Trusted() || !File.Exists(FilePath) || new FileInfo(FilePath).Length > MaxFileBytes)
                {
                    return null;
                }

                var stored = JsonSerializer.Deserialize<StoredCredential>(File.ReadAllBytes(FilePath));
                return stored is null
                    ? null
                    : new Stored(
                        new ProxyCredentialBinding(stored.Type, stored.Host, stored.Port, stored.Username),
                        stored.Secret,
                        stored.AllowPlaintextBasic);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
            {
                return null;
            }
        }
    }

    private sealed record Stored(ProxyCredentialBinding Binding, string Secret, bool AllowPlaintextBasic);

    private sealed record StoredCredential(
        ProxyProtocolType Type, string Host, ushort Port, string Username, string Secret, bool AllowPlaintextBasic = false);
}
