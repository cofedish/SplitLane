using SplitLane.Core.Models;
using SplitLane.Core.Rules;

namespace SplitLane.Core.Configuration;

/// <summary>Why a configuration was rejected.</summary>
public enum ConfigurationValidationCode
{
    /// <summary>A rule has no executable path.</summary>
    EmptyExecutablePath,

    /// <summary>A rule's executable path is not an absolute Windows path.</summary>
    RelativeExecutablePath,

    /// <summary>Two rules key on the same executable.</summary>
    DuplicateExecutablePath,

    /// <summary>The proxy host is empty.</summary>
    EmptyProxyHost,

    /// <summary>The proxy host is neither an IP literal nor a plausible DNS name.</summary>
    InvalidProxyHost,

    /// <summary>The proxy port is zero.</summary>
    InvalidProxyPort,

    /// <summary>Authentication is enabled with an empty username.</summary>
    EmptyUsername,

    /// <summary>The configuration was written by a newer build.</summary>
    UnsupportedSchemaVersion,

    /// <summary>The handshake timeout is zero or negative.</summary>
    NonPositiveTimeout,

    /// <summary>The redirect port collides with the upstream proxy port on loopback.</summary>
    RedirectPortCollision,
}

/// <summary>A configuration that cannot be applied, and why.</summary>
public sealed class ConfigurationValidationException(ConfigurationValidationCode code, string message)
    : Exception(message)
{
    /// <summary>What was wrong, as a value the UI can switch on.</summary>
    public ConfigurationValidationCode Code { get; } = code;
}

/// <summary>
/// Validates a configuration before it is persisted or applied.
/// </summary>
/// <remarks>
/// Several of these checks are load-bearing rather than cosmetic:
/// <list type="bullet">
/// <item><b>Empty executable path.</b> The engine reports an empty path for a process it could not
/// resolve. If an empty string were ever allowed as a rule key, every unresolvable process on the
/// machine would match it and be proxied. Rejecting it here means the key cannot exist.</item>
/// <item><b>Duplicate paths.</b> Rules are keyed by path in the snapshot, so a duplicate would
/// silently drop one rule. Better to refuse the configuration than to apply half of it.</item>
/// <item><b>Redirect port collision.</b> If the redirector listened on the same loopback port as the
/// upstream SOCKS5 server, the engine would dial itself. The loopback-destination check in the rule
/// engine already prevents the loop, but a configuration that can only fail is not one worth
/// storing.</item>
/// </list>
/// </remarks>
public static class ConfigurationValidator
{
    /// <summary>Throws if the configuration cannot be applied.</summary>
    public static void Validate(RuntimeConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        if (!configuration.Version.IsReadable)
        {
            throw new ConfigurationValidationException(
                ConfigurationValidationCode.UnsupportedSchemaVersion,
                $"Configuration schema version {configuration.Version.SchemaVersion} is newer than " +
                $"the supported version {ConfigurationVersion.CurrentSchema}");
        }

        var seen = new HashSet<string>(ExecutablePath.Comparer);
        foreach (var rule in configuration.Rules)
        {
            var path = ExecutablePath.Normalize(rule.Identity.ExecutablePath);

            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ConfigurationValidationException(
                    ConfigurationValidationCode.EmptyExecutablePath,
                    "An application rule has an empty executable path");
            }

            if (!IsAbsolutePath(path))
            {
                throw new ConfigurationValidationException(
                    ConfigurationValidationCode.RelativeExecutablePath,
                    $"Rule path is not absolute: {path}");
            }

            if (!seen.Add(path))
            {
                throw new ConfigurationValidationException(
                    ConfigurationValidationCode.DuplicateExecutablePath,
                    $"Duplicate rule for executable {path}");
            }
        }

        Validate(configuration.Proxy);

        if (configuration.RedirectPort != 0 &&
            configuration.Proxy.Endpoint.IsLoopback &&
            configuration.RedirectPort == configuration.Proxy.Endpoint.Port)
        {
            throw new ConfigurationValidationException(
                ConfigurationValidationCode.RedirectPortCollision,
                $"Redirect port {configuration.RedirectPort} is also the upstream proxy port");
        }
    }

    /// <summary>Throws if the proxy definition cannot be used.</summary>
    public static void Validate(ProxyConfiguration proxy)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        var host = proxy.Endpoint.Host.Trim();
        if (host.Length == 0)
        {
            throw new ConfigurationValidationException(
                ConfigurationValidationCode.EmptyProxyHost, "Proxy host is empty");
        }

        if (!IsPlausibleHost(host))
        {
            throw new ConfigurationValidationException(
                ConfigurationValidationCode.InvalidProxyHost,
                $"Proxy host {host} is neither a valid IP address nor a valid hostname");
        }

        if (proxy.Endpoint.Port == 0)
        {
            throw new ConfigurationValidationException(
                ConfigurationValidationCode.InvalidProxyPort,
                $"Proxy port {proxy.Endpoint.Port} is not valid");
        }

        if (proxy.HandshakeTimeoutMilliseconds <= 0)
        {
            throw new ConfigurationValidationException(
                ConfigurationValidationCode.NonPositiveTimeout,
                $"Handshake timeout {proxy.HandshakeTimeoutMilliseconds}ms must be greater than zero");
        }

        if (proxy.Credential is { } credential && string.IsNullOrWhiteSpace(credential.Username))
        {
            throw new ConfigurationValidationException(
                ConfigurationValidationCode.EmptyUsername,
                "Proxy authentication is enabled but the username is empty");
        }
    }

    /// <summary>
    /// Returns a configuration with anything unsafe corrected rather than rejected.
    /// </summary>
    /// <remarks>
    /// Used on load. A rule asking for family matching on <c>C:\Windows\System32</c> is downgraded to
    /// exact matching instead of failing the whole load: refusing to start because one rule is too
    /// broad would leave the user with no routing at all, and the downgrade is both safe and
    /// visible in the UI (ADR W-0003).
    /// </remarks>
    public static RuntimeConfiguration Sanitize(RuntimeConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var rules = new List<AppRule>(configuration.Rules.Count);
        var seen = new HashSet<string>(ExecutablePath.Comparer);

        foreach (var rule in configuration.Rules)
        {
            var normalized = ExecutablePath.Normalize(rule.Identity.ExecutablePath);
            if (string.IsNullOrWhiteSpace(normalized) || !IsAbsolutePath(normalized) || !seen.Add(normalized))
            {
                continue;
            }

            var identity = rule.Identity with { ExecutablePath = normalized };
            var mode = rule.MatchMode == MatchMode.ExecutableFamily && !identity.SupportsFamilyMatching
                ? MatchMode.Exact
                : rule.MatchMode;

            rules.Add(rule with { Identity = identity, MatchMode = mode });
        }

        return configuration with { Rules = rules };
    }

    /// <summary>True for a rooted Windows path: a drive-qualified path or a UNC path.</summary>
    internal static bool IsAbsolutePath(string normalizedPath)
    {
        if (normalizedPath.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return normalizedPath.Length > 2;
        }

        return normalizedPath.Length >= 3
            && char.IsAsciiLetter(normalizedPath[0])
            && normalizedPath[1] == ':'
            && normalizedPath[2] == '\\';
    }

    /// <summary>
    /// Accepts an IP literal or something shaped like a DNS name.
    /// </summary>
    /// <remarks>
    /// Intentionally permissive: this is a typo guard for the Proxy screen, not a hostname grammar.
    /// Rejecting an unusual but working name would be worse than accepting a nonsense one, which
    /// simply fails to connect and says so.
    /// </remarks>
    internal static bool IsPlausibleHost(string host)
    {
        if (NetworkAddress.IsIPLiteral(host))
        {
            return true;
        }

        if (System.Text.Encoding.UTF8.GetByteCount(host) > 253)
        {
            return false;
        }

        if (host.StartsWith('.') || host.EndsWith('.'))
        {
            return false;
        }

        var labels = host.Split('.');
        if (labels.Length == 0)
        {
            return false;
        }

        foreach (var label in labels)
        {
            if (label.Length == 0 || System.Text.Encoding.UTF8.GetByteCount(label) > 63)
            {
                return false;
            }

            if (label.StartsWith('-') || label.EndsWith('-'))
            {
                return false;
            }

            foreach (var c in label)
            {
                if (!char.IsLetterOrDigit(c) && c != '-' && c != '_')
                {
                    return false;
                }
            }
        }

        return true;
    }
}
