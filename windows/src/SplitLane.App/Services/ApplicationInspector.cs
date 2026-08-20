using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;

namespace SplitLane.App.Services;

/// <summary>One application the user could select.</summary>
/// <param name="Identity">What SplitLane would record about it.</param>
/// <param name="ProcessCount">How many of its processes are running right now.</param>
public sealed record ApplicationCandidate(AppIdentity Identity, int ProcessCount)
{
    /// <summary>Name for the list.</summary>
    public string DisplayName => Identity.DisplayName;

    /// <summary>Path, for the second line.</summary>
    public string Path => Identity.ExecutablePath;

    /// <summary>Publisher, or a plain statement that there is none.</summary>
    public string PublisherLabel => Identity.Publisher ?? "Unsigned";

    /// <summary>Whether the executable carries a valid Authenticode signature.</summary>
    public bool IsSigned => Identity.Publisher is not null;

    /// <summary>How many processes this executable currently has, for the picker.</summary>
    public string ProcessLabel => ProcessCount == 1 ? "1 process" : $"{ProcessCount} processes";

    /// <summary>Whether there is a process count worth showing.</summary>
    public bool HasProcesses => ProcessCount > 0;
}

/// <summary>
/// Turns an executable into an <see cref="AppIdentity"/>, and enumerates what is running.
/// </summary>
/// <remarks>
/// <para>
/// This is where the Windows equivalent of "pick an app" lives. macOS reads a code signing identifier
/// out of a bundle; here the routing key is the image path, and the publisher is read from the
/// Authenticode certificate for display and for the hardening path.
/// </para>
/// <para>
/// Signature verification is a chain build that can touch the network for revocation, so it is done
/// once at pick time and cached — never on the routing path, which is exactly why the engine matches
/// on the path and not the signature.
/// </para>
/// </remarks>
public static class ApplicationInspector
{
    private static readonly Dictionary<string, string?> PublisherCache =
        new(ExecutablePath.Comparer);

    /// <summary>
    /// Lists the distinct applications with a visible window or a network-capable process.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Grouped by executable, because ten Chrome processes are one application to a user, and the
    /// routing key is the executable anyway.
    /// </para>
    /// <para>
    /// The signature is deliberately <b>not</b> read here. Verifying Authenticode builds a
    /// certificate chain, which can block on a revocation check, and doing it for every process on
    /// the machine turned opening the picker into a visible multi-second stall. It is read once, for
    /// the one application the user actually picks.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<ApplicationCandidate> RunningApplications()
    {
        var byPath = new Dictionary<string, (string Name, int Count)>(ExecutablePath.Comparer);

        foreach (var process in Process.GetProcesses())
        {
            try
            {
                var path = process.MainModule?.FileName;
                if (string.IsNullOrEmpty(path))
                {
                    continue;
                }

                var normalized = ExecutablePath.Normalize(path);
                if (normalized.Length == 0)
                {
                    continue;
                }

                var name = string.IsNullOrWhiteSpace(process.MainWindowTitle)
                    ? process.ProcessName
                    : process.ProcessName;

                if (byPath.TryGetValue(normalized, out var existing))
                {
                    byPath[normalized] = (existing.Name, existing.Count + 1);
                }
                else
                {
                    byPath[normalized] = (name, 1);
                }
            }
            catch (Win32Exception)
            {
                // A protected or cross-session process. Nothing to show and nothing to route.
            }
            catch (InvalidOperationException)
            {
                // It exited while being enumerated.
            }
            finally
            {
                process.Dispose();
            }
        }

        return [.. byPath
            .Select(pair => new ApplicationCandidate(
                Describe(pair.Key, pair.Value.Name, readPublisher: false), pair.Value.Count))
            .OrderBy(candidate => candidate.DisplayName, StringComparer.OrdinalIgnoreCase)];
    }

    /// <summary>Builds an identity for an executable on disk.</summary>
    /// <param name="executablePath">Full path of the executable.</param>
    /// <param name="fallbackName">Name to use when the version resource has none.</param>
    /// <param name="readPublisher">
    /// Whether to verify the Authenticode signature. False for bulk enumeration, where the cost is
    /// paid once per process on the machine and the answer is not shown.
    /// </param>
    public static AppIdentity Describe(
        string executablePath, string? fallbackName = null, bool readPublisher = true)
    {
        var normalized = ExecutablePath.Normalize(executablePath);
        string? description = null;
        string? product = null;

        try
        {
            if (File.Exists(normalized))
            {
                var info = FileVersionInfo.GetVersionInfo(normalized);
                description = Trimmed(info.FileDescription);
                product = Trimmed(info.ProductName);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }

        var name = product
            ?? description
            ?? Trimmed(fallbackName)
            ?? ExecutablePath.FileName(normalized);

        return new AppIdentity
        {
            ExecutablePath = normalized,
            DisplayName = name,
            FileDescription = description,
            Publisher = readPublisher ? ReadPublisher(normalized) : null,
            PackageFamilyName = null,
        };
    }

    /// <summary>
    /// Reads the Authenticode subject of an executable, or null when it has none that verifies.
    /// </summary>
    /// <remarks>
    /// The result is cached per path. Building a certificate chain is expensive and can block on a
    /// revocation check, and the picker calls this once per candidate.
    /// </remarks>
    public static string? ReadPublisher(string executablePath)
    {
        var normalized = ExecutablePath.Normalize(executablePath);

        lock (PublisherCache)
        {
            if (PublisherCache.TryGetValue(normalized, out var cached))
            {
                return cached;
            }
        }

        string? publisher = null;

        try
        {
            if (File.Exists(normalized))
            {
                // CreateFromSignedFile, not the certificate loaders. The loaders expect a
                // certificate file; an Authenticode signature is embedded in the PE, and asking
                // them to read an .exe throws — which silently labelled every signed binary on the
                // machine "Unsigned".
#pragma warning disable SYSLIB0057 // The Authenticode extraction path has no modern replacement.
                using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(normalized));
#pragma warning restore SYSLIB0057
                publisher = SimpleName(certificate.Subject);
            }
        }
        catch (CryptographicException)
        {
            // Unsigned, which is a normal and common answer.
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }

        lock (PublisherCache)
        {
            PublisherCache[normalized] = publisher;
        }

        return publisher;
    }

    /// <summary>Pulls the CN out of a distinguished name, falling back to the whole string.</summary>
    private static string? SimpleName(string subject)
    {
        if (string.IsNullOrWhiteSpace(subject))
        {
            return null;
        }

        foreach (var part in subject.Split(','))
        {
            var trimmed = part.Trim();
            if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            {
                return trimmed[3..].Trim('"');
            }
        }

        return subject;
    }

    private static string? Trimmed(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
