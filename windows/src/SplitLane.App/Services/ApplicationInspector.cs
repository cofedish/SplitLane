using System.ComponentModel;
using System.Diagnostics;
using SplitLane.Core.Configuration;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;
using SplitLane.Platform;

namespace SplitLane.App.Services;

/// <summary>One application the user could select.</summary>
/// <param name="Path">Normalised path of the executable.</param>
/// <param name="DisplayName">Name for the list.</param>
/// <param name="PackageFamilyName">
/// Package family read from a running process's token, or null for an unpackaged one.
/// </param>
/// <param name="ProcessCount">How many of its processes are running right now.</param>
/// <remarks>
/// Deliberately not an <see cref="AppIdentity"/>. The scan does not verify signatures, so it does not
/// know what the application is - only where it is running from. An identity built here would be a
/// path identity, which is exactly the kind of rule that stopped matching after every update.
/// </remarks>
public sealed record ApplicationCandidate(string Path, string DisplayName, string? PackageFamilyName, int ProcessCount)
{
    /// <summary>How many processes this executable currently has, for the picker.</summary>
    public string ProcessLabel => ProcessCount == 1 ? "1 process" : $"{ProcessCount} processes";

    /// <summary>Whether there is a process count worth showing.</summary>
    public bool HasProcesses => ProcessCount > 0;

    /// <summary>The package family, from the token or failing that from a WindowsApps path; or empty.</summary>
    public string PackageFamily => !string.IsNullOrEmpty(PackageFamilyName)
        ? PackageFamilyName
        : PackagePath.Family(Path);
}

/// <summary>
/// What SplitLane would record for a file the user picked: an identity, or the reason there is none.
/// </summary>
/// <param name="Path">The file, normalised.</param>
/// <param name="DisplayName">Name to show, including in the refusal.</param>
/// <param name="Identity">The identity to record, or null when the file cannot be added.</param>
/// <param name="Refusal">Why it cannot be added, in words for the user; null when it can.</param>
public sealed record ApplicationDescription(string Path, string DisplayName, AppIdentity? Identity, string? Refusal)
{
    /// <summary>Whether a rule can be made from this.</summary>
    public bool CanBeAdded => Identity is not null;
}

/// <summary>
/// Turns an executable into an <see cref="AppIdentity"/>, and enumerates what is running.
/// </summary>
/// <remarks>
/// <para>
/// This is where the Windows equivalent of "pick an app" lives. The identity recorded here is what
/// the engine compares a process against for as long as the rule exists, so it is built from the same
/// evidence the engine builds - <see cref="WindowsImageInspector"/>, linked into both - and by the
/// same function, <see cref="ConfigurationMigrator.IdentityFor"/>.
/// </para>
/// <para>
/// It used to read the publisher with <c>X509Certificate.CreateFromSignedFile</c>, which extracts the
/// certificate without checking that the signature covers the file, and cut the common name at the
/// first comma - <c>CN="OpenAI OpCo, LLC"</c> became <c>OpenAI OpCo</c>. A publisher recorded that way
/// was never evidence of anything, which is why it could only ever be shown and never matched on.
/// </para>
/// </remarks>
public static class ApplicationInspector
{
    /// <summary>
    /// Lists the distinct applications with a visible window or a network-capable process.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Grouped by executable, because ten Chrome processes are one application to a user.
    /// </para>
    /// <para>
    /// The signature is deliberately <b>not</b> read here. Verifying Authenticode hashes the whole
    /// file, and doing it for every process on the machine turned opening the picker into a visible
    /// multi-second stall. It is read once, for the one application the user actually picks.
    /// </para>
    /// <para>
    /// The package family <i>is</i> read, because it is cheap - one token query - and only a running
    /// process has it. A packaged application installed on another drive has no <c>WindowsApps</c> in
    /// its path, so the path alone would record it as an ordinary signed program, and the rule would
    /// then match its files rather than its package.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<ApplicationCandidate> RunningApplications()
    {
        var byPath = new Dictionary<string, (string Name, string? Package, int Count)>(ExecutablePath.Comparer);

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

                if (byPath.TryGetValue(normalized, out var existing))
                {
                    // Every process of one packaged executable carries the same family; asking again
                    // is only worth it while none of them has answered.
                    var package = existing.Package ?? ProcessPackage.FamilyName((uint)process.Id);
                    byPath[normalized] = (existing.Name, package, existing.Count + 1);
                }
                else
                {
                    byPath[normalized] = (process.ProcessName, ProcessPackage.FamilyName((uint)process.Id), 1);
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
                pair.Key, DisplayNameFor(pair.Key, pair.Value.Name), pair.Value.Package, pair.Value.Count))
            .OrderBy(candidate => candidate.DisplayName, StringComparer.OrdinalIgnoreCase)];
    }

    /// <summary>
    /// Reads a file and works out the identity a rule for it would record.
    /// </summary>
    /// <param name="executablePath">Full path of the executable.</param>
    /// <param name="fallbackName">Name to use when the version resource has none.</param>
    /// <param name="packageFamilyName">
    /// The package family of a running process picked from the list, read from its token. Null for a
    /// file picked from disk, where the path is all there is to go on.
    /// </param>
    /// <remarks>
    /// Slow: it verifies the Authenticode signature and hashes the file, a full read each - about a
    /// second and a half for a 320 MB executable read cold. Call it off the UI thread.
    /// </remarks>
    public static ApplicationDescription Describe(
        string executablePath, string? fallbackName = null, string? packageFamilyName = null)
    {
        var path = ExecutablePath.Normalize(executablePath);
        var (product, _, description) = ImageFile.ReadVersion(path);
        var name = product ?? description ?? Trimmed(fallbackName) ?? ExecutablePath.FileName(path);

        var package = Trimmed(packageFamilyName);
        var evidence = WindowsImageInspector.Read(path, computeSha256: true);

        if (evidence is null)
        {
            // A packaged application is recognised by its package, which the token or the path has
            // already given; its file does not have to be readable. Anything else cannot be told apart
            // from any other program without reading it.
            if (package is null && PackagePath.Family(path).Length == 0)
            {
                return new ApplicationDescription(path, name, null, Unreadable(name, path));
            }

            evidence = ImageEvidence.FromPath(path);
        }

        if (package is not null)
        {
            evidence = evidence with { PackageFamilyName = package };
        }

        var identity = ConfigurationMigrator.IdentityFor(path, name, evidence, description);
        return identity is null
            ? new ApplicationDescription(path, name, null, Unrecognisable(name, path, evidence))
            : new ApplicationDescription(path, name, identity, null);
    }

    /// <summary>The name the picker shows before anything has been verified.</summary>
    private static string DisplayNameFor(string path, string processName)
    {
        var (product, _, description) = ImageFile.ReadVersion(path);
        return product ?? description ?? Trimmed(processName) ?? ExecutablePath.FileName(path);
    }

    private static string Unreadable(string name, string path) =>
        $"{name} could not be added: {path} could not be opened. It may be in the middle of an " +
        "update, or it may not be readable from your account. Try again in a moment.";

    /// <summary>Why <see cref="ConfigurationMigrator.IdentityFor"/> refused a file, in the user's terms.</summary>
    private static string Unrecognisable(string name, string path, ImageEvidence evidence) => evidence.Signature switch
    {
        SignatureStatus.Invalid =>
            $"{name} could not be added: the signature on {path} does not verify. The file was changed " +
            "after it was signed, or its certificate is not trusted on this machine, so SplitLane cannot " +
            "tell which program it is — and a rule for it could be claimed by any file with the same " +
            "broken signature.",
        SignatureStatus.Valid =>
            $"{name} could not be added: the signature on {path} verifies but names no publisher " +
            "SplitLane can recognise it by.",
        _ =>
            $"{name} could not be added: {path} is not signed, and it could not be read in full to " +
            "record which file it is. Try again in a moment.",
    };

    private static string? Trimmed(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
