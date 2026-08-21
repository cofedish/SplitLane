using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SplitLane.Core.Update;

/// <summary>What a release says about itself.</summary>
/// <param name="Version">Product version of the release, as <c>0.6.0</c>.</param>
/// <param name="Url">Where the installer can be fetched.</param>
/// <param name="Sha256">SHA-256 of the installer, hex, upper or lower case.</param>
/// <param name="ReleasedAt">When the release was published.</param>
/// <param name="Notes">A sentence for the person deciding whether to install it.</param>
public sealed record UpdateManifest(
    string Version,
    string Url,
    string Sha256,
    DateTimeOffset ReleasedAt,
    string? Notes = null);

/// <summary>Why a manifest was refused.</summary>
public enum ManifestRejection
{
    /// <summary>Not refused.</summary>
    None,

    /// <summary>The bytes are not a manifest.</summary>
    Malformed,

    /// <summary>The signature does not verify against the key this build trusts.</summary>
    BadSignature,

    /// <summary>A field is missing, or names something this build will not fetch.</summary>
    Unusable,
}

/// <summary>
/// Decides whether an update manifest may be acted on.
/// </summary>
/// <remarks>
/// <para>
/// The engine runs as <c>LocalSystem</c>. Anything that can persuade it to install a file has, by
/// definition, arranged for code to run with full privileges on the machine - so the question this
/// type answers is not "is this the latest version" but "is this ours".
/// </para>
/// <para>
/// It is answered with a signature the project controls, not with the transport. TLS says the bytes
/// came from the host named in the URL; it says nothing about a compromised release, a redirected
/// host, or a mirror. The public key is compiled into the build and the private key never leaves the
/// release pipeline, so a manifest that verifies was produced by whoever holds that key and nobody
/// else. Nothing else about the update path is trusted: the URL, the version and the hash are all
/// read from the signed document rather than from anywhere they could be substituted.
/// </para>
/// <para>
/// Pure, and separate from anything that downloads, on purpose. This is the check that must not be
/// possible to get wrong, so it has to be reachable from a test that needs no network.
/// </para>
/// </remarks>
public static class ManifestVerifier
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>
    /// Verifies a signed manifest and returns it, or says why it was refused.
    /// </summary>
    /// <param name="manifestJson">The manifest document, exactly as published.</param>
    /// <param name="signatureBase64">Its detached signature, base64.</param>
    /// <param name="publicKeySpkiBase64">The key this build trusts, base64 SubjectPublicKeyInfo.</param>
    /// <param name="manifest">The manifest, when accepted.</param>
    /// <returns>The reason for refusal, or <see cref="ManifestRejection.None"/>.</returns>
    public static ManifestRejection Verify(
        string? manifestJson,
        string? signatureBase64,
        string publicKeySpkiBase64,
        out UpdateManifest? manifest)
    {
        manifest = null;

        if (string.IsNullOrWhiteSpace(manifestJson) || string.IsNullOrWhiteSpace(signatureBase64))
        {
            return ManifestRejection.Malformed;
        }

        // The signature is checked over the bytes as published, before anything is parsed out of
        // them. Verifying a re-serialised document would check a different document.
        if (!SignatureMatches(manifestJson, signatureBase64, publicKeySpkiBase64))
        {
            return ManifestRejection.BadSignature;
        }

        UpdateManifest? parsed;

        try
        {
            parsed = JsonSerializer.Deserialize<UpdateManifest>(manifestJson, Options);
        }
        catch (JsonException)
        {
            return ManifestRejection.Malformed;
        }

        if (parsed is null)
        {
            return ManifestRejection.Malformed;
        }

        if (!ProductVersion.TryParse(parsed.Version, out _) ||
            !IsAcceptableUrl(parsed.Url) ||
            !IsSha256(parsed.Sha256))
        {
            return ManifestRejection.Unusable;
        }

        manifest = parsed;
        return ManifestRejection.None;
    }

    private static bool SignatureMatches(string manifestJson, string signatureBase64, string publicKey)
    {
        try
        {
            var signature = Convert.FromBase64String(signatureBase64.Trim());
            var key = Convert.FromBase64String(publicKey.Trim());

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(key, out _);

            return ecdsa.VerifyData(
                Encoding.UTF8.GetBytes(manifestJson),
                signature,
                HashAlgorithmName.SHA256);
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            // A malformed signature or key is a failed verification, not an error to propagate.
            // Anything that cannot be checked has not been checked.
            return false;
        }
    }

    /// <summary>
    /// Whether the installer URL is one this build is willing to fetch.
    /// </summary>
    /// <remarks>
    /// HTTPS only, and only from where releases are published. The URL comes out of a signed
    /// document, so this is a second line rather than the first - but a signing key that ever leaks
    /// should not also be a way to point the engine at an arbitrary host.
    /// </remarks>
    private static bool IsAcceptableUrl(string? url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var uri) &&
        uri.Scheme == Uri.UriSchemeHttps &&
        (uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase) ||
         uri.Host.EndsWith(".github.com", StringComparison.OrdinalIgnoreCase) ||
         uri.Host.Equals("objects.githubusercontent.com", StringComparison.OrdinalIgnoreCase));

    private static bool IsSha256(string? hex)
    {
        if (hex is not { Length: 64 })
        {
            return false;
        }

        foreach (var character in hex)
        {
            if (!Uri.IsHexDigit(character))
            {
                return false;
            }
        }

        return true;
    }
}
