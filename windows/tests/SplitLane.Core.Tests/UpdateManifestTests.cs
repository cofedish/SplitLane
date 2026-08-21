using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SplitLane.Core.Update;

namespace SplitLane.Core.Tests;

/// <summary>Deciding whether an update is ours.</summary>
/// <remarks>
/// No key material is checked in, including for tests. Each test makes its own pair, which also
/// means a test cannot accidentally pass because it was handed the real one.
/// </remarks>
public sealed class UpdateManifestTests
{
    private const string Url =
        "https://github.com/cofedish/SplitLane/releases/download/v0.7.0/SplitLane-0.7.0-x64.msi";

    private static readonly string Sha = new('a', 64);

    private static (string Json, string Signature, string PublicKey) Signed(
        string? version = "0.7.0",
        string? url = null,
        string? sha = null)
    {
        var json = JsonSerializer.Serialize(new
        {
            version,
            url = url ?? Url,
            sha256 = sha ?? Sha,
            releasedAt = "2026-08-21T12:00:00+00:00",
            notes = "A release.",
        });

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signature = key.SignData(Encoding.UTF8.GetBytes(json), HashAlgorithmName.SHA256);

        return (json,
                Convert.ToBase64String(signature),
                Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
    }

    [Fact]
    public void ASignedManifestIsAccepted()
    {
        var (json, signature, publicKey) = Signed();

        var rejection = ManifestVerifier.Verify(json, signature, publicKey, out var manifest);

        Assert.Equal(ManifestRejection.None, rejection);
        Assert.NotNull(manifest);
        Assert.Equal("0.7.0", manifest!.Version);
        Assert.Equal(Url, manifest.Url);
    }

    [Fact]
    public void AManifestEditedAfterSigningIsRefused()
    {
        // The case the signature exists for: the document says one thing, the signature covers
        // another. A single character is enough, and here it is the hash of what gets installed.
        var (json, signature, publicKey) = Signed();
        var tampered = json.Replace(Sha, new string('b', 64), StringComparison.Ordinal);

        Assert.Equal(
            ManifestRejection.BadSignature,
            ManifestVerifier.Verify(tampered, signature, publicKey, out _));
    }

    [Fact]
    public void AManifestSignedByAnotherKeyIsRefused()
    {
        var (json, signature, _) = Signed();
        var (_, _, someoneElsesKey) = Signed();

        // A perfectly valid signature, made by a key this build does not trust. This is what a
        // compromised release host produces, and the only thing that distinguishes it from a real
        // release is the key it was signed with.
        Assert.Equal(
            ManifestRejection.BadSignature,
            ManifestVerifier.Verify(json, signature, someoneElsesKey, out _));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-base64!")]
    public void AMissingOrMalformedSignatureIsRefused(string? signature)
    {
        var (json, _, publicKey) = Signed();

        Assert.NotEqual(
            ManifestRejection.None,
            ManifestVerifier.Verify(json, signature, publicKey, out _));
    }

    [Theory]
    // Not the release host. The URL comes out of a signed document, so this only matters if the
    // signing key ever leaks - which is exactly when it matters.
    [InlineData("https://example.com/SplitLane.msi")]
    // Not encrypted.
    [InlineData("http://github.com/cofedish/SplitLane/releases/download/v0.7.0/x.msi")]
    // Not a URL.
    [InlineData(@"C:\Windows\Temp\evil.msi")]
    public void AnInstallerFromAnywhereElseIsRefused(string url)
    {
        var (json, signature, publicKey) = Signed(url: url);

        Assert.Equal(
            ManifestRejection.Unusable,
            ManifestVerifier.Verify(json, signature, publicKey, out _));
    }

    [Theory]
    [InlineData("not-a-version")]
    [InlineData("")]
    public void AManifestWithNoUsableVersionIsRefused(string version)
    {
        var (json, signature, publicKey) = Signed(version: version);

        Assert.Equal(
            ManifestRejection.Unusable,
            ManifestVerifier.Verify(json, signature, publicKey, out _));
    }

    [Theory]
    [InlineData("abc")]
    [InlineData("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")]
    public void AManifestWithNoUsableHashIsRefused(string sha)
    {
        var (json, signature, publicKey) = Signed(sha: sha);

        Assert.Equal(
            ManifestRejection.Unusable,
            ManifestVerifier.Verify(json, signature, publicKey, out _));
    }

    [Fact]
    public void TheKeyThisBuildShipsIsAKey()
    {
        // Guards against a truncated or re-wrapped constant, which would fail every update with a
        // bad signature and look like a signing problem at the other end.
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(ReleaseKey.PublicKeySpki), out var read);

        Assert.True(read > 0);
        Assert.Equal(256, ecdsa.KeySize);
    }
}
