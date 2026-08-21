namespace SplitLane.Core.Update;

/// <summary>
/// The key this build trusts to have produced an update.
/// </summary>
/// <remarks>
/// <para>
/// A public key, so there is nothing secret here - it is checked in on purpose, because the point of
/// it is that it ships inside the binary. An update is trusted because it was signed by the holder
/// of the matching private key, not because of where it was downloaded from, so substituting this
/// value is substituting the whole trust decision. It changes only with an ADR.
/// </para>
/// <para>
/// The private half never enters this repository, is held in the release pipeline's secrets, and
/// signs one thing: the update manifest. Losing it means an inability to publish updates that
/// existing installations will accept; leaking it means someone else can, which is why the manifest
/// is also constrained to installer URLs on the release host (see <see cref="ManifestVerifier"/>).
/// </para>
/// <para>
/// ECDSA on P-256 with SHA-256: in the box on .NET, no package reference, and no argument about
/// which curve implementation is being used.
/// </para>
/// </remarks>
public static class ReleaseKey
{
    /// <summary>Base64 SubjectPublicKeyInfo of the release signing key.</summary>
    public const string PublicKeySpki =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQ74zI/ZFvQSN764lEft5SRM1I/a75499HT9YmHWjlvFlz" +
        "fV6vwtonni8kVmQxQAJ5zx44k1KDFS1uqlLrqV7/g==";
}
