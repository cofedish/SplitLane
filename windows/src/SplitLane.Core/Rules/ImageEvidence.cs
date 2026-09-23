namespace SplitLane.Core.Rules;

/// <summary>What is known about the signature of an executable.</summary>
public enum SignatureStatus
{
    /// <summary>Not looked at yet. A rule that depends on the answer cannot be decided.</summary>
    NotChecked = 0,

    /// <summary>A signature that verifies, embedded or through a system catalog.</summary>
    Valid = 1,

    /// <summary>No signature at all.</summary>
    Unsigned = 2,

    /// <summary>
    /// A signature that does not verify: the bytes were changed after signing, the chain is not
    /// trusted, or policy refused it. Never treated as the publisher it claims to be.
    /// </summary>
    Invalid = 3,
}

/// <summary>
/// Which extra facts about an executable a routing decision is waiting for.
/// </summary>
[Flags]
public enum EvidenceNeeds
{
    /// <summary>Nothing; the decision stands.</summary>
    None = 0,

    /// <summary>The signature, and with it the version resource it covers.</summary>
    Signature = 1,

    /// <summary>The SHA-256 of the file, for a rule on an unsigned application.</summary>
    Hash = 2,
}

/// <summary>
/// The facts about a process image that application identity is decided from.
/// </summary>
/// <remarks>
/// <para>
/// Gathered in two stages because the facts cost wildly different amounts. The path, the file name,
/// the package family from the process token and the file size cost microseconds and are read on the
/// routing path. The signature costs a hash of the whole file - about 1.5 s for the 320 MB
/// <c>codex.exe</c> measured on the development machine - and is read once per file version, off the
/// routing path, only for files that claim to be a selected application.
/// </para>
/// <para>
/// A claim is cheap evidence that points at a rule: the file name a signed rule names, the folder it
/// lives under, the size of a pinned unsigned file. A claim never routes anything by itself; it only
/// says which expensive fact to go and get.
/// </para>
/// </remarks>
public sealed record ImageEvidence
{
    private readonly string _executablePath = string.Empty;

    /// <summary>Normalised image path of the process.</summary>
    public required string ExecutablePath
    {
        get => _executablePath;
        init
        {
            _executablePath = value ?? string.Empty;
            FileName = Rules.ExecutablePath.FileName(_executablePath);
        }
    }

    /// <summary>The file name part of <see cref="ExecutablePath"/>.</summary>
    public string FileName { get; private init; } = string.Empty;

    /// <summary>
    /// Package family name read from the process token, or null for an unpackaged process.
    /// </summary>
    /// <remarks>
    /// From the token, not the path: Windows assigns it when it activates the package, a process
    /// cannot give itself one, and it is the same whether the package lives under
    /// <c>C:\Program Files\WindowsApps</c> or on another drive.
    /// </remarks>
    public string? PackageFamilyName { get; init; }

    /// <summary>
    /// <c>ProductName</c> from the version resource, or null when there is none or it was not read.
    /// </summary>
    /// <remarks>
    /// The version resource sits inside the signed image, so once the signature is
    /// <see cref="SignatureStatus.Valid"/> this is as trustworthy as the publisher. Before that it is
    /// a claim.
    /// </remarks>
    public string? ProductName
    {
        get => _productName;
        init
        {
            _productName = value;
            NormalizedProductName = ProductFamily.Normalize(value);
        }
    }

    /// <summary>
    /// <see cref="ProductName"/> in the form product rules are keyed on, computed once. The lookup runs
    /// per connection; normalising there allocated per connection.
    /// </summary>
    public string NormalizedProductName { get; private init; } = string.Empty;

    private readonly string? _productName;

    /// <summary>
    /// <c>OriginalFilename</c> from the language-neutral version resource, or null. Inside the signed
    /// image, so a copy renamed to look like another binary still reports its own.
    /// </summary>
    public string? OriginalFileName { get; init; }

    /// <summary>
    /// File name of the program database recorded in the image's CodeView debug record, e.g.
    /// <c>codex.pdb</c>, or null. Inside the signed image, and unchanged by renaming the file.
    /// </summary>
    public string? DebugName { get; init; }

    /// <summary>Whether <see cref="ProductName"/> reflects the file, rather than not having been read.</summary>
    public bool HasVersionInfo { get; init; }

    /// <summary>What is known about the signature.</summary>
    public SignatureStatus Signature { get; init; }

    /// <summary>Canonical publisher key when <see cref="Signature"/> is valid; see <see cref="PublisherName"/>.</summary>
    public string? SignerSubject { get; init; }

    /// <summary>Signer common name for display, when the signature is valid.</summary>
    public string? SignerName { get; init; }

    /// <summary>File size in bytes, or 0 when not known.</summary>
    public long FileSize { get; init; }

    /// <summary>
    /// Lower-case hex SHA-256 of the file when computed; empty when it was asked for and could not be,
    /// which matches nothing and is not asked for again; null when not asked for.
    /// </summary>
    public string? Sha256 { get; init; }

    /// <summary>Evidence that is only a path. What a flow carries before anything else is read.</summary>
    public static ImageEvidence FromPath(string? executablePath) =>
        new() { ExecutablePath = Rules.ExecutablePath.Normalize(executablePath) };

    /// <summary>Whether a signed identity can be judged from this evidence.</summary>
    public bool HasSignatureVerdict => Signature != SignatureStatus.NotChecked;
}
