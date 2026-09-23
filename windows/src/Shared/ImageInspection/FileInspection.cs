namespace SplitLane.Platform;

/// <summary>What Authenticode verification concluded about a file.</summary>
internal enum SignatureCheck
{
    /// <summary>
    /// A signature covers the file's bytes and chains to a trusted root, either embedded in the file
    /// or through a system catalog that lists the file's hash.
    /// </summary>
    Valid,

    /// <summary>
    /// No embedded signature and no system catalog entry. A normal and common answer: most software
    /// people install is not signed at all.
    /// </summary>
    Unsigned,

    /// <summary>
    /// A signature is present and does not hold: the bytes do not match it, the chain does not reach
    /// a trusted root, the certificate is explicitly distrusted, or it expired without a timestamp.
    /// Distinct from <see cref="Unsigned"/> because a signed binary that has been edited is exactly
    /// the case that must not be mistaken for its publisher.
    /// </summary>
    Invalid,
}

/// <summary>Cheap identity of one version of a file on disk.</summary>
/// <param name="Size">File size in bytes.</param>
/// <param name="LastWriteUtcTicks">Last write time as UTC <see cref="DateTime"/> ticks; 0 when out of range.</param>
/// <param name="VolumeSerial">Serial number of the volume holding the file.</param>
/// <param name="FileIndex">
/// NTFS file index. Changes when a file is replaced by a copy, even a byte-identical one, which is
/// what makes a stamp a version identity rather than a content identity. On ReFS the real identifier
/// is 128 bits and this is its truncation.
/// </param>
/// <remarks>
/// A stamp answers "is this still the file that was inspected" for the price of one open and one
/// query, so the expensive <see cref="ImageFile.Inspect"/> runs once per version rather than once per
/// process start.
/// </remarks>
internal readonly record struct FileStamp(long Size, long LastWriteUtcTicks, uint VolumeSerial, ulong FileIndex)
{
    /// <summary>False for the default value, which describes no file.</summary>
    public bool IsKnown => Size > 0 || FileIndex != 0;
}

/// <summary>One inspection of one file version.</summary>
/// <param name="Stamp">The version inspected, read from the same handle as everything else.</param>
/// <param name="Signature">The Authenticode verdict.</param>
/// <param name="SignerSubject">
/// Subject RDNs of the leaf signer in certificate (encoded) order, keyed by short name where one is
/// conventional (<c>CN</c>, <c>O</c>, <c>OU</c>, <c>L</c>, <c>S</c>, <c>C</c>,
/// <c>SERIALNUMBER</c>) and by dotted OID otherwise. Empty unless <see cref="SignatureCheck.Valid"/>.
/// </param>
/// <param name="SignerCommonName">
/// The leaf signer's CN, for display. Null unless <see cref="SignatureCheck.Valid"/>, and null when
/// the certificate has no CN.
/// </param>
/// <param name="SignerThumbprint">
/// Upper-case hex SHA-1 thumbprint of the leaf signer. Diagnostic only: it changes every time the
/// publisher renews its certificate, so it must never be part of an identity.
/// </param>
/// <param name="FromCatalog">
/// True when the verdict came from a system catalog rather than an embedded signature. Most of
/// Windows itself is signed this way.
/// </param>
/// <param name="ErrorCode">
/// 0 for <see cref="SignatureCheck.Valid"/>; otherwise the <c>WinVerifyTrust</c> HRESULT. For an
/// unsigned PE that is <c>TRUST_E_NOSIGNATURE</c>; for a file that is not a PE it is usually
/// <c>TRUST_E_SUBJECT_FORM_UNKNOWN</c>.
/// </param>
/// <param name="Sha256">
/// Lower-case hex SHA-256 of the whole file, when requested and the read succeeded; otherwise null.
/// </param>
/// <remarks>
/// Everything here comes from a single open handle that denies write sharing, so the stamp, the
/// signature and the hash describe the same bytes. Opening the file three times would let an update
/// land between the signature check and the hash.
/// </remarks>
internal sealed record FileInspection(
    FileStamp Stamp,
    SignatureCheck Signature,
    IReadOnlyList<KeyValuePair<string, string>> SignerSubject,
    string? SignerCommonName,
    string? SignerThumbprint,
    bool FromCatalog,
    int ErrorCode,
    string? Sha256);
