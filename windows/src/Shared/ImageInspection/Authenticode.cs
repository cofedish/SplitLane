using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
using static SplitLane.Platform.ImageInspectionNative;

namespace SplitLane.Platform;

/// <summary>Who signed a file, read from a verified signature.</summary>
/// <param name="Subject">Subject RDNs in certificate order, keys mapped from OIDs.</param>
/// <param name="CommonName">The CN, or null when the certificate has none.</param>
/// <param name="Thumbprint">Upper-case hex SHA-1 thumbprint.</param>
internal sealed record AuthenticodeSigner(
    IReadOnlyList<KeyValuePair<string, string>> Subject,
    string? CommonName,
    string Thumbprint);

/// <summary>The outcome of verifying one open file.</summary>
/// <param name="Check">The verdict.</param>
/// <param name="ErrorCode">0 when valid, otherwise the HRESULT that decided it.</param>
/// <param name="FromCatalog">True when the verdict came from a system catalog.</param>
/// <param name="Signer">The leaf signer. Present exactly when <paramref name="Check"/> is valid.</param>
internal readonly record struct AuthenticodeVerdict(
    SignatureCheck Check, int ErrorCode, bool FromCatalog, AuthenticodeSigner? Signer);

/// <summary>
/// Authenticode verification through <c>WinVerifyTrust</c>, embedded signature first and system
/// catalogs second, with no network access.
/// </summary>
/// <remarks>
/// <para>
/// <c>X509Certificate.CreateFromSignedFile</c> is deliberately not used. It extracts the certificate
/// without checking that the signature covers the file's bytes, so a signed binary with its code
/// edited keeps reporting its publisher. <c>WinVerifyTrust</c> hashes the file and compares.
/// </para>
/// <para>
/// No network, ever: revocation is off, and URL retrieval is limited to the local cache. This runs as
/// LocalSystem on every new binary version on the machine, and a verifier that fetched CRLs would
/// make requests from the service for each of them and stall for as long as the network chose.
/// </para>
/// <para>
/// Much of Windows carries no embedded signature: its files are listed by hash in signed catalogs
/// under <c>System32\CatRoot</c>. Of ten inbox tools checked on Windows 11 26200, eight had none,
/// <c>PING.EXE</c> and <c>cmd.exe</c> among them, and a verifier that stopped at the embedded
/// signature would call them unsigned. The catalog lookup is by hash, so it follows the bytes and not
/// the location: a catalog-signed file copied elsewhere still verifies.
/// </para>
/// <para>
/// A file with both is judged by its embedded signature and reports that signer. On the same build
/// <c>curl.exe</c> is embedded-signed by "Microsoft 3rd Party Application Component" (and
/// <c>tar.exe</c> by "Microsoft Windows Third Party Application Component"), and both are also
/// catalog-listed under "Microsoft Windows". This layer reports the embedded signer; PowerShell's
/// <c>Get-AuthenticodeSignature</c>, which prefers the catalog, reports "Microsoft Windows".
/// </para>
/// </remarks>
internal static class Authenticode
{
    /// <summary>
    /// <c>TRUST_E_NO_SIGNER_CERT</c>. Reported, as <see cref="SignatureCheck.Invalid"/>, when
    /// verification succeeded but the signer certificate could not be read back from it. An
    /// identity built from an empty signer would match every other empty signer, so a signature whose
    /// signer is unknown is not treated as valid.
    /// </summary>
    internal const int TrustENoSignerCert = unchecked((int)0x8009_6002);

    /// <summary>
    /// Catalog hash algorithms, in the order tried. Null asks for SHA-1, the algorithm of catalogs
    /// that predate SHA-256 member hashes; a file is only looked up that way when no SHA-256 catalog
    /// lists it.
    /// </summary>
    private static readonly string?[] CatalogAlgorithms = ["SHA256", null];

    /// <summary>Verifies the file behind <paramref name="file"/>.</summary>
    /// <param name="file">An open handle with read access. Its file position is not preserved.</param>
    /// <param name="path">
    /// The path the handle was opened from. WinVerifyTrust wants both; the bytes are read through the
    /// handle, which is what ties the verdict to the version the caller holds open.
    /// </param>
    public static AuthenticodeVerdict Verify(SafeFileHandle file, string path)
    {
        var added = false;
        file.DangerousAddRef(ref added);

        try
        {
            var raw = file.DangerousGetHandle();

            var embedded = VerifyEmbedded(file, raw, path, out var signer);
            if (embedded == 0)
            {
                return signer is null
                    ? new AuthenticodeVerdict(SignatureCheck.Invalid, TrustENoSignerCert, false, null)
                    : new AuthenticodeVerdict(SignatureCheck.Valid, 0, false, signer);
            }

            if (embedded is not (TrustENoSignature or TrustESubjectFormUnknown or TrustEProviderUnknown))
            {
                // A signature is present and does not hold. The catalogs are not consulted: falling
                // through to them would turn "bad signature" into "unsigned" and hide the one fact
                // worth reporting about an edited binary.
                return new AuthenticodeVerdict(SignatureCheck.Invalid, embedded, false, null);
            }

            foreach (var algorithm in CatalogAlgorithms)
            {
                if (TryVerifyFromCatalog(file, raw, path, algorithm, out var result, out signer))
                {
                    if (result != 0)
                    {
                        return new AuthenticodeVerdict(SignatureCheck.Invalid, result, true, null);
                    }

                    return signer is null
                        ? new AuthenticodeVerdict(SignatureCheck.Invalid, TrustENoSignerCert, true, null)
                        : new AuthenticodeVerdict(SignatureCheck.Valid, 0, true, signer);
                }
            }

            return new AuthenticodeVerdict(SignatureCheck.Unsigned, embedded, false, null);
        }
        finally
        {
            if (added)
            {
                file.DangerousRelease();
            }
        }
    }

    /// <summary>Checks the signature embedded in the file itself.</summary>
    private static int VerifyEmbedded(SafeFileHandle file, nint raw, string path, out AuthenticodeSigner? signer)
    {
        var pathPointer = nint.Zero;
        var infoPointer = nint.Zero;

        try
        {
            pathPointer = Marshal.StringToHGlobalUni(path);

            var info = new WinTrustFileInfo
            {
                StructSize = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                FilePath = pathPointer,
                File = raw,
            };

            infoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(info, infoPointer, false);

            Rewind(file);
            return Run(WtdChoiceFile, infoPointer, out signer);
        }
        finally
        {
            Marshal.FreeHGlobal(infoPointer);
            Marshal.FreeHGlobal(pathPointer);
        }
    }

    /// <summary>
    /// Looks the file up in the system catalogs by its Authenticode hash and, when a catalog lists
    /// it, verifies the file as a member of that catalog.
    /// </summary>
    /// <returns>False when no catalog lists the file; the out values are then meaningless.</returns>
    private static bool TryVerifyFromCatalog(
        SafeFileHandle file,
        nint raw,
        string path,
        string? algorithm,
        out int result,
        out AuthenticodeSigner? signer)
    {
        result = 0;
        signer = null;

        // A null subsystem is DRIVER_ACTION_VERIFY, the catalog database the operating system's own
        // files are registered in.
        if (!CryptCATAdminAcquireContext2(out var admin, nint.Zero, algorithm, nint.Zero, 0))
        {
            return false;
        }

        try
        {
            // 64 bytes holds any digest a catalog can use; SHA-256 fills 32 and SHA-1 20.
            var hash = new byte[64];
            var hashSize = (uint)hash.Length;

            Rewind(file);
            if (!CryptCATAdminCalcHashFromFileHandle2(admin, file, ref hashSize, hash, 0)
                || hashSize == 0 || hashSize > hash.Length)
            {
                return false;
            }

            // Only the first catalog is used. A failure there is reported rather than retried against
            // other catalogs, so a verdict never depends on searching until something passes.
            var catalog = CryptCATAdminEnumCatalogFromHash(admin, hash, hashSize, 0, nint.Zero);
            if (catalog == nint.Zero)
            {
                return false;
            }

            var catalogInfo = nint.Zero;
            var catalogPath = nint.Zero;
            var memberTag = nint.Zero;
            var memberPath = nint.Zero;
            var hashPointer = nint.Zero;
            var infoPointer = nint.Zero;

            try
            {
                // CATALOG_INFO is { DWORD cbStruct; WCHAR wszCatalogFile[MAX_PATH]; }: 4 + 520 bytes,
                // no padding, since WCHAR is 2-aligned.
                var catalogInfoSize = sizeof(uint) + (MaxPath * sizeof(char));
                catalogInfo = Marshal.AllocHGlobal(catalogInfoSize);
                Marshal.Copy(new byte[catalogInfoSize], 0, catalogInfo, catalogInfoSize);
                Marshal.WriteInt32(catalogInfo, catalogInfoSize);

                if (!CryptCATCatalogInfoFromContext(catalog, catalogInfo, 0))
                {
                    return false;
                }

                var catalogFile = Marshal.PtrToStringUni(catalogInfo + sizeof(uint), MaxPath);
                var terminator = catalogFile.IndexOf('\0', StringComparison.Ordinal);
                if (terminator >= 0)
                {
                    catalogFile = catalogFile[..terminator];
                }

                catalogPath = Marshal.StringToHGlobalUni(catalogFile);

                // The member tag is the hash in upper-case hex, which is how catalogs name members.
                memberTag = Marshal.StringToHGlobalUni(Convert.ToHexString(hash, 0, (int)hashSize));
                memberPath = Marshal.StringToHGlobalUni(path);

                hashPointer = Marshal.AllocHGlobal((int)hashSize);
                Marshal.Copy(hash, 0, hashPointer, (int)hashSize);

                var info = new WinTrustCatalogInfo
                {
                    StructSize = (uint)Marshal.SizeOf<WinTrustCatalogInfo>(),
                    CatalogFilePath = catalogPath,
                    MemberTag = memberTag,
                    MemberFilePath = memberPath,
                    MemberFile = raw,
                    CalculatedFileHash = hashPointer,
                    CalculatedFileHashSize = hashSize,
                    CatAdmin = admin,
                };

                infoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustCatalogInfo>());
                Marshal.StructureToPtr(info, infoPointer, false);

                Rewind(file);
                result = Run(WtdChoiceCatalog, infoPointer, out signer);
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(infoPointer);
                Marshal.FreeHGlobal(hashPointer);
                Marshal.FreeHGlobal(memberPath);
                Marshal.FreeHGlobal(memberTag);
                Marshal.FreeHGlobal(catalogPath);
                Marshal.FreeHGlobal(catalogInfo);
                CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
            }
        }
        finally
        {
            CryptCATAdminReleaseContext(admin, 0);
        }
    }

    /// <summary>
    /// One <c>WinVerifyTrust</c> verify-and-close pair, reading the signer while the state is open.
    /// </summary>
    private static int Run(uint unionChoice, nint info, out AuthenticodeSigner? signer)
    {
        signer = null;

        var action = WinTrustActionGenericVerifyV2;
        var data = new WinTrustData
        {
            StructSize = (uint)Marshal.SizeOf<WinTrustData>(),
            UiChoice = WtdUiNone,
            RevocationChecks = WtdRevokeNone,
            UnionChoice = unionChoice,
            Info = info,
            StateAction = WtdStateActionVerify,
            ProvFlags = WtdCacheOnlyUrlRetrieval | WtdRevocationCheckNone,
        };

        try
        {
            var result = WinVerifyTrust(InvalidHandleValue, ref action, ref data);
            if (result == 0)
            {
                // The provider data, and the certificate context inside it, belong to the state
                // handle and are freed by the close below; the certificate is copied out first.
                signer = ReadSigner(data.StateData);
            }

            return result;
        }
        finally
        {
            // The state is allocated whether or not verification succeeded, and leaks unless closed.
            data.StateAction = WtdStateActionClose;
            WinVerifyTrust(InvalidHandleValue, ref action, ref data);
        }
    }

    /// <summary>Reads the leaf certificate of the first signer out of an open verification state.</summary>
    private static AuthenticodeSigner? ReadSigner(nint stateData)
    {
        if (stateData == nint.Zero)
        {
            return null;
        }

        var providerData = WTHelperProvDataFromStateData(stateData);
        if (providerData == nint.Zero)
        {
            return null;
        }

        var signerPointer = WTHelperGetProvSignerFromChain(providerData, 0, false, 0);
        if (signerPointer == nint.Zero)
        {
            return null;
        }

        var signer = Marshal.PtrToStructure<CryptProviderSignerHead>(signerPointer);

        // cbStruct is checked against the fields actually read: a structure smaller than the prefix
        // declared here would mean the layout assumption is wrong, and reading on would be reading
        // someone else's memory.
        if (signer.StructSize < Marshal.SizeOf<CryptProviderSignerHead>()
            || signer.CertChainCount == 0
            || signer.CertChain == nint.Zero)
        {
            return null;
        }

        var leaf = Marshal.PtrToStructure<CryptProviderCertHead>(signer.CertChain);
        if (leaf.StructSize < Marshal.SizeOf<CryptProviderCertHead>() || leaf.Certificate == nint.Zero)
        {
            return null;
        }

        try
        {
            // The handle constructor duplicates the context, so the copy outlives the close.
            using var certificate = new X509Certificate2(leaf.Certificate);
            var subject = SubjectOf(certificate);

            string? commonName = null;
            foreach (var (key, value) in subject)
            {
                // The last CN in certificate order is the most specific one, the one a Subject
                // string leads with.
                if (key == "CN")
                {
                    commonName = value;
                }
            }

            return new AuthenticodeSigner(subject, commonName, certificate.Thumbprint);
        }
        catch (CryptographicException)
        {
            return null;
        }
        catch (AsnContentException)
        {
            return null;
        }
    }

    /// <summary>The subject RDNs of a certificate, in encoded order.</summary>
    private static List<KeyValuePair<string, string>> SubjectOf(X509Certificate2 certificate)
    {
        var subject = new List<KeyValuePair<string, string>>();

        foreach (var rdn in certificate.SubjectName.EnumerateRelativeDistinguishedNames(reversed: false))
        {
            var value = rdn.HasMultipleElements ? null : rdn.GetSingleElementValue();

            if (value is not null)
            {
                subject.Add(new(KeyFor(rdn.GetSingleElementType().Value), value));
            }
            else
            {
                // A multi-valued RDN, or a value that is not a string type. The convenience
                // accessors throw or return null for these; decoding the SET directly keeps every
                // attribute rather than silently dropping the ones .NET does not render.
                DecodeRdn(rdn.RawData, subject);
            }
        }

        return subject;
    }

    /// <summary>Decodes an RDN's <c>SET OF AttributeTypeAndValue</c>, appending each attribute.</summary>
    private static void DecodeRdn(ReadOnlyMemory<byte> encoded, List<KeyValuePair<string, string>> into)
    {
        var reader = new AsnReader(encoded, AsnEncodingRules.BER);
        var set = reader.ReadSetOf(skipSortOrderValidation: true);

        while (set.HasData)
        {
            var attribute = set.ReadSequence();
            var oid = attribute.ReadObjectIdentifier();
            into.Add(new(KeyFor(oid), ReadValue(attribute)));
        }
    }

    /// <summary>
    /// A directory string as text, or anything else as <c>#</c> and the hex of its encoding, which is
    /// how RFC 4514 writes a value that has no string form.
    /// </summary>
    private static string ReadValue(AsnReader attribute)
    {
        var tag = attribute.PeekTag();

        if (tag.TagClass == TagClass.Universal)
        {
            var type = (UniversalTagNumber)tag.TagValue;
            if (type is UniversalTagNumber.UTF8String
                or UniversalTagNumber.PrintableString
                or UniversalTagNumber.IA5String
                or UniversalTagNumber.BMPString
                or UniversalTagNumber.NumericString
                or UniversalTagNumber.VisibleString
                or UniversalTagNumber.T61String)
            {
                return attribute.ReadCharacterString(type);
            }
        }

        return "#" + Convert.ToHexString(attribute.ReadEncodedValue().Span);
    }

    /// <summary>The conventional short name for an attribute OID, or the OID itself.</summary>
    private static string KeyFor(string? oid) => oid switch
    {
        "2.5.4.3" => "CN",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.7" => "L",
        "2.5.4.8" => "S",
        "2.5.4.6" => "C",
        "2.5.4.5" => "SERIALNUMBER",
        _ => oid ?? string.Empty,
    };

    /// <summary>
    /// Puts the file position back to the start before an API reads through the handle.
    /// </summary>
    /// <remarks>
    /// Measured on Windows 11 26200, neither needs it: WinVerifyTrust verified <c>dotnet.exe</c> with
    /// the position at 100,000, and the catalog hash of <c>PING.EXE</c> was identical with it at
    /// 20,000. Neither is documented to ignore the position, though, and the rewind costs one call.
    /// </remarks>
    private static void Rewind(SafeFileHandle file) => SetFilePointerEx(file, 0, nint.Zero, FileBegin);
}
