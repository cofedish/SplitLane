using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using SplitLane.Platform;
using Xunit.Abstractions;

namespace SplitLane.Engine.Tests;

/// <summary>
/// Stamps, Authenticode verdicts, hashes and package identity, read from real files on the machine.
/// </summary>
/// <remarks>
/// <para>
/// Nothing here is simulated. <c>WinVerifyTrust</c> runs against the <c>dotnet.exe</c> host, which
/// carries an embedded signature, and against an inbox Windows tool, which is signed only through a
/// system catalog; both exist on any Windows machine that can run these tests, and both are located
/// at run time rather than named by a path from one machine.
/// </para>
/// <para>
/// The case that matters most is the edited copy of a signed binary. Extracting the certificate
/// without checking it, which is what <c>X509Certificate.CreateFromSignedFile</c> does, reports the
/// original publisher for it; this layer must report it invalid.
/// </para>
/// </remarks>
public sealed class ImageInspectionTests : IDisposable
{
    private const int TrustENoSignature = unchecked((int)0x800B_0100);

    private readonly ITestOutputHelper _output;
    private readonly string _scratch;

    public ImageInspectionTests(ITestOutputHelper output)
    {
        _output = output;
        _scratch = Path.Combine(Path.GetTempPath(), "SplitLane.ImageInspectionTests." + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_scratch);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_scratch, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    [Fact]
    public void EmbeddedSignatureOfTheDotnetHostIsValid()
    {
        var host = DotnetHost();
        if (host is null)
        {
            _output.WriteLine("SKIPPED: no dotnet.exe found beside the running runtime or under Program Files.");
            return;
        }

        var inspection = InspectLogged("embedded", host, computeSha256: false);

        Assert.Equal(SignatureCheck.Valid, inspection.Signature);
        Assert.False(inspection.FromCatalog);
        Assert.Equal(0, inspection.ErrorCode);
        Assert.Contains(new KeyValuePair<string, string>("O", "Microsoft Corporation"), inspection.SignerSubject);
        Assert.False(string.IsNullOrEmpty(inspection.SignerCommonName));
        Assert.Matches("^[0-9A-F]{40}$", inspection.SignerThumbprint!);
        Assert.Null(inspection.Sha256);
    }

    [Fact]
    public void CatalogSignedSystemToolIsValidThroughItsCatalog()
    {
        var tool = CatalogSignedSystemTool();

        var inspection = InspectLogged("catalog", tool, computeSha256: false);

        Assert.Equal(SignatureCheck.Valid, inspection.Signature);
        Assert.True(inspection.FromCatalog);
        Assert.Equal(0, inspection.ErrorCode);
        Assert.Equal("Microsoft Windows", inspection.SignerCommonName);
        Assert.Contains(new KeyValuePair<string, string>("CN", "Microsoft Windows"), inspection.SignerSubject);
    }

    [Fact]
    public void CatalogSignatureFollowsTheBytesNotTheLocation()
    {
        // Identity has to survive a folder move: a catalog lists a hash, not a path.
        var copy = CopyToScratch(CatalogSignedSystemTool());

        var inspection = InspectLogged("catalog copy", copy, computeSha256: false);

        Assert.Equal(SignatureCheck.Valid, inspection.Signature);
        Assert.True(inspection.FromCatalog);
        Assert.Equal("Microsoft Windows", inspection.SignerCommonName);
    }

    [Fact]
    public void SignedBinaryWithOneByteChangedIsInvalid()
    {
        var host = DotnetHost();
        if (host is null)
        {
            _output.WriteLine("SKIPPED: no dotnet.exe found beside the running runtime or under Program Files.");
            return;
        }

        var bytes = File.ReadAllBytes(host);

        // The middle of the file is code or data, which the Authenticode hash covers. The signature
        // itself sits at the end: the last 10 KB of 167 KB for the .NET 10 host.
        bytes[bytes.Length / 2] ^= 0xFF;
        var tampered = Path.Combine(_scratch, "tampered-" + Path.GetFileName(host));
        File.WriteAllBytes(tampered, bytes);

        var inspection = InspectLogged("tampered", tampered, computeSha256: false);

        Assert.Equal(SignatureCheck.Invalid, inspection.Signature);
        Assert.NotEqual(0, inspection.ErrorCode);
        Assert.NotEqual(TrustENoSignature, inspection.ErrorCode);
        Assert.False(inspection.FromCatalog);
        Assert.Empty(inspection.SignerSubject);
        Assert.Null(inspection.SignerCommonName);
        Assert.Null(inspection.SignerThumbprint);
    }

    [Fact]
    public void UnsignedExecutableIsUnsigned()
    {
        // The engine's and the testbed's apphosts are copied beside the tests by their project
        // references, and the SDK writes them unsigned.
        var candidates = new[] { "SplitLane.Testbed.Socks5.exe", "SplitLane.Engine.exe" }
            .Select(name => Path.Combine(AppContext.BaseDirectory, name));
        var unsigned = candidates.FirstOrDefault(File.Exists);
        Assert.True(unsigned is not null, $"No unsigned apphost found in {AppContext.BaseDirectory}.");

        var inspection = InspectLogged("unsigned", unsigned, computeSha256: false);

        Assert.Equal(SignatureCheck.Unsigned, inspection.Signature);
        Assert.Equal(TrustENoSignature, inspection.ErrorCode);
        Assert.False(inspection.FromCatalog);
        Assert.Empty(inspection.SignerSubject);
        Assert.Null(inspection.SignerCommonName);
    }

    [Fact]
    public void FileThatIsNotAnExecutableIsNotValidAndDoesNotThrow()
    {
        var text = Path.Combine(_scratch, "notes.txt");
        File.WriteAllText(text, "not a portable executable\r\n");

        var inspection = InspectLogged("text", text, computeSha256: true);

        Assert.NotEqual(SignatureCheck.Valid, inspection.Signature);
        Assert.NotEqual(0, inspection.ErrorCode);
        Assert.Equal(
            Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(text))),
            inspection.Sha256);
        Assert.Equal((null, null, null), ImageFile.ReadVersion(text));
    }

    [Fact]
    public void MissingFileIsNotAnError()
    {
        var missing = Path.Combine(_scratch, "does-not-exist.exe");

        Assert.Null(ImageFile.Inspect(missing, computeSha256: true));
        Assert.False(ImageFile.TryGetStamp(missing, out var stamp));
        Assert.False(stamp.IsKnown);
        Assert.Equal((null, null, null), ImageFile.ReadVersion(missing));
        Assert.Null(ImageFile.Inspect(string.Empty, computeSha256: false));
        Assert.Null(ImageFile.Inspect("C:\\Windows\\notepad.exe\0.txt", computeSha256: false));
    }

    [Fact]
    public void StampIdentifiesAVersionAndHashIdentifiesContent()
    {
        var original = CatalogSignedSystemTool();
        var copy = CopyToScratch(original);

        Assert.True(ImageFile.TryGetStamp(original, out var first));
        Assert.True(ImageFile.TryGetStamp(original, out var second));
        Assert.True(ImageFile.TryGetStamp(copy, out var copied));

        Assert.True(first.IsKnown);
        Assert.Equal(first, second);

        // A byte-identical copy is a different file: same size, different index.
        Assert.Equal(first.Size, copied.Size);
        Assert.NotEqual(first.FileIndex, copied.FileIndex);
        Assert.NotEqual(first, copied);

        var inspectedOriginal = ImageFile.Inspect(original, computeSha256: true);
        var inspectedCopy = ImageFile.Inspect(copy, computeSha256: true);
        Assert.NotNull(inspectedOriginal);
        Assert.NotNull(inspectedCopy);

        // Inspect reads its stamp from its own handle; it must be the same version TryGetStamp saw.
        Assert.Equal(first, inspectedOriginal.Stamp);
        Assert.Equal(copied, inspectedCopy.Stamp);

        var expected = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(original)));
        Assert.Equal(expected, inspectedOriginal.Sha256);
        Assert.Equal(expected, inspectedCopy.Sha256);
    }

    [Fact]
    public void VersionResourceIsReadAndTrimmed()
    {
        var (product, originalFilename, description) = ImageFile.ReadVersion(CatalogSignedSystemTool());
        _output.WriteLine($"product='{product}' original='{originalFilename}' description='{description}'");

        Assert.False(string.IsNullOrEmpty(originalFilename));
        foreach (var value in new[] { product, originalFilename, description })
        {
            if (value is not null)
            {
                Assert.Equal(value.Trim(), value);
            }
        }
    }

    [Fact]
    public void UnpackagedAndMissingProcessesHaveNoPackageFamily()
    {
        Assert.Null(ProcessPackage.FamilyName((uint)Environment.ProcessId));
        Assert.Null(ProcessPackage.FamilyName(uint.MaxValue));
        Assert.Null(ProcessPackage.FamilyName(0u));
        Assert.Null(ProcessPackage.FamilyName(nint.Zero));

        using var self = Process.GetCurrentProcess();
        Assert.Null(ProcessPackage.FamilyName(self.Handle));
    }

    [Fact]
    public void InspectionCostIsRecorded()
    {
        // Not a performance test: a record of what one inspection costs on this machine, so a
        // regression shows up in the test log before it shows up as a stalled engine.
        var host = DotnetHost();
        if (host is null)
        {
            _output.WriteLine("SKIPPED: no dotnet.exe found beside the running runtime or under Program Files.");
            return;
        }

        ImageFile.Inspect(host, computeSha256: false);

        var withoutHash = Stopwatch.StartNew();
        var verified = ImageFile.Inspect(host, computeSha256: false);
        withoutHash.Stop();

        var withHash = Stopwatch.StartNew();
        var hashed = ImageFile.Inspect(host, computeSha256: true);
        withHash.Stop();

        var stamp = Stopwatch.StartNew();
        Assert.True(ImageFile.TryGetStamp(host, out _));
        stamp.Stop();

        Assert.NotNull(verified);
        Assert.NotNull(hashed);
        Assert.NotNull(hashed.Sha256);
        _output.WriteLine(
            $"{host} ({new FileInfo(host).Length} bytes): stamp {stamp.Elapsed.TotalMilliseconds:F2} ms, " +
            $"verify {withoutHash.Elapsed.TotalMilliseconds:F1} ms, " +
            $"verify+sha256 {withHash.Elapsed.TotalMilliseconds:F1} ms");
    }

    /// <summary>Runs one inspection, writes what it found to the test log, and requires a result.</summary>
    private FileInspection InspectLogged(string label, string path, bool computeSha256)
    {
        var watch = Stopwatch.StartNew();
        var inspection = ImageFile.Inspect(path, computeSha256);
        watch.Stop();

        Assert.NotNull(inspection);

        var subject = string.Join(", ", inspection.SignerSubject.Select(pair => $"{pair.Key}={pair.Value}"));
        _output.WriteLine(
            $"{label}: {path} -> {inspection.Signature}, FromCatalog={inspection.FromCatalog}, " +
            $"ErrorCode=0x{inspection.ErrorCode:X8}, CN={inspection.SignerCommonName}, " +
            $"Subject=[{subject}], Thumbprint={inspection.SignerThumbprint}, " +
            $"{watch.Elapsed.TotalMilliseconds:F1} ms");

        return inspection;
    }

    /// <summary>
    /// The <c>dotnet.exe</c> host: this process when it is one, then the usual install location, then
    /// the root of the runtime these tests are running on. Under <c>dotnet test</c> the process is
    /// <c>testhost.exe</c>, so the first rarely applies.
    /// </summary>
    private static string? DotnetHost()
    {
        var candidates = new List<string?>();

        if (string.Equals(Path.GetFileName(Environment.ProcessPath), "dotnet.exe", StringComparison.OrdinalIgnoreCase))
        {
            candidates.Add(Environment.ProcessPath);
        }

        candidates.Add(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "dotnet.exe"));

        // <root>\shared\Microsoft.NETCore.App\<version>\ - three levels below the host.
        candidates.Add(Path.GetFullPath(
            Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "..", "..", "..", "dotnet.exe")));

        return candidates.FirstOrDefault(path => !string.IsNullOrEmpty(path) && File.Exists(path));
    }

    /// <summary>
    /// An inbox Windows tool with no embedded signature, signed only through a system catalog.
    /// </summary>
    /// <remarks>
    /// Chosen by reading the PE header, not by name alone. <c>curl.exe</c> and <c>tar.exe</c> look
    /// catalog-signed to PowerShell, which prefers a catalog when there is one, but on Windows 11
    /// 26200 both also carry an embedded signature, and an embedded signature is what this layer
    /// checks first.
    /// </remarks>
    private static string CatalogSignedSystemTool()
    {
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);

        foreach (var name in new[] { "PING.EXE", "where.exe", "whoami.exe", "hostname.exe", "cmd.exe" })
        {
            var path = Path.Combine(system, name);
            if (File.Exists(path) && !HasEmbeddedSignature(path))
            {
                return path;
            }
        }

        throw new InvalidOperationException($"No system tool without an embedded signature in {system}.");
    }

    /// <summary>Whether a PE's certificate table (data directory 4) is non-empty.</summary>
    private static bool HasEmbeddedSignature(string path)
    {
        var image = File.ReadAllBytes(path);
        var optionalHeader = BitConverter.ToInt32(image, 0x3C) + 4 + 20;   // "PE\0\0", then the COFF header
        var isPe32Plus = BitConverter.ToUInt16(image, optionalHeader) == 0x20B;
        var directories = optionalHeader + (isPe32Plus ? 112 : 96);
        return BitConverter.ToInt32(image, directories + (4 * 8) + 4) != 0;
    }

    private string CopyToScratch(string source)
    {
        var destination = Path.Combine(_scratch, Path.GetFileName(source));
        File.Copy(source, destination);
        return destination;
    }
}
