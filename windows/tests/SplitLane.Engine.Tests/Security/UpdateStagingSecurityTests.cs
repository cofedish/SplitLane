using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using SplitLane.Core.Update;
using SplitLane.Engine.Runtime;
using SplitLane.Engine.Update;

namespace SplitLane.Engine.Tests.Security;

/// <summary>
/// SL-SEC-001: an update package is installed only if it is, at the moment it is handed over, the exact
/// file the signed manifest described, in a directory nobody but the service can write.
/// </summary>
/// <remarks>
/// Tests run unelevated, so "the service" is the test account: it is the only writer the protected
/// directories are created for. The rules are the ones the service applies with SYSTEM.
/// </remarks>
[Trait("Category", "Security")]
public sealed class UpdateStagingSecurityTests : IDisposable
{
    private static readonly SecurityIdentifier Me = WindowsIdentity.GetCurrent().User!;

    private readonly string _sandbox = Path.Combine(Path.GetTempPath(), "sl-sec001-" + Guid.NewGuid().ToString("N"));

    public UpdateStagingSecurityTests() => Directory.CreateDirectory(_sandbox);

    private string RootPath => Path.Combine(_sandbox, "updates");

    private ProtectedDirectory Root() => new(RootPath, UserAccess.None, [Me], checkAncestry: false);

    private UpdateStaging Staging() => new(Root(), [Me]);

    private static readonly byte[] Package = Encoding.ASCII.GetBytes("pretend this is an MSI");

    private static string Sha(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));

    private static Func<Stream, CancellationToken, Task> Writes(byte[] bytes) =>
        (stream, token) => stream.WriteAsync(bytes, token).AsTask();

    [Fact]
    public void A_directory_that_inherits_user_writable_permissions_is_rejected_and_replaced()
    {
        Directory.CreateDirectory(RootPath); // inherits %TEMP%'s permissions, like a user-made folder
        var planted = Path.Combine(RootPath, "planted.msi");
        File.WriteAllText(planted, "attacker");

        var root = Root();
        Assert.NotNull(root.Problem(RootPath));

        var path = root.Ensure();

        Assert.Equal(RootPath, path);
        Assert.Null(root.Problem(path));
        Assert.False(File.Exists(planted)); // the planted file went aside with the old folder
        Assert.True(new DirectoryInfo(path).GetAccessControl().AreAccessRulesProtected);
    }

    [Fact]
    public async Task A_junction_where_the_staging_directory_belongs_is_never_followed()
    {
        var target = Path.Combine(_sandbox, "elsewhere");
        Directory.CreateDirectory(target);
        CreateJunction(RootPath, target);

        var root = Root();
        Assert.Equal("it is a link", root.Problem(RootPath));

        var staged = await Staging().StageAsync("p.msi", Writes(Package), Sha(Package));

        Assert.Empty(Directory.EnumerateFileSystemEntries(target)); // nothing was written through the link
        Assert.StartsWith(RootPath + "\\", staged.Path, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, (int)(File.GetAttributes(RootPath) & FileAttributes.ReparsePoint));
    }

    [Fact]
    public async Task A_package_with_the_wrong_hash_is_refused_and_removed()
    {
        var wrong = Sha(Encoding.ASCII.GetBytes("something else"));

        await Assert.ThrowsAsync<StagingRejectedException>(() => Staging().StageAsync("p.msi", Writes(Package), wrong));

        Assert.Empty(Directory.EnumerateFiles(RootPath, "*", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task A_package_modified_after_download_is_refused()
    {
        var staging = Staging();
        var staged = await staging.StageAsync("p.msi", Writes(Package), Sha(Package));

        await using (var file = new FileStream(staged.Path, FileMode.Open, FileAccess.Write, FileShare.Read))
        {
            file.Write("tampered"u8);
        }

        var error = Assert.Throws<StagingRejectedException>(() => staging.VerifyFinal(staged));
        Assert.Contains("changed", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_package_replaced_by_another_file_with_the_same_content_is_refused()
    {
        var staging = Staging();
        var staged = await staging.StageAsync("p.msi", Writes(Package), Sha(Package));

        File.Delete(staged.Path);
        await File.WriteAllBytesAsync(staged.Path, Package);

        var error = Assert.Throws<StagingRejectedException>(() => staging.VerifyFinal(staged));
        Assert.Contains("replaced", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_package_with_a_second_name_is_refused()
    {
        var staging = Staging();
        var staged = await staging.StageAsync("p.msi", Writes(Package), Sha(Package));

        Assert.True(CreateHardLink(Path.Combine(_sandbox, "second-name.msi"), staged.Path, 0));

        var error = Assert.Throws<StagingRejectedException>(() => staging.VerifyFinal(staged));
        Assert.Contains("hard link", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_package_owned_by_an_untrusted_account_is_refused()
    {
        var staged = await Staging().StageAsync("p.msi", Writes(Package), Sha(Package));

        // Same directory, but a verifier that trusts only SYSTEM/Administrators: the test account that
        // created the file is then exactly "somebody else".
        var strict = new UpdateStaging(Root());

        var error = Assert.Throws<StagingRejectedException>(() => strict.VerifyFinal(staged));
        Assert.Contains("owned by", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_package_outside_the_staging_directory_is_refused()
    {
        var staging = Staging();
        var staged = await staging.StageAsync("p.msi", Writes(Package), Sha(Package));

        var outside = Path.Combine(_sandbox, "p.msi");
        File.Copy(staged.Path, outside);

        Assert.Throws<StagingRejectedException>(() => staging.VerifyFinal(staged with { Path = outside }));
    }

    [Fact]
    public async Task A_package_name_cannot_escape_its_directory()
    {
        await Assert.ThrowsAsync<ArgumentException>(
            () => Staging().StageAsync(@"..\evil.msi", Writes(Package), Sha(Package)));
    }

    [Fact]
    public async Task A_manifest_signed_by_another_key_installs_nothing()
    {
        using var trusted = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var installer = new RecordingInstaller();

        using var service = Service(trusted, signWith: other, Package, installer);

        Assert.Equal(UpdateState.Failed, await service.CheckAsync());
        Assert.False(await service.ApplyAsync());
        Assert.Empty(installer.Installed);
    }

    [Fact]
    public async Task A_package_that_does_not_match_the_signed_hash_installs_nothing()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var installer = new RecordingInstaller();

        using var service = Service(key, signWith: key, Package, installer, served: Encoding.ASCII.GetBytes("swapped"));

        Assert.Equal(UpdateState.Available, await service.CheckAsync());
        Assert.False(await service.ApplyAsync());
        Assert.Empty(installer.Installed);
        Assert.Contains("hash", service.LastError, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task The_installer_receives_exactly_the_verified_file()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var installer = new RecordingInstaller();

        using var service = Service(key, signWith: key, Package, installer);

        Assert.Equal(UpdateState.Available, await service.CheckAsync());
        Assert.True(await service.ApplyAsync());

        var installed = Assert.Single(installer.Installed);
        Assert.StartsWith(RootPath + "\\", installed.Package.Path, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(Sha(Package), installed.Sha256AtInstall);
        Assert.Equal(Sha(Package), installed.Package.Sha256);
        Assert.Equal(installed.Package.FileIndex, installed.FileIndexAtInstall);
    }

    [Fact]
    public void The_real_installer_runs_msiexec_from_System32_by_absolute_path()
    {
        Assert.True(Path.IsPathFullyQualified(MsiexecInstaller.MsiexecPath));
        Assert.Equal(
            Path.Combine(Environment.SystemDirectory, "msiexec.exe"),
            MsiexecInstaller.MsiexecPath,
            ignoreCase: true);
    }

    private UpdateService Service(ECDsa trusted, ECDsa signWith, byte[] package, IUpdateInstaller installer, byte[]? served = null)
    {
        const string PackageUrl = "https://github.com/cofedish/SplitLane/releases/download/v99.0.0/SplitLane-99.0.0-x64.msi";

        var manifest =
            $$"""{"version":"99.0.0","url":"{{PackageUrl}}","sha256":"{{Sha(package)}}","releasedAt":"2026-10-06T00:00:00Z"}""";
        var signature = Convert.ToBase64String(signWith.SignData(Encoding.UTF8.GetBytes(manifest), HashAlgorithmName.SHA256));
        var key = Convert.ToBase64String(trusted.ExportSubjectPublicKeyInfo());

        var handler = new StaticHandler(new Dictionary<string, byte[]>
        {
            ["update.json"] = Encoding.UTF8.GetBytes(manifest),
            ["update.json.sig"] = Encoding.ASCII.GetBytes(signature),
            ["SplitLane-99.0.0-x64.msi"] = served ?? package,
        });

        return new UpdateService(new HttpClient(handler), Staging(), installer, key)
        {
            InstalledVersion = ProductVersion.Parse("1.0.0"),
        };
    }

    private sealed class StaticHandler(IReadOnlyDictionary<string, byte[]> files) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var name = request.RequestUri!.Segments[^1];
            return Task.FromResult(files.TryGetValue(name, out var body)
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) }
                : new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    private sealed class RecordingInstaller : IUpdateInstaller
    {
        public List<(StagedPackage Package, string Sha256AtInstall, ulong FileIndexAtInstall)> Installed { get; } = [];

        public void Install(StagedPackage verifiedPackage)
        {
            // What a real installer would read, read at the moment it would read it.
            var bytes = File.ReadAllBytes(verifiedPackage.Path);
            Installed.Add((verifiedPackage, Sha(bytes), FileIndexOf(verifiedPackage.Path)));
        }
    }

    private static ulong FileIndexOf(string path)
    {
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        Assert.True(GetFileInformationByHandle(file.SafeFileHandle, out var info));
        return ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow;
    }

    private static void CreateJunction(string link, string target)
    {
        using var process = Process.Start(new ProcessStartInfo(
            Path.Combine(Environment.SystemDirectory, "cmd.exe"),
            ["/c", "mklink", "/J", link, target])
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
        })!;
        process.WaitForExit();
        Assert.Equal(0, process.ExitCode);
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(string fileName, string existingFileName, nint securityAttributes);

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct FileInfoByHandle
    {
        public uint FileAttributes;
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle file, out FileInfoByHandle info);

    public void Dispose()
    {
        try
        {
            // Junctions first, so a recursive delete never walks through one.
            foreach (var entry in Directory.EnumerateDirectories(_sandbox, "*", SearchOption.TopDirectoryOnly))
            {
                if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0)
                {
                    Directory.Delete(entry);
                }
            }

            Directory.Delete(_sandbox, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }
}
