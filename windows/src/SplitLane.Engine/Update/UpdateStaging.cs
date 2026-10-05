using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SplitLane.Engine.Runtime;
using SplitLane.Platform;

namespace SplitLane.Engine.Update;

/// <summary>Hands a verified installer package to Windows Installer.</summary>
/// <remarks>
/// An abstraction so that tests can prove which file would have been installed without ever running
/// <c>msiexec</c>.
/// </remarks>
public interface IUpdateInstaller
{
    /// <summary>Starts installing the package at <paramref name="verifiedPackage"/>.</summary>
    void Install(StagedPackage verifiedPackage);
}

/// <summary>Runs <c>msiexec.exe</c> from System32, by absolute path.</summary>
public sealed class MsiexecInstaller : IUpdateInstaller
{
    /// <summary>The installer executable, never resolved through the search path (SL-SEC-015).</summary>
    public static string MsiexecPath { get; } = Path.Combine(Environment.SystemDirectory, "msiexec.exe");

    /// <inheritdoc />
    public void Install(StagedPackage verifiedPackage)
    {
        ArgumentNullException.ThrowIfNull(verifiedPackage);

        var start = new ProcessStartInfo(MsiexecPath)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Environment.SystemDirectory,
        };

        // ArgumentList quotes each argument; nothing from the network reaches the command line except
        // a path the service built itself under its own protected directory.
        start.ArgumentList.Add("/i");
        start.ArgumentList.Add(verifiedPackage.Path);
        start.ArgumentList.Add("/qn");
        start.ArgumentList.Add("/norestart");

        using var process = Process.Start(start)
            ?? throw new InvalidOperationException("msiexec could not be started");
    }
}

/// <summary>An installer package that was downloaded, hashed and re-verified in protected storage.</summary>
/// <param name="Path">Where it is.</param>
/// <param name="Sha256">Its SHA-256, upper-case hex, as verified.</param>
/// <param name="Volume">Volume serial number of the file that was verified.</param>
/// <param name="FileIndex">File index of the file that was verified.</param>
public sealed record StagedPackage(string Path, string Sha256, uint Volume, ulong FileIndex);

/// <summary>Why a staged package was refused.</summary>
public sealed class StagingRejectedException : IOException
{
    /// <summary>Builds the exception.</summary>
    public StagingRejectedException(string message)
        : base(message)
    {
    }
}

/// <summary>
/// Puts an update package where only the service can change it, and proves it is still the package
/// the signed manifest described right before it is installed (SL-SEC-001).
/// </summary>
/// <remarks>
/// <para>
/// The old arrangement downloaded into <c>%ProgramData%\SplitLane\updates</c> under a predictable name,
/// hashed the file by path, closed it, and ran <c>msiexec</c> on the path. Users can create files and
/// folders there, so a user could prepare the file or the folder in advance and change the package
/// after it was hashed - code running as SYSTEM.
/// </para>
/// <para>Now:</para>
/// <list type="number">
/// <item>the staging root is a <see cref="ProtectedDirectory"/> (SYSTEM and Administrators only,
/// inheritance cut, never a link), and each update gets a fresh directory with a random name inside
/// it, so nothing can be prepared under the name in advance;</item>
/// <item>the package is created with <see cref="FileMode.CreateNew"/> and no sharing, written, flushed
/// and hashed through that same handle - no other handle exists while it is judged;</item>
/// <item>right before installing, it is opened again, sharing read only, and the handle is checked
/// to be the same file (volume and index), a regular file with exactly one name (no hard link to
/// anything else), owned by and writable only by SYSTEM/Administrators - and hashed again;</item>
/// <item>only then is its path handed to the installer.</item>
/// </list>
/// <para>
/// Windows Installer has no way to install from a handle; it takes a path. That path is in a directory
/// nobody but SYSTEM and Administrators can write, so between the last check and <c>msiexec</c>
/// opening it only an administrator could change it, and an administrator does not need this to run
/// code as SYSTEM.
/// </para>
/// </remarks>
public sealed class UpdateStaging
{
    private const uint FileAttributeReparsePoint = 0x400;
    private const uint FileAttributeDirectory = 0x10;

    /// <summary>Rights on the file that would let someone other than the writers change it.</summary>
    private const FileSystemRights Modifying =
        FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete |
        FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership |
        FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes;

    private readonly ProtectedDirectory _root;
    private readonly HashSet<string> _trusted;

    /// <summary>Staging under the service's protected update directory.</summary>
    public UpdateStaging()
        : this(new ProtectedDirectory(SplitLanePaths.UpdateStaging, UserAccess.None))
    {
    }

    /// <summary>Staging under an explicit protected directory. Used by tests.</summary>
    internal UpdateStaging(ProtectedDirectory root, IEnumerable<SecurityIdentifier>? additionalTrusted = null)
    {
        _root = root ?? throw new ArgumentNullException(nameof(root));
        _trusted = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "S-1-5-18",
            "S-1-5-32-544",
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
        };

        foreach (var sid in additionalTrusted ?? [])
        {
            _trusted.Add(sid.Value);
        }
    }

    /// <summary>
    /// Writes a package into a new protected directory and checks its hash on the handle it was
    /// written through.
    /// </summary>
    /// <param name="fileName">A file name the caller built; it must not contain a path.</param>
    /// <param name="writeContent">Writes the package into the stream it is given.</param>
    /// <param name="expectedSha256">The hash the signed manifest names.</param>
    /// <param name="cancellationToken">Cancels the download.</param>
    public async Task<StagedPackage> StageAsync(
        string fileName,
        Func<Stream, CancellationToken, Task> writeContent,
        string expectedSha256,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);
        ArgumentNullException.ThrowIfNull(writeContent);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedSha256);

        if (Path.GetFileName(fileName) != fileName || fileName.Contains("..", StringComparison.Ordinal))
        {
            throw new ArgumentException("The package name must be a plain file name.", nameof(fileName));
        }

        RemoveStaleStages();

        var directory = _root.CreateUniqueChild("stage");
        var path = Path.Combine(directory, fileName);

        try
        {
            string actual;
            ImageInspectionNative.ByHandleFileInformation identity;

            await using (var file = new FileStream(
                path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 81920, FileOptions.Asynchronous))
            {
                await writeContent(file, cancellationToken).ConfigureAwait(false);
                await file.FlushAsync(cancellationToken).ConfigureAwait(false);
                file.Flush(flushToDisk: true);

                file.Position = 0;
                actual = Convert.ToHexString(await SHA256.HashDataAsync(file, cancellationToken).ConfigureAwait(false));
                identity = Identity(file.SafeFileHandle);
            }

            if (!actual.Equals(expectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new StagingRejectedException(
                    "the downloaded installer does not match the hash the release was signed with");
            }

            return new StagedPackage(path, actual, identity.VolumeSerialNumber, Index(identity));
        }
        catch
        {
            TryDeleteDirectory(directory);
            throw;
        }
    }

    /// <summary>
    /// Proves the staged package is still exactly what was verified, and returns it. Called right
    /// before the package is handed to the installer.
    /// </summary>
    public StagedPackage VerifyFinal(StagedPackage staged)
    {
        ArgumentNullException.ThrowIfNull(staged);

        var directory = Path.GetDirectoryName(staged.Path)
            ?? throw new StagingRejectedException("the package has no directory");

        if (!IsWithin(directory, _root.Path))
        {
            throw new StagingRejectedException("the package is not in the protected staging directory");
        }

        if (_root.Problem(_root.Path) is { } rootProblem)
        {
            throw new StagingRejectedException($"the staging directory is not safe: {rootProblem}");
        }

        if (_root.Problem(directory) is { } directoryProblem)
        {
            throw new StagingRejectedException($"the package's directory is not safe: {directoryProblem}");
        }

        using var file = new FileStream(staged.Path, FileMode.Open, FileAccess.Read, FileShare.Read);

        var identity = Identity(file.SafeFileHandle);

        if ((identity.FileAttributes & (FileAttributeReparsePoint | FileAttributeDirectory)) != 0)
        {
            throw new StagingRejectedException("the package is not a regular file");
        }

        if (identity.NumberOfLinks != 1)
        {
            throw new StagingRejectedException("the package has more than one name (a hard link)");
        }

        if (identity.VolumeSerialNumber != staged.Volume || Index(identity) != staged.FileIndex)
        {
            throw new StagingRejectedException("the package was replaced after it was verified");
        }

        var security = file.GetAccessControl();
        var owner = security.GetOwner(typeof(SecurityIdentifier))?.Value ?? string.Empty;

        if (!_trusted.Contains(owner))
        {
            throw new StagingRejectedException($"the package is owned by {owner}");
        }

        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow &&
                !_trusted.Contains(rule.IdentityReference.Value) &&
                ((rule.FileSystemRights & Modifying) != 0 || ((int)rule.FileSystemRights & (0x10000000 | 0x40000000)) != 0))
            {
                throw new StagingRejectedException($"{rule.IdentityReference.Value} can modify the package");
            }
        }

        var actual = Convert.ToHexString(SHA256.HashData(file));

        if (!actual.Equals(staged.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new StagingRejectedException("the package changed after it was verified");
        }

        return staged;
    }

    /// <summary>
    /// Removes earlier stages but the newest, which holds the package the installed product came from
    /// - Windows Installer may need it again for a repair. Best effort.
    /// </summary>
    private void RemoveStaleStages()
    {
        var root = _root.Ensure();

        var stages = new DirectoryInfo(root).EnumerateDirectories("stage-*")
            .OrderByDescending(stage => stage.CreationTimeUtc)
            .Skip(1);

        foreach (var stale in stages)
        {
            TryDeleteDirectory(stale.FullName);
        }
    }

    private static void TryDeleteDirectory(string directory)
    {
        try
        {
            // The staging tree is SYSTEM-only and never contains links (each child is created by us),
            // so a recursive delete cannot be steered outside it.
            Directory.Delete(directory, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static bool IsWithin(string candidate, string root)
    {
        var full = Path.GetFullPath(candidate).TrimEnd('\\') + "\\";
        var prefix = Path.GetFullPath(root).TrimEnd('\\') + "\\";
        return full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    private static ImageInspectionNative.ByHandleFileInformation Identity(SafeFileHandle handle)
    {
        if (!ImageInspectionNative.GetFileInformationByHandle(handle, out var information))
        {
            throw new IOException(
                $"the package's identity could not be read (Win32 {System.Runtime.InteropServices.Marshal.GetLastPInvokeError()})");
        }

        return information;
    }

    private static ulong Index(in ImageInspectionNative.ByHandleFileInformation information) =>
        ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow;
}
