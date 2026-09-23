using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using static SplitLane.Platform.ImageInspectionNative;

namespace SplitLane.Platform;

/// <summary>Reads what SplitLane needs to know about an executable on disk.</summary>
/// <remarks>
/// <para>
/// Compiled into both the App and the engine from one source, so the identity the App records when a
/// person picks an application and the identity the engine computes when that application starts are
/// the same function of the same bytes.
/// </para>
/// <para>
/// Nothing here throws for the ordinary ways a file can fail to be read - missing, locked, access
/// denied, not a PE. Those are answers, and the engine meets all of them on a normal machine.
/// </para>
/// </remarks>
internal static class ImageFile
{
    /// <summary>
    /// FileStream buffer for hashing. Measured on a 224 MB executable with a warm cache: 331 ms at
    /// 4 KB, 140 ms at 64 KB, 136 ms at 1 MB. 64 KB takes nearly all of the gain and stays below the
    /// large-object-heap threshold, so it is not a fresh LOH allocation per inspection.
    /// </summary>
    private const int HashBufferSize = 64 * 1024;

    /// <summary>The largest FILETIME a <see cref="DateTime"/> can represent.</summary>
    private static readonly long MaxFileTime = DateTime.MaxValue.ToFileTimeUtc();

    /// <summary>
    /// Reads the stamp of a file: size, last-write time, volume serial and file index.
    /// </summary>
    /// <remarks>
    /// Opens for attributes only and shares everything, so it succeeds against a file another
    /// process is writing, running or deleting, and never blocks one. It costs one open and one query.
    /// </remarks>
    /// <returns>False when the file cannot be opened or queried.</returns>
    public static bool TryGetStamp(string path, out FileStamp stamp)
    {
        stamp = default;

        if (!IsUsablePath(path))
        {
            return false;
        }

        using var handle = CreateFile(
            path,
            FileReadAttributes,
            FileShareRead | FileShareWrite | FileShareDelete,
            nint.Zero,
            OpenExisting,
            0,
            nint.Zero);

        return !handle.IsInvalid && TryReadStamp(handle, out stamp);
    }

    /// <summary>
    /// Stamps, verifies and optionally hashes a file, all from one handle.
    /// </summary>
    /// <param name="path">Full path of the file.</param>
    /// <param name="computeSha256">Whether to hash the whole file as well: a second full read.</param>
    /// <returns>Null when the file cannot be opened; otherwise the inspection.</returns>
    /// <remarks>
    /// <para>
    /// Expensive: WinVerifyTrust reads the whole file. Measured with a warm file cache, a 224 MB
    /// executable took 188 ms to verify and 319 ms with the SHA-256; a cold read is bounded by the
    /// disk instead, and has been seen at about 1.5 s for 320 MB. It belongs off any hot path, once
    /// per file version, keyed by <see cref="FileStamp"/>.
    /// </para>
    /// <para>
    /// The handle shares read and delete but not write. Denying write is what makes the stamp, the
    /// signature and the hash describe the same bytes: nothing can change the file while it is held.
    /// Sharing delete means an updater that renames the file out of the way is not refused because
    /// SplitLane happened to be reading it. A file already open for writing cannot be opened this
    /// way, and returns null - it is most likely mid-update, and what it contains is not yet a version.
    /// </para>
    /// </remarks>
    public static FileInspection? Inspect(string path, bool computeSha256)
    {
        if (!IsUsablePath(path))
        {
            return null;
        }

        using var handle = CreateFile(
            path,
            GenericRead,
            FileShareRead | FileShareDelete,
            nint.Zero,
            OpenExisting,
            FileFlagSequentialScan,
            nint.Zero);

        if (handle.IsInvalid || !TryReadStamp(handle, out var stamp))
        {
            return null;
        }

        var verdict = Authenticode.Verify(handle, path);
        var sha256 = computeSha256 ? HashWhole(handle) : null;
        var signer = verdict.Check == SignatureCheck.Valid ? verdict.Signer : null;

        return new FileInspection(
            stamp,
            verdict.Check,
            signer?.Subject ?? [],
            signer?.CommonName,
            signer?.Thumbprint,
            verdict.FromCatalog,
            verdict.ErrorCode,
            sha256);
    }

    /// <summary>Reads the naming strings from a file's own, language-neutral version resource.</summary>
    /// <returns>Each value trimmed, or null when absent, empty or unreadable.</returns>
    /// <remarks>
    /// <para>
    /// Language-neutral on purpose (<c>FILE_VER_GET_NEUTRAL</c>). <see cref="FileVersionInfo"/> reads
    /// a MUI-enabled binary's strings from its satellite <c>&lt;lang&gt;\name.exe.mui</c>: a separate
    /// file, not covered by the executable's signature, that anyone who can write next to the file can
    /// supply - and the reason Windows components report their product name in the display language.
    /// The neutral resource is inside the signed image and reads the same on every machine, which a
    /// rule written on one machine and deployed to ten thousand needs.
    /// </para>
    /// </remarks>
    public static (string? ProductName, string? OriginalFilename, string? FileDescription) ReadVersion(string path)
    {
        if (!IsUsablePath(path))
        {
            return (null, null, null);
        }

        var size = GetFileVersionInfoSizeEx(FileVerGetNeutral, path, out _);
        if (size == 0 || size > MaxVersionResource)
        {
            return (null, null, null);
        }

        var block = new byte[size];
        if (!GetFileVersionInfoEx(FileVerGetNeutral, path, 0, size, block))
        {
            return (null, null, null);
        }

        var table = StringTable(block);
        return table is null
            ? (null, null, null)
            : (Query(block, table, "ProductName"), Query(block, table, "OriginalFilename"), Query(block, table, "FileDescription"));
    }

    /// <summary>
    /// Whether a path is on a drive of this machine: a fixed, removable, optical or RAM disk.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The engine runs as LocalSystem, and it reads the files that processes were started from and the
    /// files rules name. Opening <c>\\host\share\app.exe</c> - or a drive letter mapped to one - as
    /// LocalSystem makes the machine authenticate to that host with its own account, which is a known
    /// way to turn "any user can name a path" into a relayable machine credential. So nothing that
    /// is not on a local drive is opened at all: UNC paths, <c>\\?\</c> and <c>\\.\</c> device paths,
    /// and drives Windows reports as remote. Such a file cannot be verified, and is treated as not
    /// being any selected application.
    /// </para>
    /// <para>
    /// Drive types are cached for a minute. The question is asked once per new process on the routing
    /// path, and a drive letter changing from local to remote is rare enough to be caught within that.
    /// </para>
    /// </remarks>
    public static bool IsLocalPath(string? path)
    {
        if (string.IsNullOrEmpty(path) || path.Length < 3 || path[1] != ':' || path[2] != '\\' ||
            !char.IsAsciiLetter(path[0]))
        {
            return false;
        }

        // Type and time packed into one long, so a reader on another thread never sees one without
        // the other: a torn read here would call a local drive remote for a minute.
        var index = char.ToUpperInvariant(path[0]) - 'A';
        var now = Environment.TickCount64;
        var cached = Volatile.Read(ref DriveTypes[index]);
        var type = (uint)(cached & 0xFF);
        var checkedAt = cached >> 8;

        if (cached == 0 || now - checkedAt > DriveTypeLifetimeMs)
        {
            type = GetDriveType($"{char.ToUpperInvariant(path[0])}:\\");
            Volatile.Write(ref DriveTypes[index], (now << 8) | (type & 0xFF));
        }

        return type is DriveFixed or DriveRemovable or DriveCdRom or DriveRamDisk;
    }

    /// <summary>
    /// The long form of a path that contains 8.3 short names, or the path unchanged.
    /// </summary>
    /// <remarks>
    /// A process started through <c>C:\Users\JOHNSM~1\...</c> reports that spelling as its image
    /// path, and a file name like <c>CODEX~1.EXE</c> claims no rule - so the selected application went
    /// DIRECT depending on how it happened to be launched. Only paths with a tilde are asked about.
    /// </remarks>
    public static string LongPath(string path)
    {
        if (string.IsNullOrEmpty(path) || !path.Contains('~', StringComparison.Ordinal) || !IsLocalPath(path))
        {
            return path;
        }

        var buffer = new char[1024];
        var length = GetLongPathName(path, buffer, (uint)buffer.Length);
        if (length > buffer.Length && length <= short.MaxValue)
        {
            buffer = new char[length];
            length = GetLongPathName(path, buffer, (uint)buffer.Length);
        }

        return length == 0 || length > buffer.Length ? path : new string(buffer, 0, (int)length);
    }

    /// <summary>Largest version resource read. Real ones are a few kilobytes.</summary>
    private const uint MaxVersionResource = 1024 * 1024;

    private const long DriveTypeLifetimeMs = 60_000;

    private static readonly long[] DriveTypes = new long[26];

    /// <summary>The first language and code page the resource declares, as a StringFileInfo key.</summary>
    private static string? StringTable(byte[] block)
    {
        if (VerQueryValue(block, @"\VarFileInfo\Translation", out var pointer, out var length) &&
            pointer != nint.Zero && length >= 4)
        {
            var language = (ushort)System.Runtime.InteropServices.Marshal.ReadInt16(pointer);
            var codePage = (ushort)System.Runtime.InteropServices.Marshal.ReadInt16(pointer, 2);
            return $"{language:X4}{codePage:X4}";
        }

        // No translation table: the two tables resource compilers write when none is declared.
        foreach (var fallback in new[] { "040904B0", "040904E4", "04090000" })
        {
            if (VerQueryValue(block, $@"\StringFileInfo\{fallback}\ProductName", out _, out _) ||
                VerQueryValue(block, $@"\StringFileInfo\{fallback}\OriginalFilename", out _, out _))
            {
                return fallback;
            }
        }

        return null;
    }

    private static string? Query(byte[] block, string table, string name)
    {
        if (!VerQueryValue(block, $@"\StringFileInfo\{table}\{name}", out var pointer, out var length) ||
            pointer == nint.Zero || length == 0)
        {
            return null;
        }

        return Trimmed(System.Runtime.InteropServices.Marshal.PtrToStringUni(pointer, (int)length).TrimEnd('\0'));
    }

    /// <summary>
    /// Rejects what cannot name a local file. An embedded NUL in particular: the native call would stop
    /// reading at it and open a different file from the one the caller named. And anything not on a
    /// local drive - see <see cref="IsLocalPath"/>.
    /// </summary>
    private static bool IsUsablePath(string? path)
        => !string.IsNullOrEmpty(path) && !path.Contains('\0', StringComparison.Ordinal) && IsLocalPath(path);

    private static bool TryReadStamp(SafeFileHandle handle, out FileStamp stamp)
    {
        if (!GetFileInformationByHandle(handle, out var info))
        {
            stamp = default;
            return false;
        }

        var size = ((long)info.FileSizeHigh << 32) | info.FileSizeLow;
        var lastWrite = ((long)info.LastWriteTimeHigh << 32) | info.LastWriteTimeLow;
        var index = ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow;

        // A FILETIME outside DateTime's range is possible - it is whatever the last writer set - and
        // converting it would throw. It becomes 0, which still differs from any real time.
        var ticks = lastWrite >= 0 && lastWrite <= MaxFileTime
            ? DateTime.FromFileTimeUtc(lastWrite).Ticks
            : 0;

        stamp = new FileStamp(size, ticks, info.VolumeSerialNumber, index);
        return true;
    }

    /// <summary>
    /// SHA-256 of the whole file, read through the handle the signature was checked on.
    /// </summary>
    /// <returns>Lower-case hex, or null when the read failed.</returns>
    /// <remarks>
    /// The FileStream takes ownership of the handle and closes it; this is the last use of it.
    /// </remarks>
    private static string? HashWhole(SafeFileHandle handle)
    {
        try
        {
            using var stream = new FileStream(handle, FileAccess.Read, HashBufferSize);

            // A FileStream built on a handle starts at the handle's current position, and the
            // verification calls read through this handle before it.
            stream.Position = 0;
            return Convert.ToHexStringLower(SHA256.HashData(stream));
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static string? Trimmed(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
