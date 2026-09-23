using System.Buffers.Binary;
using System.IO;
using System.Text;

namespace SplitLane.Platform;

/// <summary>
/// Reads the program database name an executable was linked with, from its CodeView debug record.
/// </summary>
/// <remarks>
/// <para>
/// A second name for a binary that its file name cannot change. The linker writes the path of the
/// <c>.pdb</c> into the image's debug directory - <c>codex.pdb</c> for <c>codex.exe</c> - and that
/// record lives in a section the Authenticode signature covers. Renaming a file leaves it as it was.
/// </para>
/// <para>
/// It matters for exactly the binaries with nothing else to go on: command-line tools written in Rust
/// or Go routinely ship with no version resource, so for them the signer and the on-disk file name were
/// the whole identity, and any other binary the same publisher signed could be copied under the
/// selected name and inherit its rule.
/// </para>
/// <para>
/// Only the file name of the recorded path is returned: the directory is the build machine's, and
/// changes from one build to the next.
/// </para>
/// </remarks>
internal static class PeDebugInfo
{
    /// <summary>How much of the file is read for the headers and section table.</summary>
    private const int HeaderBytes = 4096;

    private const int ImageDebugTypeCodeView = 2;
    private const uint CodeViewRsds = 0x53445352; // "RSDS"

    /// <summary>The PDB file name recorded in a file, or null.</summary>
    public static string? ReadPdbName(string path)
    {
        // Opened as LocalSystem by the engine: nothing off this machine (see ImageFile.IsLocalPath).
        if (!ImageFile.IsLocalPath(path))
        {
            return null;
        }

        try
        {
            using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096);

            var headers = new byte[Math.Min(HeaderBytes, stream.Length)];
            stream.ReadExactly(headers);

            if (!TryLocateDebugDirectory(headers, out var directoryOffset, out var directorySize))
            {
                return null;
            }

            // A handful of entries at most; anything larger is not a real debug directory.
            if (directorySize is <= 0 or > 28 * 32 || directoryOffset + directorySize > stream.Length)
            {
                return null;
            }

            var directory = new byte[directorySize];
            stream.Position = directoryOffset;
            stream.ReadExactly(directory);

            for (var entry = 0; entry + 28 <= directory.Length; entry += 28)
            {
                var type = BinaryPrimitives.ReadInt32LittleEndian(directory.AsSpan(entry + 12));
                var size = BinaryPrimitives.ReadInt32LittleEndian(directory.AsSpan(entry + 16));
                var pointer = BinaryPrimitives.ReadInt32LittleEndian(directory.AsSpan(entry + 24));

                if (type != ImageDebugTypeCodeView || size is < 25 or > 4096 || pointer <= 0 ||
                    pointer + (long)size > stream.Length)
                {
                    continue;
                }

                var record = new byte[size];
                stream.Position = pointer;
                stream.ReadExactly(record);
                return PdbName(record);
            }

            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return null;
        }
    }

    /// <summary>The file name inside an RSDS record, or null. Pure.</summary>
    internal static string? PdbName(ReadOnlySpan<byte> record)
    {
        // RSDS: signature (4), GUID (16), age (4), then a NUL-terminated UTF-8 path.
        if (record.Length < 25 || BinaryPrimitives.ReadUInt32LittleEndian(record) != CodeViewRsds)
        {
            return null;
        }

        var text = record[24..];
        var end = text.IndexOf((byte)0);
        var path = Encoding.UTF8.GetString(end >= 0 ? text[..end] : text);
        var separator = path.LastIndexOfAny(['\\', '/']);
        var name = (separator >= 0 ? path[(separator + 1)..] : path).Trim();

        return name.Length == 0 ? null : name;
    }

    /// <summary>
    /// Finds the file offset and size of the debug directory from the headers. Pure.
    /// </summary>
    internal static bool TryLocateDebugDirectory(ReadOnlySpan<byte> headers, out long offset, out int size)
    {
        offset = 0;
        size = 0;

        if (headers.Length < 64 || headers[0] != (byte)'M' || headers[1] != (byte)'Z')
        {
            return false;
        }

        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(headers[0x3C..]);
        if (peOffset <= 0 || peOffset + 24 > headers.Length ||
            BinaryPrimitives.ReadUInt32LittleEndian(headers[peOffset..]) != 0x00004550)
        {
            return false;
        }

        var fileHeader = peOffset + 4;
        var sections = BinaryPrimitives.ReadUInt16LittleEndian(headers[(fileHeader + 2)..]);
        var optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(headers[(fileHeader + 16)..]);
        var optional = fileHeader + 20;

        if (optional + optionalSize > headers.Length || optionalSize < 2)
        {
            return false;
        }

        // PE32 (0x10B) keeps its data directories at 96 into the optional header, PE32+ (0x20B) at 112.
        var magic = BinaryPrimitives.ReadUInt16LittleEndian(headers[optional..]);
        var directories = magic switch
        {
            0x10B => optional + 96,
            0x20B => optional + 112,
            _ => -1,
        };

        const int DebugDirectoryIndex = 6;
        var entry = directories + (DebugDirectoryIndex * 8);
        if (directories < 0 || entry + 8 > optional + optionalSize)
        {
            return false;
        }

        var rva = BinaryPrimitives.ReadUInt32LittleEndian(headers[entry..]);
        size = BinaryPrimitives.ReadInt32LittleEndian(headers[(entry + 4)..]);
        if (rva == 0 || size <= 0)
        {
            return false;
        }

        var table = optional + optionalSize;
        for (var index = 0; index < sections && table + ((index + 1) * 40) <= headers.Length; index++)
        {
            var section = headers[(table + (index * 40))..];
            var virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(section[8..]);
            var virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(section[12..]);
            var rawSize = BinaryPrimitives.ReadUInt32LittleEndian(section[16..]);
            var rawPointer = BinaryPrimitives.ReadUInt32LittleEndian(section[20..]);
            var extent = Math.Max(virtualSize, rawSize);

            if (rva >= virtualAddress && rva < virtualAddress + extent)
            {
                offset = rawPointer + (long)(rva - virtualAddress);
                return true;
            }
        }

        return false;
    }
}
