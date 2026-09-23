using System.IO;
using SplitLane.Core.Configuration;
using SplitLane.Core.Rules;

namespace SplitLane.Platform;

/// <summary>
/// Reads the evidence application identity is decided from, from a real file.
/// </summary>
/// <remarks>
/// <para>
/// Compiled into both the app and the engine from this one source file. The app builds a rule's
/// identity from what this returns when the user picks an application; the engine builds a process's
/// evidence from what it returns when that process claims a rule. If the two ever computed the
/// publisher key differently, every rule would silently match nothing, so there is one
/// implementation and it is linked, not copied.
/// </para>
/// <para>
/// Slow by nature - it verifies an Authenticode signature, which hashes the whole file - and never
/// called on the routing path.
/// </para>
/// </remarks>
internal sealed class WindowsImageInspector : IImageInspector
{
    /// <summary>The shared instance. Stateless.</summary>
    public static WindowsImageInspector Instance { get; } = new();

    /// <summary>
    /// Verifies a file and reads its version resource. Null when the file cannot be opened.
    /// </summary>
    public static ImageEvidence? Read(string executablePath, bool computeSha256)
    {
        var path = ExecutablePath.Normalize(executablePath);
        if (path.Length == 0)
        {
            return null;
        }

        var inspection = ImageFile.Inspect(path, computeSha256);
        if (inspection is null)
        {
            return null;
        }

        var (product, originalName, _) = ImageFile.ReadVersion(path);
        var pdbName = PeDebugInfo.ReadPdbName(path);
        var valid = inspection.Signature == SignatureCheck.Valid;

        // The version resource is read through a second open. If the file changed in between, the
        // strings may not belong to the bytes that were verified; the stamp says whether it did.
        if (!ImageFile.TryGetStamp(path, out var after) || after != inspection.Stamp)
        {
            return null;
        }

        return new ImageEvidence
        {
            ExecutablePath = path,
            Signature = inspection.Signature switch
            {
                SignatureCheck.Valid => SignatureStatus.Valid,
                SignatureCheck.Unsigned => SignatureStatus.Unsigned,
                _ => SignatureStatus.Invalid,
            },
            SignerSubject = valid ? PublisherName.Canonical(inspection.SignerSubject) : null,
            SignerName = valid ? inspection.SignerCommonName : null,
            ProductName = product,
            OriginalFileName = originalName,
            DebugName = pdbName,
            HasVersionInfo = true,
            FileSize = inspection.Stamp.Size,
            Sha256 = inspection.Sha256,
        };
    }

    /// <inheritdoc />
    public ImageEvidence? Inspect(string executablePath, bool computeSha256) => Read(executablePath, computeSha256);

    /// <inheritdoc />
    public IReadOnlyList<string> ChildDirectories(string directory)
    {
        // Listing a directory as LocalSystem is an access like any other: nothing off this machine.
        if (!ImageFile.IsLocalPath(directory))
        {
            return [];
        }

        try
        {
            return Directory.Exists(directory) ? Directory.GetDirectories(directory) : [];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }
}
