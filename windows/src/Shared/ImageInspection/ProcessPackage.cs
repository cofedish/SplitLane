using static SplitLane.Platform.ImageInspectionNative;

namespace SplitLane.Platform;

/// <summary>Reads the package identity of a running process.</summary>
/// <remarks>
/// <para>
/// Packaged applications are matched by package family, never by path (ADR W-0010), and the family
/// comes from the process token rather than from the install directory's name. The token's package
/// identity is assigned by the operating system when it activates the package; the process does not
/// get to choose it.
/// </para>
/// <para>
/// The handle needs only <c>PROCESS_QUERY_LIMITED_INFORMATION</c>, the same right the engine already
/// uses for the image path, so a process whose path can be read can have its package read too.
/// </para>
/// </remarks>
internal static class ProcessPackage
{
    /// <summary>
    /// Initial buffer, in characters. Package family names are a package name, an underscore and a
    /// 13-character publisher id, well inside this, so the first call normally succeeds.
    /// </summary>
    private const int InitialLength = 128;

    /// <summary>The package family name of a process, or null when it has none or cannot be opened.</summary>
    public static string? FamilyName(uint processId)
    {
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (handle == nint.Zero)
        {
            return null;
        }

        try
        {
            return FamilyName(handle);
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    /// <summary>
    /// The package family name of the process behind a handle the caller holds - only when its origin
    /// was verified. Null for an unpackaged process, an untrusted registration, or any failure.
    /// </summary>
    /// <param name="processHandle">
    /// A process handle with at least <c>PROCESS_QUERY_LIMITED_INFORMATION</c>. Not closed here.
    /// </param>
    public static string? FamilyName(nint processHandle)
    {
        var (family, verdict) = Read(processHandle);
        return verdict == PackageOriginVerdict.Verified ? family : null;
    }

    /// <summary>
    /// What the engine routes on: the family when verified, the family marked
    /// <see cref="UnverifiedPrefix"/> when the process claims one whose origin could not be established,
    /// null otherwise (SL-SEC-016).
    /// </summary>
    public static string? Claim(nint processHandle)
    {
        var (family, verdict) = Read(processHandle);
        return verdict switch
        {
            PackageOriginVerdict.Verified => family,
            PackageOriginVerdict.VerificationFailed => UnverifiedPrefix + family,
            _ => null,
        };
    }

    /// <summary>Marks a claimed family whose origin could not be verified. Never part of a real family name.</summary>
    public const string UnverifiedPrefix = "?";

    /// <summary>The package family of a process and how far its origin could be established.</summary>
    internal static (string? Family, PackageOriginVerdict Verdict) Read(nint processHandle)
    {
        if (processHandle == nint.Zero)
        {
            return (null, PackageOriginVerdict.NotPackaged);
        }

        var length = (uint)InitialLength;
        var buffer = new char[length];
        var result = GetPackageFamilyName(processHandle, ref length, buffer);

        if (result == ErrorInsufficientBuffer && length > InitialLength && length <= short.MaxValue)
        {
            buffer = new char[length];
            result = GetPackageFamilyName(processHandle, ref length, buffer);
        }

        // APPMODEL_ERROR_NO_PACKAGE is the common answer: most processes are not packaged. Other
        // failures to read the family at all are treated the same way: there is no family claim to
        // honour or to refuse, and the process is identified by its executable like any other.
        if (result != ErrorSuccess)
        {
            return (null, PackageOriginVerdict.NotPackaged);
        }

        // The returned length counts the terminating NUL.
        var end = Array.IndexOf(buffer, '\0');
        var name = new string(buffer, 0, end >= 0 ? end : buffer.Length);
        if (name.Length == 0)
        {
            return (null, PackageOriginVerdict.NotPackaged);
        }

        return (name, Origin(processHandle));
    }

    /// <summary>
    /// How the package was registered. Only Store, Inbox, LineOfBusiness and DeveloperSigned are
    /// verified origins: each requires a signature Windows trusts. Unsigned and DeveloperUnsigned layouts
    /// take their identity from a manifest the user wrote. Anything else - an origin of Unknown, an
    /// error, a Windows without the call - is a verification that failed, not a pass (SL-SEC-016).
    /// </summary>
    internal static PackageOriginVerdict Classify(int? origin) => origin switch
    {
        PackageOriginInbox or PackageOriginStore or PackageOriginDeveloperSigned or PackageOriginLineOfBusiness
            => PackageOriginVerdict.Verified,
        PackageOriginUnsigned or PackageOriginDeveloperUnsigned => PackageOriginVerdict.Untrusted,
        _ => PackageOriginVerdict.VerificationFailed,
    };

    private static PackageOriginVerdict Origin(nint processHandle)
    {
        var length = 256u;
        var buffer = new char[length];
        var result = GetPackageFullName(processHandle, ref length, buffer);

        if (result == ErrorInsufficientBuffer && length > buffer.Length && length <= short.MaxValue)
        {
            buffer = new char[length];
            result = GetPackageFullName(processHandle, ref length, buffer);
        }

        if (result != ErrorSuccess)
        {
            return Classify(null);
        }

        var end = Array.IndexOf(buffer, '\0');
        var fullName = new string(buffer, 0, end >= 0 ? end : buffer.Length);

        try
        {
            return Classify(GetStagedPackageOrigin(fullName, out var origin) == ErrorSuccess ? origin : null);
        }
        catch (Exception ex) when (ex is EntryPointNotFoundException or DllNotFoundException)
        {
            // Runs on the engine's socket pump, where an exception stops routing for the whole machine.
            // A Windows without the call cannot say how a package was registered: not verified.
            return Classify(null);
        }
    }
}

/// <summary>How far a process's package origin could be established.</summary>
internal enum PackageOriginVerdict
{
    /// <summary>The process has no package identity.</summary>
    NotPackaged,

    /// <summary>Registered from a signed package Windows trusts.</summary>
    Verified,

    /// <summary>Registered from an unsigned layout; its identity proves nothing.</summary>
    Untrusted,

    /// <summary>It claims a package, and its origin could not be established.</summary>
    VerificationFailed,
}
