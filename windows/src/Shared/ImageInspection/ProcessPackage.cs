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
    /// The package family name of the process behind a handle the caller holds, or null when it has
    /// none or on any error.
    /// </summary>
    /// <param name="processHandle">
    /// A process handle with at least <c>PROCESS_QUERY_LIMITED_INFORMATION</c>. Not closed here.
    /// </param>
    public static string? FamilyName(nint processHandle)
    {
        if (processHandle == nint.Zero)
        {
            return null;
        }

        var length = (uint)InitialLength;
        var buffer = new char[length];
        var result = GetPackageFamilyName(processHandle, ref length, buffer);

        if (result == ErrorInsufficientBuffer && length > InitialLength && length <= short.MaxValue)
        {
            buffer = new char[length];
            result = GetPackageFamilyName(processHandle, ref length, buffer);
        }

        // APPMODEL_ERROR_NO_PACKAGE is the common answer: most processes are not packaged. Every
        // other failure is treated the same way, because "no package" routes by path, which is how
        // an unpackaged process would have been routed anyway.
        if (result != ErrorSuccess)
        {
            return null;
        }

        // The returned length counts the terminating NUL.
        var end = Array.IndexOf(buffer, '\0');
        var name = new string(buffer, 0, end >= 0 ? end : buffer.Length);
        if (name.Length == 0)
        {
            return null;
        }

        // A package registered from an unsigned layout - Developer Mode's loose-file registration -
        // takes its name and publisher from a manifest the user wrote, so its family name proves
        // nothing about who published it. It is treated as unpackaged: matched, if at all, by the
        // signature of its executable like anything else.
        return IsUnsignedRegistration(processHandle) ? null : name;
    }

    private static bool IsUnsignedRegistration(nint processHandle)
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
            return false;
        }

        var end = Array.IndexOf(buffer, '\0');
        var fullName = new string(buffer, 0, end >= 0 ? end : buffer.Length);

        try
        {
            return GetStagedPackageOrigin(fullName, out var origin) == ErrorSuccess &&
                   origin is PackageOriginUnsigned or PackageOriginDeveloperUnsigned;
        }
        catch (Exception ex) when (ex is EntryPointNotFoundException or DllNotFoundException)
        {
            // This runs on the engine's socket pump, where an exception stops routing for the whole
            // machine. A Windows without the call cannot say how a package was registered; its family
            // is used as it was before the check existed.
            return false;
        }
    }
}
