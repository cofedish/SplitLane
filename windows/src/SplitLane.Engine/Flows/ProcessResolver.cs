using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using SplitLane.Core.Rules;

namespace SplitLane.Engine.Flows;

/// <summary>What is known about a process, cached.</summary>
/// <param name="ExecutablePath">Normalised image path, or empty when it could not be read.</param>
/// <param name="StartTime">
/// Process creation time. The half of the cache key that makes pid reuse safe: Windows recycles pids
/// within seconds, and a cache keyed on the pid alone would eventually attribute one program's
/// connection to another program's rule.
/// </param>
/// <param name="PackageFamilyName">
/// Package family from the process token, or null for an unpackaged process. Read with the same handle
/// as the path, and authoritative in a way the path is not: Windows sets it when it activates the
/// package, wherever the package is installed.
/// </param>
/// <param name="Image">The image's record in the catalog, or null when no catalog is attached.</param>
public readonly record struct ProcessInfo(
    string ExecutablePath,
    long StartTime,
    string? PackageFamilyName = null,
    ImageRecord? Image = null)
{
    /// <summary>True when the image path could not be determined.</summary>
    public bool IsUnknown => string.IsNullOrEmpty(ExecutablePath);
}

/// <summary>
/// Turns a process id into the routing key.
/// </summary>
/// <remarks>
/// <para>
/// This runs on the hot path — once per outbound connection on the machine — so the result is
/// cached, and the cache is bounded. An unbounded dictionary keyed on a 32-bit pid on a machine that
/// churns short-lived processes is a slow memory leak in an elevated service.
/// </para>
/// <para>
/// The path is read with <c>QueryFullProcessImageName</c> against a handle opened with only
/// <c>PROCESS_QUERY_LIMITED_INFORMATION</c>. That is the least privilege that answers the question,
/// it works for processes running as other users, and unlike reading the PEB it cannot be spoofed by
/// the target process. A protected process still refuses to open, which is reported as "unknown" and
/// routes DIRECT — the safe direction.
/// </para>
/// </remarks>
public sealed class ProcessResolver
{
    private readonly ConcurrentDictionary<uint, ProcessInfo> _cache = new();
    private readonly int _maxEntries;
    private readonly ImageCatalog? _images;

    /// <summary>Builds a resolver with a bounded cache.</summary>
    /// <param name="maxEntries">Cache bound.</param>
    /// <param name="images">
    /// Where a new process's image is looked up, so every connection it makes afterwards reaches its
    /// evidence without touching the disk. Null resolves paths only.
    /// </param>
    public ProcessResolver(int maxEntries = 4096, ImageCatalog? images = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxEntries, 1);
        _maxEntries = maxEntries;
        _images = images;
    }

    /// <summary>Cached entry count. Diagnostic.</summary>
    public int CacheSize => _cache.Count;

    /// <summary>Number of resolutions that did not hit the cache. Diagnostic.</summary>
    public long Misses { get; private set; }

    /// <summary>Resolves a pid to its image path, caching the answer.</summary>
    public string Resolve(uint processId) => ResolveInfo(processId).ExecutablePath;

    /// <summary>Resolves a pid to everything known about it, caching the answer.</summary>
    public ProcessInfo ResolveInfo(uint processId)
    {
        if (processId == 0)
        {
            return default;
        }

        var (rawPath, startTime, packageFamily, cached) = Query(processId);

        if (cached is { } hit)
        {
            return hit;
        }

        Misses++;

        // The long form, once per process: an image started through an 8.3 name reports that name,
        // and a file name like CODEX~1.EXE claims no rule.
        var path = ExecutablePath.Normalize(SplitLane.Platform.ImageFile.LongPath(rawPath));

        // A new process is the moment to look at its image's stamp: a record made for a file that has
        // since been replaced must not vouch for the replacement.
        var image = path.Length > 0 ? _images?.Refresh(path) : null;
        var info = new ProcessInfo(path, startTime, packageFamily, image);

        if (_cache.Count >= _maxEntries)
        {
            // A plain clear rather than an LRU eviction. The cache exists to absorb bursts of
            // connections from the same handful of processes, and rebuilding it costs one syscall
            // per live process; carrying an LRU's bookkeeping on the hot path to avoid that would be
            // the more expensive choice.
            _cache.Clear();
        }

        _cache[processId] = info;
        return info;
    }

    /// <summary>Drops the cache. Used when routing stops.</summary>
    public void Clear() => _cache.Clear();

    /// <summary>Reads the full image path of a process, or an empty string when it cannot be read.</summary>
    public static string QueryImagePath(uint processId)
    {
        var handle = NativeMethods.OpenProcess(
            NativeMethods.ProcessQueryLimitedInformation, false, processId);

        if (handle == nint.Zero)
        {
            return string.Empty;
        }

        try
        {
            var capacity = 1024;
            var buffer = new StringBuilder(capacity);

            if (NativeMethods.QueryFullProcessImageName(handle, 0, buffer, ref capacity))
            {
                return buffer.ToString(0, capacity);
            }

            // ERROR_INSUFFICIENT_BUFFER on a long path; retry once at the maximum.
            if (Marshal.GetLastWin32Error() == NativeMethods.ErrorInsufficientBuffer)
            {
                capacity = 32768;
                buffer = new StringBuilder(capacity);
                if (NativeMethods.QueryFullProcessImageName(handle, 0, buffer, ref capacity))
                {
                    return buffer.ToString(0, capacity);
                }
            }

            return string.Empty;
        }
        finally
        {
            NativeMethods.CloseHandle(handle);
        }
    }

    /// <summary>
    /// Reads a process's image path and creation time from a single handle, and on a cache miss its
    /// package family from the same handle.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One <c>OpenProcess</c> and two cheap queries, plus a third for a process not seen before. The
    /// cache is consulted between them so that the package family - a token read - is paid once per
    /// process rather than once per connection. The previous version called
    /// <c>Process.GetProcessById</c> for the start time, which opens the process a second time and
    /// builds a managed wrapper around it - milliseconds, on a path that runs once per outbound
    /// connection on the machine.
    /// </para>
    /// <para>
    /// That cost was not merely wasteful, it was a correctness bug. Windows delivers the
    /// socket-layer event before the SYN goes out, but the two are processed on different threads;
    /// while this call was slow the packet loop overtook the socket pump, the SYN left
    /// un-redirected, and the connection established with the real server before SplitLane had
    /// recorded anything about it.
    /// </para>
    /// </remarks>
    private (string Path, long StartTime, string? PackageFamily, ProcessInfo? Cached) Query(uint processId)
    {
        var handle = NativeMethods.OpenProcess(
            NativeMethods.ProcessQueryLimitedInformation, false, processId);

        if (handle == nint.Zero)
        {
            // A protected process, or one that has already exited. Unknown identity routes DIRECT.
            return (string.Empty, 0, null, null);
        }

        try
        {
            var path = string.Empty;
            var capacity = 1024;
            var buffer = new StringBuilder(capacity);

            if (NativeMethods.QueryFullProcessImageName(handle, 0, buffer, ref capacity))
            {
                path = buffer.ToString(0, capacity);
            }
            else if (Marshal.GetLastWin32Error() == NativeMethods.ErrorInsufficientBuffer)
            {
                capacity = 32768;
                buffer = new StringBuilder(capacity);
                if (NativeMethods.QueryFullProcessImageName(handle, 0, buffer, ref capacity))
                {
                    path = buffer.ToString(0, capacity);
                }
            }

            long startTime = 0;
            if (NativeMethods.GetProcessTimes(handle, out var created, out _, out _, out _))
            {
                startTime = ((long)created.High << 32) | (uint)created.Low;
            }

            if (_cache.TryGetValue(processId, out var cached) && cached.StartTime == startTime)
            {
                return (path, startTime, cached.PackageFamilyName, cached);
            }

            return (path, startTime, SplitLane.Platform.ProcessPackage.FamilyName(handle), null);
        }
        finally
        {
            NativeMethods.CloseHandle(handle);
        }
    }
}

/// <summary>The handful of Win32 entry points the engine needs outside WinDivert.</summary>
internal static partial class NativeMethods
{
    internal const uint ProcessQueryLimitedInformation = 0x1000;
    internal const int ErrorInsufficientBuffer = 122;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial nint OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint processId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseHandle(nint handle);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "QueryFullProcessImageNameW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryFullProcessImageName(
        nint process, uint flags, StringBuilder exeName, ref int size);

    [StructLayout(LayoutKind.Sequential)]
    internal struct FileTime
    {
        public uint Low;
        public int High;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetProcessTimes(
        nint process, out FileTime creation, out FileTime exit, out FileTime kernel, out FileTime user);
}
