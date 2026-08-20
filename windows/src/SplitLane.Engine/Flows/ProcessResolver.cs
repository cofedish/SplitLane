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
public readonly record struct ProcessInfo(string ExecutablePath, long StartTime)
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

    /// <summary>Builds a resolver with a bounded cache.</summary>
    public ProcessResolver(int maxEntries = 4096)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxEntries, 1);
        _maxEntries = maxEntries;
    }

    /// <summary>Cached entry count. Diagnostic.</summary>
    public int CacheSize => _cache.Count;

    /// <summary>Number of resolutions that did not hit the cache. Diagnostic.</summary>
    public long Misses { get; private set; }

    /// <summary>Resolves a pid to its image path, caching the answer.</summary>
    public string Resolve(uint processId)
    {
        if (processId == 0)
        {
            return string.Empty;
        }

        var startTime = TryGetStartTime(processId);

        if (_cache.TryGetValue(processId, out var cached) && cached.StartTime == startTime)
        {
            return cached.ExecutablePath;
        }

        Misses++;

        var path = ExecutablePath.Normalize(QueryImagePath(processId));
        var info = new ProcessInfo(path, startTime);

        if (_cache.Count >= _maxEntries)
        {
            // A plain clear rather than an LRU eviction. The cache exists to absorb bursts of
            // connections from the same handful of processes, and rebuilding it costs one syscall
            // per live process; carrying an LRU's bookkeeping on the hot path to avoid that would be
            // the more expensive choice.
            _cache.Clear();
        }

        _cache[processId] = info;
        return path;
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

    /// <summary>Reads a process's creation time as a tick count, or 0 when unavailable.</summary>
    private static long TryGetStartTime(uint processId)
    {
        try
        {
            using var process = Process.GetProcessById((int)processId);
            return process.StartTime.Ticks;
        }
        catch (ArgumentException)
        {
            // The process is already gone. Its connection is going nowhere, and the empty identity
            // this produces routes DIRECT.
            return 0;
        }
        catch (InvalidOperationException)
        {
            return 0;
        }
        catch (Win32Exception)
        {
            // A protected process. Unknown identity, DIRECT.
            return 0;
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
}
