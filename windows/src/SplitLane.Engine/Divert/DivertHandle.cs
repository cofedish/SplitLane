using System.ComponentModel;
using System.Runtime.InteropServices;
using SplitLane.Engine.Interop;

namespace SplitLane.Engine.Divert;

/// <summary>Why the divert layer could not start, in terms a user can act on.</summary>
public enum DivertFailureKind
{
    /// <summary><c>WinDivert.dll</c> is not next to the engine.</summary>
    LibraryMissing,

    /// <summary>The driver could not be installed or started — almost always a rights problem.</summary>
    DriverUnavailable,

    /// <summary>The process is not elevated.</summary>
    AccessDenied,

    /// <summary>The filter string was rejected by the driver. A bug, not a user problem.</summary>
    InvalidFilter,

    /// <summary>Anything else.</summary>
    Unknown,
}

/// <summary>A divert layer failure, with a message written for the person reading it in the app.</summary>
public sealed class DivertException(DivertFailureKind kind, string message, Exception? inner = null)
    : Exception(message, inner)
{
    /// <summary>What went wrong.</summary>
    public DivertFailureKind Kind { get; } = kind;

    /// <summary>What the user should do about it.</summary>
    public string Remedy => Kind switch
    {
        DivertFailureKind.LibraryMissing =>
            "Run tools\\fetch-windivert.ps1 to download the WinDivert driver next to SplitLane.Engine.exe.",
        DivertFailureKind.DriverUnavailable =>
            "The WinDivert driver could not start. Check that Secure Boot allows it and that no other " +
            "network filter is holding it open.",
        DivertFailureKind.AccessDenied =>
            "Start SplitLane.Engine elevated. Diverting packets requires administrator rights.",
        DivertFailureKind.InvalidFilter =>
            "This is a SplitLane bug — the divert filter was rejected. Please report it.",
        _ => "Check the engine log for detail.",
    };
}

/// <summary>
/// A single open WinDivert handle.
/// </summary>
/// <remarks>
/// Wraps the raw pointer so that closing it is not something a caller can forget, and so that the
/// Win32 error codes that come back from <c>WinDivertOpen</c> are translated once, into a vocabulary
/// the UI can present, rather than at each of the three call sites.
/// </remarks>
public sealed class DivertHandle : IDisposable
{
    private const int ErrorFileNotFound = 2;
    private const int ErrorAccessDenied = 5;
    private const int ErrorInvalidParameter = 87;
    private const int ErrorInvalidImageHash = 577;
    private const int ErrorDriverBlocked = 1275;
    private const int ErrorServiceDoesNotExist = 1060;

    private nint _handle;

    private DivertHandle(nint handle) => _handle = handle;

    /// <summary>True while the handle is usable.</summary>
    public bool IsOpen => _handle != nint.Zero && _handle != -1;

    /// <summary>
    /// Opens a handle, translating every documented failure into an actionable message.
    /// </summary>
    public static DivertHandle Open(string filter, WinDivertLayer layer, short priority, WinDivertFlags flags)
    {
        nint handle;
        try
        {
            handle = WinDivertNative.Open(filter, layer, priority, flags);
        }
        catch (DllNotFoundException ex)
        {
            throw new DivertException(
                DivertFailureKind.LibraryMissing,
                "WinDivert.dll was not found next to SplitLane.Engine.exe.",
                ex);
        }
        catch (EntryPointNotFoundException ex)
        {
            throw new DivertException(
                DivertFailureKind.LibraryMissing,
                "WinDivert.dll is present but is not a supported version (2.2 or later is required).",
                ex);
        }
        catch (BadImageFormatException ex)
        {
            throw new DivertException(
                DivertFailureKind.LibraryMissing,
                "WinDivert.dll is the wrong architecture. SplitLane requires the 64-bit build.",
                ex);
        }

        if (handle == -1 || handle == nint.Zero)
        {
            var error = Marshal.GetLastWin32Error();
            throw Translate(error, layer, filter);
        }

        return new DivertHandle(handle);
    }

    private static DivertException Translate(int error, WinDivertLayer layer, string filter) => error switch
    {
        ErrorFileNotFound or ErrorServiceDoesNotExist => new DivertException(
            DivertFailureKind.LibraryMissing,
            "The WinDivert driver file (WinDivert64.sys) is missing next to WinDivert.dll."),

        ErrorAccessDenied => new DivertException(
            DivertFailureKind.AccessDenied,
            "Access denied opening the divert handle. The engine must run elevated."),

        ErrorInvalidParameter => new DivertException(
            DivertFailureKind.InvalidFilter,
            $"The driver rejected the {layer} filter: {filter}"),

        ErrorInvalidImageHash => new DivertException(
            DivertFailureKind.DriverUnavailable,
            "Windows refused to load WinDivert64.sys because its signature was rejected."),

        ErrorDriverBlocked => new DivertException(
            DivertFailureKind.DriverUnavailable,
            "Windows blocked the WinDivert driver. A vulnerable-driver blocklist or Secure Boot policy is preventing it from loading."),

        _ => new DivertException(
            DivertFailureKind.Unknown,
            $"WinDivertOpen failed with Win32 error {error} ({new Win32Exception(error).Message}).",
            new Win32Exception(error)),
    };

    /// <summary>Sets a queue parameter.</summary>
    public void SetParam(WinDivertParam param, ulong value)
    {
        if (IsOpen && !WinDivertNative.SetParam(_handle, param, value))
        {
            throw new DivertException(
                DivertFailureKind.Unknown,
                $"Could not set {param}: Win32 error {Marshal.GetLastWin32Error()}.");
        }
    }

    /// <summary>Reads a queue parameter, or returns null when it cannot be read.</summary>
    public unsafe ulong? GetParam(WinDivertParam param)
    {
        if (!IsOpen)
        {
            return null;
        }

        ulong value;
        return WinDivertNative.GetParam(_handle, param, &value) ? value : null;
    }

    /// <summary>
    /// Receives one packet or event. Returns false when the handle has been shut down.
    /// </summary>
    public unsafe bool Receive(Span<byte> buffer, out int length, out WinDivertAddress address)
    {
        length = 0;
        address = default;

        if (!IsOpen)
        {
            return false;
        }

        uint received = 0;
        WinDivertAddress local = default;

        bool ok;
        fixed (byte* packet = buffer)
        {
            ok = WinDivertNative.Recv(_handle, packet, (uint)buffer.Length, &received, &local);
        }

        if (!ok)
        {
            return false;
        }

        length = (int)received;
        address = local;
        return true;
    }

    /// <summary>Reinjects a packet. Returns false when the handle has been shut down.</summary>
    public unsafe bool Send(ReadOnlySpan<byte> buffer, ref WinDivertAddress address)
    {
        if (!IsOpen)
        {
            return false;
        }

        uint sent = 0;

        fixed (byte* packet = buffer)
        fixed (WinDivertAddress* addr = &address)
        {
            return WinDivertNative.Send(_handle, packet, (uint)buffer.Length, &sent, addr);
        }
    }

    /// <summary>
    /// Unblocks a thread parked in <see cref="Receive"/> so the loop can exit.
    /// </summary>
    /// <remarks>
    /// Closing the handle from another thread while a receive is in flight is not defined; shutting
    /// it down first is. <c>how = 2</c> is <c>WINDIVERT_SHUTDOWN_BOTH</c>.
    /// </remarks>
    public void Shutdown()
    {
        if (IsOpen)
        {
            WinDivertNative.Shutdown(_handle, 2);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        var handle = Interlocked.Exchange(ref _handle, nint.Zero);
        if (handle != nint.Zero && handle != -1)
        {
            WinDivertNative.Close(handle);
        }
    }

    /// <summary>
    /// Whether the WinDivert library can be loaded at all, without opening a handle.
    /// </summary>
    /// <remarks>
    /// Used to give a precise message before attempting to start, so a machine with no driver
    /// installed says so instead of reporting a generic open failure.
    /// </remarks>
    public static bool IsLibraryAvailable()
    {
        try
        {
            return NativeLibrary.TryLoad("WinDivert.dll", out var library) && Free(library);
        }
        catch (DllNotFoundException)
        {
            return false;
        }
        catch (BadImageFormatException)
        {
            return false;
        }

        static bool Free(nint library)
        {
            NativeLibrary.Free(library);
            return true;
        }
    }
}
