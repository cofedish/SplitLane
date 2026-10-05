using System.IO.Pipes;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace SplitLane.Engine.Interop;

/// <summary>Which Windows session a process, or the client of a pipe, belongs to.</summary>
internal static partial class ProcessSessions
{
    /// <summary>The session of a process, or null when it cannot be read (it may have exited).</summary>
    public static uint? Of(uint processId) => ProcessIdToSessionId(processId, out var session) ? session : null;

    /// <summary>The session of the process on the other end of a server pipe, or null.</summary>
    public static uint? OfClient(NamedPipeServerStream pipe)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        // The safe handle, not its raw value: it is held for the call, so a pipe closed meanwhile
        // cannot have its handle value reused under the call.
        return GetNamedPipeClientSessionId(pipe.SafePipeHandle, out var session) ? session : null;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ProcessIdToSessionId(uint processId, out uint sessionId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientSessionId(SafePipeHandle pipe, out uint sessionId);
}
