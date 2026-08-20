using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SplitLane.App.Infrastructure;

/// <summary>
/// Keeps one SplitLane window per session, and brings it forward when asked for another.
/// </summary>
/// <remarks>
/// <para>
/// Without this, opening SplitLane while it is already open produced a second window stacked a
/// little below and to the right of the first - which reads, to anyone looking at it, as the title
/// bar having grown a duplicate set of minimise, maximise and close buttons. That is how it was
/// reported, and it was a fair description of what was on screen.
/// </para>
/// <para>
/// There is a second reason beyond tidiness. Both windows would hold their own view of the engine's
/// configuration and each would save over the other's edits, with the last one to press Save
/// winning silently.
/// </para>
/// <para>
/// The mutex is session-local (<c>Local\</c>). Two people signed in at once are two users, each
/// entitled to their own window; a global name would let one of them silently prevent the other from
/// opening the application at all.
/// </para>
/// </remarks>
internal static class SingleInstance
{
    private const string MutexName = @"Local\SplitLane.App.SingleInstance";

    private static Mutex? _held;

    /// <summary>
    /// Claims the single-instance slot.
    /// </summary>
    /// <returns>True when this process owns it; false when another already does.</returns>
    public static bool TryClaim()
    {
        _held = new Mutex(initiallyOwned: true, MutexName, out var createdNew);

        if (createdNew)
        {
            return true;
        }

        _held.Dispose();
        _held = null;
        return false;
    }

    /// <summary>Brings the window of the process that already holds the slot to the front.</summary>
    /// <remarks>
    /// Best effort by design. Failing to raise the other window is a poor greeting, but starting a
    /// second copy because the first could not be found would be worse - and the caller exits either
    /// way, so a person who sees nothing happen will click again and find the window they wanted.
    /// </remarks>
    public static void ActivateExisting()
    {
        try
        {
            var current = Environment.ProcessId;

            foreach (var process in Process.GetProcessesByName("SplitLane"))
            {
                using (process)
                {
                    if (process.Id == current || process.MainWindowHandle == nint.Zero)
                    {
                        continue;
                    }

                    // Restore first: a minimised window accepts foreground and stays minimised,
                    // which looks exactly like the click having done nothing.
                    if (IsIconic(process.MainWindowHandle))
                    {
                        ShowWindow(process.MainWindowHandle, ShowRestore);
                    }

                    SetForegroundWindow(process.MainWindowHandle);
                    return;
                }
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or SystemException)
        {
        }
    }

    /// <summary>Releases the slot. Called as the application shuts down.</summary>
    public static void Release()
    {
        if (_held is null)
        {
            return;
        }

        try
        {
            _held.ReleaseMutex();
        }
        catch (ApplicationException)
        {
            // Not owned any more. Nothing to do, and nothing worth saying about it.
        }

        _held.Dispose();
        _held = null;
    }

    private const int ShowRestore = 9;

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(nint window);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindow(nint window, int command);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsIconic(nint window);
}
