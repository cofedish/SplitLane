using System.Security.Principal;
using SplitLane.Core.Logging;
using SplitLane.Engine.Divert;
using SplitLane.Engine.Ipc;
using SplitLane.Engine.Runtime;

namespace SplitLane.Engine;

/// <summary>Entry point of the elevated engine.</summary>
internal static class Program
{
    private const string LogCategory = "engine";

    private static async Task<int> Main(string[] args)
    {
        var options = ParseOptions(args);

        SplitLanePaths.EnsureCreated();
        SplitLaneLog.MinimumLevel = options.Verbose ? LogLevel.Debug : LogLevel.Info;
        SplitLaneLog.AddSink(new RollingFileLogSink(SplitLanePaths.EngineLog));

        // Console output is opt-out, because it can hang the whole engine. In a console window with
        // QuickEdit enabled - the Windows default - a stray click puts the window into selection
        // mode and blocks Console.WriteLine indefinitely, taking every thread that logs with it.
        // That was observed: the engine printed one line, never opened its control channel, and sat
        // there looking alive. A routing engine meant to run unattended must not be stoppable by a
        // mouse click in a window nobody is looking at.
        if (!args.Contains("--no-console-log", StringComparer.OrdinalIgnoreCase))
        {
            SplitLaneLog.AddSink(new ConsoleLogSink());
        }

        if (args.Contains("--check", StringComparer.OrdinalIgnoreCase))
        {
            return RunPreflight();
        }

        if (options.EnableDivert && !IsElevated())
        {
            SplitLaneLog.Error(
                LogCategory,
                "SplitLane.Engine must run elevated to divert packets. " +
                "Start it from an administrator prompt, or pass --no-divert to run the control " +
                "channel and relay only.");
            return 2;
        }

        var store = new ConfigurationStore();
        await using var runtime = new EngineRuntime(store, options);
        runtime.LoadConfiguration();

        await using var control = new ControlServer(runtime, store);
        control.Start();

        try
        {
            await runtime.StartAsync().ConfigureAwait(false);
        }
        catch (DivertException ex)
        {
            // Not fatal. The control channel stays up so the app can show what went wrong and let
            // the user fix it, which is far better than an engine that exits and leaves the UI
            // saying "not running" with no reason.
            SplitLaneLog.Error(LogCategory, $"{ex.Message} {ex.Remedy}");
        }

        SplitLaneLog.Info(LogCategory, "engine ready — press Ctrl+C to stop");

        var stopping = new TaskCompletionSource();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            stopping.TrySetResult();
        };
        AppDomain.CurrentDomain.ProcessExit += (_, _) => stopping.TrySetResult();

        await stopping.Task.ConfigureAwait(false);

        SplitLaneLog.Info(LogCategory, "stopping");
        return 0;
    }

    private static EngineOptions ParseOptions(string[] args) => new(
        EnableDivert: !args.Contains("--no-divert", StringComparer.OrdinalIgnoreCase),
        Verbose: args.Contains("--verbose", StringComparer.OrdinalIgnoreCase));

    /// <summary>
    /// Reports whether this machine can actually run the divert layer, without starting it.
    /// </summary>
    /// <remarks>
    /// Worth having as a separate mode: "it does not work" has three quite different causes on
    /// Windows — no driver on disk, no elevation, driver blocked by policy — and they need three
    /// different fixes.
    /// </remarks>
    private static int RunPreflight()
    {
        var elevated = IsElevated();
        var library = DivertHandle.IsLibraryAvailable();

        Console.WriteLine($"Elevated:          {(elevated ? "yes" : "no")}");
        Console.WriteLine($"WinDivert.dll:     {(library ? "found" : "not found")}");
        Console.WriteLine($"Configuration:     {SplitLanePaths.ConfigurationFile}");
        Console.WriteLine($"Log:               {SplitLanePaths.EngineLog}");

        if (!library)
        {
            Console.WriteLine();
            Console.WriteLine("Run tools\\fetch-windivert.ps1 to download the driver next to the engine.");
            return 3;
        }

        if (!elevated)
        {
            Console.WriteLine();
            Console.WriteLine("Start the engine from an administrator prompt.");
            return 2;
        }

        try
        {
            using var handle = DivertHandle.Open(
                "false", Interop.WinDivertLayer.Network, 0, Interop.WinDivertFlags.Sniff | Interop.WinDivertFlags.RecvOnly);

            var major = handle.GetParam(Interop.WinDivertParam.VersionMajor);
            var minor = handle.GetParam(Interop.WinDivertParam.VersionMinor);
            Console.WriteLine($"Driver:            {major}.{minor} — ready");
            return 0;
        }
        catch (DivertException ex)
        {
            Console.WriteLine($"Driver:            unavailable — {ex.Message}");
            Console.WriteLine();
            Console.WriteLine(ex.Remedy);
            return 4;
        }
    }

    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}

/// <summary>Mirrors log records to the console when the engine runs in a window.</summary>
internal sealed class ConsoleLogSink : ILogSink
{
    /// <inheritdoc />
    public void Write(LogLevel level, string category, string message)
    {
        var previous = Console.ForegroundColor;

        Console.ForegroundColor = level switch
        {
            LogLevel.Error => ConsoleColor.Red,
            LogLevel.Warning => ConsoleColor.Yellow,
            LogLevel.Debug => ConsoleColor.DarkGray,
            _ => previous,
        };

        Console.WriteLine($"{DateTime.Now:HH:mm:ss} [{category}] {message}");
        Console.ForegroundColor = previous;
    }
}
