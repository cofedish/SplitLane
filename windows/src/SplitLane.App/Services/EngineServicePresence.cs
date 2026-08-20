using System.ComponentModel;
using System.ServiceProcess;

namespace SplitLane.App.Services;

/// <summary>How the engine is installed on this machine, if it is.</summary>
public enum EngineServiceState
{
    /// <summary>No such service. The engine was unpacked rather than installed, or removed.</summary>
    NotInstalled,

    /// <summary>Registered, but not currently running.</summary>
    Stopped,

    /// <summary>Registered and running.</summary>
    Running,

    /// <summary>The service exists but its state could not be read.</summary>
    Unknown,
}

/// <summary>
/// Reads the state of the engine service, so that "not running" can say something useful.
/// </summary>
/// <remarks>
/// <para>
/// Without this the application can only report that its control channel is not answering, and the
/// advice attached to that has to be a guess covering every machine at once. The two cases want
/// opposite things said: on an installed machine the service should be running and something is
/// wrong; on an unpacked copy there is no service at all and never was.
/// </para>
/// <para>
/// Reading a service's status needs no elevation. Starting one does, which is why nothing here
/// offers to - a button that raises a consent prompt and then fails for a reason the application
/// cannot see is worse than a sentence that says where to look.
/// </para>
/// </remarks>
public static class EngineServicePresence
{
    /// <summary>The service name the installer registers. Must match the installer and the engine.</summary>
    public const string ServiceName = "SplitLane";

    /// <summary>Looks up the current state. Never throws.</summary>
    public static EngineServiceState Read()
    {
        try
        {
            using var service = new ServiceController(ServiceName);

            return service.Status switch
            {
                ServiceControllerStatus.Running => EngineServiceState.Running,
                ServiceControllerStatus.StartPending => EngineServiceState.Running,
                ServiceControllerStatus.Stopped => EngineServiceState.Stopped,
                ServiceControllerStatus.StopPending => EngineServiceState.Stopped,
                ServiceControllerStatus.Paused => EngineServiceState.Stopped,
                _ => EngineServiceState.Unknown,
            };
        }
        catch (InvalidOperationException)
        {
            // What ServiceController throws when the service does not exist. It wraps a Win32
            // error rather than having a "does it exist" question of its own.
            return EngineServiceState.NotInstalled;
        }
        catch (Win32Exception)
        {
            return EngineServiceState.Unknown;
        }
    }

    /// <summary>What to tell someone whose engine is not answering, given how it is installed.</summary>
    public static string Remedy(EngineServiceState state) => state switch
    {
        EngineServiceState.Stopped =>
            "The SplitLane service is installed but stopped. Start it from Services, " +
            "or restart the machine — it is set to start on its own.",

        EngineServiceState.Running =>
            "The SplitLane service is running but not answering. Its log is in " +
            @"C:\ProgramData\SplitLane\logs.",

        EngineServiceState.NotInstalled =>
            "No SplitLane service is installed on this machine. Install the MSI, which registers " +
            "one that starts with Windows, or run SplitLane.Engine.exe from an elevated prompt.",

        _ => "The state of the SplitLane service could not be read.",
    };
}
