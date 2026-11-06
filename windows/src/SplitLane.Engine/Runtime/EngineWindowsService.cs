using System.ServiceProcess;
using SplitLane.Core.Logging;

namespace SplitLane.Engine.Runtime;

/// <summary>
/// The engine as the service control manager sees it.
/// </summary>
/// <remarks>
/// <para>
/// This exists so that starting SplitLane is one action. Before it, routing meant launching the
/// engine from an elevated prompt and then opening the application separately - two executables for
/// one product, with the privilege split, which is a sound design, pushed onto the person using it.
/// </para>
/// <para>
/// Running as <c>LocalSystem</c> is what makes the application able to stay unelevated. The control
/// channel was already built for this: its ACL grants LocalSystem full control and the interactive
/// user read and write, so a service-hosted engine and a normal user's window can talk without
/// either side gaining anything from the other.
/// </para>
/// </remarks>
internal sealed class EngineWindowsService : ServiceBase
{
    private const string LogCategory = "service";

    /// <summary>The name the service is registered under. The installer must agree with this.</summary>
    internal const string ServiceKey = "SplitLane";

    private readonly EngineOptions _options;
    private EngineHost? _host;

    public EngineWindowsService(EngineOptions options)
    {
        _options = options;
        ServiceName = ServiceKey;
        CanStop = true;
        CanShutdown = true;
        CanHandlePowerEvent = true;
        // Lock/unlock and UI disconnects do not control this LocalSystem service.
        CanHandleSessionChangeEvent = false;

        // The engine keeps its own log, with reasons and remedies in it. Letting ServiceBase also
        // write to the Application event log would duplicate every start and stop into a place
        // nobody would think to correlate with the real one.
        AutoLog = false;
    }

    /// <inheritdoc />
    protected override void OnStart(string[] args)
    {
        SplitLaneLog.Info(LogCategory, "service starting");

        _host = new EngineHost();

        // Synchronous, because if the control channel cannot open there is no engine and the
        // service manager should hear about it now rather than report a healthy service that
        // nothing can talk to.
        _host.Start(_options);

        // The divert layer is opened in the background. The service control manager expects OnStart
        // to return promptly, and opening a kernel driver is not something to promise it will be
        // quick - a slow open would be reported to the user as a service that failed to start,
        // which is a worse description of the machine than the truth.
        _ = Task.Run(async () =>
        {
            try
            {
                await _host.StartRoutingAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                SplitLaneLog.Error(LogCategory, $"routing could not be started: {ex.Message}");
            }
        });

        SplitLaneLog.Info(LogCategory, "service started");
    }

    /// <inheritdoc />
    protected override void OnStop()
    {
        SplitLaneLog.Info(LogCategory, "service stopping");
        ShutDownHost();
    }

    /// <inheritdoc />
    protected override void OnShutdown()
    {
        // Windows is going down. Same work as a stop, and worth doing rather than being killed
        // mid-flow: the divert handles are closed in order and the log says why the engine went
        // away, instead of leaving a reader to guess between a crash and a shutdown.
        SplitLaneLog.Info(LogCategory, "machine shutting down");
        ShutDownHost();
    }

    /// <inheritdoc />
    protected override bool OnPowerEvent(PowerBroadcastStatus powerStatus) =>
        DispatchPowerEvent(powerStatus, () => _host?.ReportSystemResume());

    internal static bool DispatchPowerEvent(PowerBroadcastStatus powerStatus, Action resumed)
    {
        // Windows sends ResumeAutomatic on every wake. ResumeSuspend may follow it for an
        // interactive wake; acting on both would tear down the freshly recovered generation twice.
        if (powerStatus == PowerBroadcastStatus.ResumeAutomatic)
        {
            SplitLaneLog.Info(LogCategory, "machine resumed; scheduling routing recovery");
            resumed();
        }
        // Keep capture open during suspend preparation and do not veto the machine's power policy.
        return true;
    }

    private void ShutDownHost()
    {
        if (_host is null)
        {
            return;
        }

        try
        {
            _host.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            SplitLaneLog.Error(LogCategory, $"shutdown was not clean: {ex.Message}");
        }
        finally
        {
            _host = null;
        }
    }

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            ShutDownHost();
        }

        base.Dispose(disposing);
    }
}
