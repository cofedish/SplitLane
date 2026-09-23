using SplitLane.Core.Logging;
using SplitLane.Engine.Divert;
using SplitLane.Engine.Ipc;

namespace SplitLane.Engine.Runtime;

/// <summary>
/// Everything the engine is, independent of how it was started.
/// </summary>
/// <remarks>
/// <para>
/// The engine runs two ways: as a Windows service, which is how it is installed, and as a console
/// process, which is how it is developed and diagnosed. Those differ only in who signals the stop -
/// the service control manager or Ctrl+C - so the body lives here and each entry point supplies its
/// own waiting.
/// </para>
/// <para>
/// Startup is split deliberately. <see cref="Start"/> opens the control channel and nothing else: it
/// is fast, and it either works or the engine is useless, so it may throw. <see cref="StartRoutingAsync"/>
/// opens the divert layer, which can legitimately fail on a machine where the driver has not been
/// fetched yet, and a failure there must leave the control channel up so the application can say
/// what is wrong instead of showing "not running" with no reason.
/// </para>
/// </remarks>
internal sealed class EngineHost : IAsyncDisposable
{
    private const string LogCategory = "engine";

    private ConfigurationStore? _store;
    private EngineRuntime? _runtime;
    private ControlServer? _control;

    /// <summary>Loads configuration and opens the control channel. Fast, and fatal if it fails.</summary>
    public void Start(EngineOptions options)
    {
        _store = new ConfigurationStore();
        _runtime = new EngineRuntime(_store, options);
        _runtime.LoadConfiguration();

        // After the first load, so a policy already in place applies from the first decision; the
        // watcher is what makes a rule an administrator removes stop applying without a restart.
        _runtime.StartPolicyWatch();

        _control = new ControlServer(_runtime, _store);
        _control.Start();
    }

    /// <summary>Opens the divert layer. Logs and returns on failure rather than bringing the engine down.</summary>
    public async Task StartRoutingAsync()
    {
        if (_runtime is null)
        {
            throw new InvalidOperationException("Start must be called first.");
        }

        try
        {
            await _runtime.StartAsync().ConfigureAwait(false);
        }
        catch (DivertException ex)
        {
            // Not fatal, and not silent. The commonest cause by far is a machine where
            // fetch-windivert.ps1 has not been run yet, which the user fixes and then presses Start
            // routing - the same request re-attempts this without restarting anything.
            SplitLaneLog.Error(LogCategory, $"{ex.Message} {ex.Remedy}");
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_control is not null)
        {
            await _control.DisposeAsync().ConfigureAwait(false);
        }

        if (_runtime is not null)
        {
            await _runtime.DisposeAsync().ConfigureAwait(false);
        }
    }
}
