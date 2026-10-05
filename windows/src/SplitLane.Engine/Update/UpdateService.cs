using System.Net.Http;
using System.Reflection;
using SplitLane.Core.Logging;
using SplitLane.Core.Update;
using SplitLane.Engine.Runtime;

namespace SplitLane.Engine.Update;

/// <summary>Where an update has got to.</summary>
public enum UpdateState
{
    /// <summary>Nothing has been checked yet this run.</summary>
    Unknown,

    /// <summary>Checked, and this is the newest release.</summary>
    UpToDate,

    /// <summary>A newer release exists and is waiting to be applied.</summary>
    Available,

    /// <summary>The installer is being fetched.</summary>
    Downloading,

    /// <summary>The installer has been handed to Windows. The service is about to be restarted.</summary>
    Installing,

    /// <summary>The last attempt failed. <see cref="UpdateService.LastError"/> says how.</summary>
    Failed,
}

/// <summary>
/// Finds out whether a newer SplitLane exists, and installs it when asked to.
/// </summary>
/// <remarks>
/// <para>
/// This runs as <c>LocalSystem</c>, which is the whole reason it can update the product without a
/// consent prompt and the whole reason it has to be careful. Anything that can persuade this type to
/// install a file has arranged for code to run as SYSTEM, so it installs nothing it has not proved
/// came from the release key: the manifest is verified before it is parsed, the installer is hashed
/// against what the verified manifest said, and neither the version nor the download location is
/// read from anywhere but that document.
/// </para>
/// <para>
/// Checking is automatic and installing is not. An update restarts the service, which drops every
/// relayed connection - a few seconds of a call, a download, a game. That is a reasonable thing to
/// ask for and a bad thing to spring on someone, so the engine finds updates and the person decides
/// when to take one.
/// </para>
/// </remarks>
public sealed class UpdateService : IDisposable
{
    private const string LogCategory = "update";

    /// <summary>
    /// Where the signed manifest lives.
    /// </summary>
    /// <remarks>
    /// GitHub resolves <c>releases/latest</c> to whatever the newest release is, so there is no API
    /// call, no token, and no version list to keep. This address is a constant in the binary rather
    /// than configuration: a settable update feed is a settable answer to "is this ours".
    /// </remarks>
    private const string ManifestUrl =
        "https://github.com/" + ManifestVerifier.ReleaseRepository + "/releases/latest/download/update.json";

    private const string SignatureUrl = ManifestUrl + ".sig";

    /// <summary>How often the engine looks, when nobody has asked it to.</summary>
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(24);

    /// <summary>A first look shortly after start, once the machine has settled.</summary>
    private static readonly TimeSpan FirstCheckDelay = TimeSpan.FromMinutes(3);

    private readonly HttpClient _http;
    private readonly UpdateStaging _staging;
    private readonly IUpdateInstaller _installer;
    private readonly string _releaseKey;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Timer? _timer;

    /// <summary>Builds the service. Nothing is fetched until <see cref="Start"/>.</summary>
    public UpdateService()
        : this(null, null, null, null)
    {
    }

    /// <summary>
    /// Builds the service over explicit parts. Tests supply a fake transport, their own key, staging in
    /// a temporary protected directory, and an installer that records instead of running msiexec.
    /// </summary>
    internal UpdateService(
        HttpClient? http, UpdateStaging? staging, IUpdateInstaller? installer, string? releaseKey)
    {
        _http = http ?? new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd($"SplitLane/{CurrentVersion}");
        _staging = staging ?? new UpdateStaging();
        _installer = installer ?? new MsiexecInstaller();
        _releaseKey = releaseKey ?? ReleaseKey.PublicKeySpki;
    }

    /// <summary>The version a check compares against. Tests set it; the service uses the build's.</summary>
    internal ProductVersion InstalledVersion { get; init; } = CurrentVersion;

    /// <summary>The version this engine is.</summary>
    public static ProductVersion CurrentVersion { get; } = ReadCurrentVersion();

    /// <summary>Where the last check or install got to.</summary>
    public UpdateState State { get; private set; } = UpdateState.Unknown;

    /// <summary>The release waiting to be installed, when there is one.</summary>
    public UpdateManifest? Available { get; private set; }

    /// <summary>Why the last attempt failed, when it did.</summary>
    public string? LastError { get; private set; }

    /// <summary>When the engine last managed to ask.</summary>
    public DateTimeOffset? LastChecked { get; private set; }

    /// <summary>
    /// Whether the managed policy has turned self-update off. Honoured at every check and every
    /// install, so a policy that changes while the engine runs takes effect at the next one.
    /// </summary>
    public bool DisabledByPolicy { get; set; }

    private const string DisabledMessage =
        "self-update is turned off by your organisation's policy; releases are delivered by your IT department";

    /// <summary>Begins checking periodically.</summary>
    public void Start()
    {
        _timer ??= new Timer(_ => _ = CheckAsync(), null, FirstCheckDelay, CheckInterval);
    }

    /// <summary>
    /// Looks for a newer release.
    /// </summary>
    /// <remarks>
    /// Failure is recorded and not thrown. A machine that is offline, or behind a proxy that refuses
    /// GitHub, is not a broken machine, and an update check is the last thing that should be allowed
    /// to take the routing engine down with it.
    /// </remarks>
    public async Task<UpdateState> CheckAsync(CancellationToken cancellationToken = default)
    {
        if (DisabledByPolicy)
        {
            Available = null;
            LastError = DisabledMessage;
            return State;
        }

        if (!await _gate.WaitAsync(0, cancellationToken).ConfigureAwait(false))
        {
            return State;
        }

        try
        {
            var manifestJson = await FetchAsync(ManifestUrl, cancellationToken).ConfigureAwait(false);
            var signature = await FetchAsync(SignatureUrl, cancellationToken).ConfigureAwait(false);

            var rejection = ManifestVerifier.Verify(
                manifestJson, signature, _releaseKey, out var manifest);

            if (rejection != ManifestRejection.None || manifest is null)
            {
                // Worth saying loudly. A rejected manifest is either a release published wrong or
                // somebody standing in the middle, and the difference is not visible from here.
                return Fail($"the published update was refused: {rejection}");
            }

            LastChecked = DateTimeOffset.UtcNow;

            var offered = ProductVersion.Parse(manifest.Version);

            if (!offered.IsNewerThan(InstalledVersion))
            {
                Available = null;
                LastError = null;
                SplitLaneLog.Debug(LogCategory, $"{InstalledVersion} is current; latest is {offered}");
                return State = UpdateState.UpToDate;
            }

            Available = manifest;
            LastError = null;
            SplitLaneLog.Info(LogCategory, $"{offered} is available; this is {InstalledVersion}");
            return State = UpdateState.Available;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException)
        {
            return Fail(ex.Message);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Downloads the waiting release and hands it to Windows Installer.
    /// </summary>
    /// <remarks>
    /// The installer is started detached and this method returns. It has to be: applying the package
    /// stops this service, so waiting for the installer to finish would mean waiting inside the
    /// process the installer is about to kill.
    /// </remarks>
    public async Task<bool> ApplyAsync(CancellationToken cancellationToken = default)
    {
        if (DisabledByPolicy)
        {
            LastError = DisabledMessage;
            return false;
        }

        var manifest = Available;

        if (manifest is null)
        {
            LastError = "no update is waiting";
            return false;
        }

        if (!await _gate.WaitAsync(0, cancellationToken).ConfigureAwait(false))
        {
            return false;
        }

        try
        {
            State = UpdateState.Downloading;

            // The name is built here from a version that parsed as digits and dots, never taken from
            // the URL. It is cosmetic - the directory it lands in is new, random and SYSTEM-only.
            var fileName = $"SplitLane-{ProductVersion.Parse(manifest.Version)}-x64.msi";

            var staged = await _staging.StageAsync(
                fileName,
                (destination, token) => DownloadAsync(manifest.Url, destination, token),
                manifest.Sha256,
                cancellationToken).ConfigureAwait(false);

            // Checked again on a fresh handle, in place, immediately before it is handed over: the same
            // file, still a regular file with one name, still writable only by SYSTEM/Administrators,
            // still the hash the signed manifest names.
            var verified = _staging.VerifyFinal(staged);

            SplitLaneLog.Info(LogCategory, $"installing {manifest.Version}");
            State = UpdateState.Installing;

            _installer.Install(verified);
            return true;
        }
        catch (StagingRejectedException ex)
        {
            Fail(ex.Message);
            return false;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException
                                       or UnauthorizedAccessException or InvalidOperationException
                                       or System.ComponentModel.Win32Exception)
        {
            Fail(ex.Message);
            return false;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Fetches one document from the feed, saying what happened when it cannot.
    /// </summary>
    /// <remarks>
    /// The status code is kept because the interesting failures are distinguishable by it and by
    /// nothing else. A 404 on the whole feed does not mean "no update"; it means the releases are not
    /// published where an unauthenticated engine can read them - which is what a private repository
    /// looks like from here, and which no amount of retrying will change.
    /// </remarks>
    private async Task<string> FetchAsync(string url, CancellationToken cancellationToken)
    {
        using var response = await _http.GetAsync(url, cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"the update feed answered {(int)response.StatusCode} {response.ReasonPhrase}");
        }

        return await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task DownloadAsync(string url, Stream destination, CancellationToken cancellationToken)
    {
        using var response = await _http
            .GetAsync(new Uri(url), HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);

        response.EnsureSuccessStatusCode();
        await response.Content.CopyToAsync(destination, cancellationToken).ConfigureAwait(false);
    }

    private UpdateState Fail(string message)
    {
        LastError = message;
        SplitLaneLog.Warning(LogCategory, $"update check failed: {message}");
        return State = UpdateState.Failed;
    }

    /// <summary>
    /// The version stamped on this build.
    /// </summary>
    /// <remarks>
    /// From the informational version, which the packaging script sets from the release tag. A build
    /// made without it reports 0.0.0 and will therefore accept any release as newer - which is the
    /// right way round for a developer build that asked to check.
    /// </remarks>
    private static ProductVersion ReadCurrentVersion()
    {
        var informational = Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;

        // "0.6.0+abc1234" - the build metadata after the plus is not part of the version.
        var plus = informational?.IndexOf('+', StringComparison.Ordinal) ?? -1;
        var text = plus > 0 ? informational![..plus] : informational;

        return ProductVersion.Parse(text);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _timer?.Dispose();
        _timer = null;
        _gate.Dispose();
        _http.Dispose();
    }
}
