using System.Diagnostics;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
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
        "https://github.com/cofedish/SplitLane/releases/latest/download/update.json";

    private const string SignatureUrl = ManifestUrl + ".sig";

    /// <summary>How often the engine looks, when nobody has asked it to.</summary>
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(24);

    /// <summary>A first look shortly after start, once the machine has settled.</summary>
    private static readonly TimeSpan FirstCheckDelay = TimeSpan.FromMinutes(3);

    private readonly HttpClient _http;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Timer? _timer;

    /// <summary>Builds the service. Nothing is fetched until <see cref="Start"/>.</summary>
    public UpdateService(HttpClient? http = null)
    {
        _http = http ?? new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd($"SplitLane/{CurrentVersion}");
    }

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
                manifestJson, signature, ReleaseKey.PublicKeySpki, out var manifest);

            if (rejection != ManifestRejection.None || manifest is null)
            {
                // Worth saying loudly. A rejected manifest is either a release published wrong or
                // somebody standing in the middle, and the difference is not visible from here.
                return Fail($"the published update was refused: {rejection}");
            }

            LastChecked = DateTimeOffset.UtcNow;

            var offered = ProductVersion.Parse(manifest.Version);

            if (!offered.IsNewerThan(CurrentVersion))
            {
                Available = null;
                LastError = null;
                SplitLaneLog.Debug(LogCategory, $"{CurrentVersion} is current; latest is {offered}");
                return State = UpdateState.UpToDate;
            }

            Available = manifest;
            LastError = null;
            SplitLaneLog.Info(LogCategory, $"{offered} is available; this is {CurrentVersion}");
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

            var directory = Path.Combine(SplitLanePaths.Root, "updates");
            Directory.CreateDirectory(directory);

            var installer = Path.Combine(directory, $"SplitLane-{manifest.Version}-x64.msi");

            await DownloadAsync(manifest.Url, installer, cancellationToken).ConfigureAwait(false);

            var actual = await HashAsync(installer, cancellationToken).ConfigureAwait(false);

            if (!actual.Equals(manifest.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                TryDelete(installer);
                Fail("the downloaded installer does not match the hash the release was signed with");
                return false;
            }

            SplitLaneLog.Info(LogCategory, $"installing {manifest.Version}");
            State = UpdateState.Installing;

            Launch(installer);
            return true;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException
                                       or UnauthorizedAccessException)
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

    private async Task DownloadAsync(string url, string destination, CancellationToken cancellationToken)
    {
        using var response = await _http
            .GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);

        response.EnsureSuccessStatusCode();

        // Written under a name nothing will run, then moved. A half-downloaded file that shares the
        // name of a finished one is a file somebody's tooling will eventually try to install.
        var partial = destination + ".part";

        await using (var file = File.Create(partial))
        {
            await response.Content.CopyToAsync(file, cancellationToken).ConfigureAwait(false);
        }

        File.Move(partial, destination, overwrite: true);
    }

    private static async Task<string> HashAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = File.OpenRead(path);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hash);
    }

    /// <summary>
    /// Starts the installer as a detached process.
    /// </summary>
    /// <remarks>
    /// Quiet, because there is nobody at the console of a service to answer a dialog, and because
    /// the package already knows how to stop the service, replace the files and start it again.
    /// </remarks>
    private static void Launch(string installer)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = "msiexec.exe",
            Arguments = $"/i \"{installer}\" /qn /norestart",
            UseShellExecute = false,
            CreateNoWindow = true,
        });

        if (process is null)
        {
            SplitLaneLog.Error(LogCategory, "the installer could not be started");
        }
    }

    private UpdateState Fail(string message)
    {
        LastError = message;
        SplitLaneLog.Warning(LogCategory, $"update check failed: {message}");
        return State = UpdateState.Failed;
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
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
