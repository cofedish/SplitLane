using SplitLane.App.Infrastructure;
using SplitLane.Core.Models;

namespace SplitLane.App.ViewModels;

/// <summary>The Proxy page: where the proxy lane points.</summary>
public sealed class ProxyViewModel : ObservableObject
{
    private readonly MainViewModel _main;

    private string _host = "127.0.0.1";
    private string _port = "10808";
    private string _displayName = "Local SOCKS5";
    private ProxyProtocolType _type = ProxyProtocolType.Socks5;
    private bool _requiresAuthentication;
    private string _username = string.Empty;
    private string _password = string.Empty;
    private bool _passwordEdited;
    private bool _preferHostnames = true;
    private string _timeoutSeconds = "10";
    private string? _testResult;
    private bool _testFailed;
    private Guid _id = Guid.NewGuid();

    /// <summary>Builds the page.</summary>
    public ProxyViewModel(MainViewModel main)
    {
        _main = main ?? throw new ArgumentNullException(nameof(main));

        TestCommand = new AsyncRelayCommand(TestAsync, () => _main.EngineConnected);
    }

    /// <summary>Asks the engine to verify the upstream.</summary>
    public AsyncRelayCommand TestCommand { get; }

    /// <summary>Friendly name for this proxy.</summary>
    public string DisplayName
    {
        get => _displayName;
        set { if (Set(ref _displayName, value)) { _main.MarkDirty(); } }
    }

    /// <summary>Which protocol the upstream speaks.</summary>
    /// <remarks>
    /// Not detectable from here: an HTTP proxy sent a SOCKS5 greeting says nothing until the timeout,
    /// so the person who knows what the proxy is has to say.
    /// </remarks>
    public ProxyProtocolType Type
    {
        get => _type;
        set
        {
            if (Set(ref _type, value))
            {
                _main.MarkDirty();
                RaiseTypeDependents();
            }
        }
    }

    /// <summary>Radio binding for SOCKS5.</summary>
    public bool IsSocks5
    {
        get => Type == ProxyProtocolType.Socks5;
        set { if (value) { Type = ProxyProtocolType.Socks5; } }
    }

    /// <summary>Radio binding for HTTP.</summary>
    public bool IsHttp
    {
        get => Type == ProxyProtocolType.Http;
        set { if (value) { Type = ProxyProtocolType.Http; } }
    }

    /// <summary>The badge on the Upstream card.</summary>
    public string TypeBadge => Type.DisplayName();

    /// <summary>What the Authentication card says about how the credentials are used.</summary>
    public string AuthenticationSummary => Type == ProxyProtocolType.Http
        ? "Used when the proxy answers 407: Negotiate (Kerberos), NTLM or Basic, preferred in that order. " +
          "For a domain account enter DOMAIN\\user or user@domain. The password is encrypted for this machine and " +
          "stored outside the configuration file — SplitLane can tell you one exists, never what it is."
        : "Username and password, RFC 1929. The password is encrypted for this machine and stored outside the " +
          "configuration file — SplitLane can tell you one exists, never what it is.";

    /// <summary>The plaintext warning, which depends on the protocol.</summary>
    public string PlaintextWarning => Type == ProxyProtocolType.Http
        ? "This proxy is not on this machine. If it asks for Basic authentication the password crosses the " +
          "network unencrypted; NTLM and Negotiate never send it."
        : "This proxy is not on this machine. SOCKS5 sends the username and password unencrypted, so they will " +
          "cross the network in the clear.";

    /// <summary>What happens to a selected application's UDP with this protocol.</summary>
    public string UdpNote => Type == ProxyProtocolType.Http
        ? "HTTP CONNECT carries TCP only. A selected application's UDP is refused, never sent direct: QUIC falls " +
          "back to TCP, and anything with no TCP fallback will not connect."
        : "SOCKS5 relays a selected application's UDP as well, while UDP relaying is on in Settings.";

    /// <summary>Hostname or IP literal.</summary>
    public string Host
    {
        get => _host;
        set
        {
            if (Set(ref _host, value))
            {
                _main.MarkDirty();
                Raise(nameof(PlaintextWarningVisible));
                Raise(nameof(EndpointSummary));
            }
        }
    }

    /// <summary>TCP port, as typed.</summary>
    public string Port
    {
        get => _port;
        set
        {
            if (Set(ref _port, value))
            {
                _main.MarkDirty();
                Raise(nameof(EndpointSummary));
            }
        }
    }

    /// <summary>Whether the upstream needs a username and password.</summary>
    public bool RequiresAuthentication
    {
        get => _requiresAuthentication;
        set
        {
            if (Set(ref _requiresAuthentication, value))
            {
                _main.MarkDirty();
                Raise(nameof(PlaintextWarningVisible));
            }
        }
    }

    /// <summary>Proxy username. Not a secret and stored in the configuration file.</summary>
    public string Username
    {
        get => _username;
        set { if (Set(ref _username, value)) { _main.MarkDirty(); } }
    }

    /// <summary>
    /// Proxy password.
    /// </summary>
    /// <remarks>
    /// Held here only until the next save, then handed to the credential store and never read back.
    /// The UI can tell you that a password <i>exists</i>; it has no way to show you what it is.
    /// </remarks>
    public string Password
    {
        get => _password;
        set
        {
            if (Set(ref _password, value))
            {
                _passwordEdited = true;
                _main.MarkDirty();
                Raise(nameof(CredentialStatus));
            }
        }
    }

    /// <summary>Whether to send hostnames to the upstream when one is known.</summary>
    public bool PreferHostnames
    {
        get => _preferHostnames;
        set { if (Set(ref _preferHostnames, value)) { _main.MarkDirty(); } }
    }

    /// <summary>Connect-plus-handshake budget, in seconds, as typed.</summary>
    public string TimeoutSeconds
    {
        get => _timeoutSeconds;
        set { if (Set(ref _timeoutSeconds, value)) { _main.MarkDirty(); } }
    }

    /// <summary>Result of the last reachability test.</summary>
    public string? TestResult
    {
        get => _testResult;
        private set
        {
            if (Set(ref _testResult, value))
            {
                Raise(nameof(HasTestResult));
            }
        }
    }

    /// <summary>Whether the last test failed.</summary>
    public bool TestFailed
    {
        get => _testFailed;
        private set => Set(ref _testFailed, value);
    }

    /// <summary>Whether there is a test result to show.</summary>
    public bool HasTestResult => !string.IsNullOrEmpty(TestResult);

    /// <summary>Where the lane points, in one line.</summary>
    public string EndpointSummary => Host.Contains(':') ? $"[{Host}]:{Port}" : $"{Host}:{Port}";

    /// <summary>What the app knows about the stored password, which is only whether there is one.</summary>
    public string CredentialStatus
    {
        get
        {
            if (_passwordEdited && Password.Length > 0)
            {
                return "A new password will be stored when you save.";
            }

            return _main.Store.HasStoredCredential
                ? "A password is stored for this machine. Type a new one to replace it."
                : "No password stored yet.";
        }
    }

    /// <summary>
    /// Whether to warn that credentials would cross a real network unencrypted.
    /// </summary>
    /// <remarks>
    /// RFC 1929 sends the username and password in the clear. On loopback that is irrelevant; to a
    /// proxy on another host it is not, and the user is the only one who can decide whether that
    /// matters on their network.
    /// </remarks>
    public bool PlaintextWarningVisible =>
        RequiresAuthentication && !Core.Rules.NetworkAddress.IsLoopbackHost(Host);

    /// <summary>Reloads from a configuration.</summary>
    public void LoadFrom(RuntimeConfiguration configuration)
    {
        var proxy = configuration.Proxy;

        _id = proxy.Id;
        _displayName = proxy.DisplayName;
        _type = proxy.Type;
        _host = proxy.Endpoint.Host;
        _port = proxy.Endpoint.Port.ToString();
        _requiresAuthentication = proxy.RequiresAuthentication;
        _username = proxy.Credential?.Username ?? string.Empty;
        _preferHostnames = proxy.PreferHostnames;
        _timeoutSeconds = (proxy.HandshakeTimeoutMilliseconds / 1000.0).ToString("0.#");
        _password = string.Empty;
        _passwordEdited = false;

        Raise(nameof(DisplayName));
        RaiseTypeDependents();
        Raise(nameof(Host));
        Raise(nameof(Port));
        Raise(nameof(RequiresAuthentication));
        Raise(nameof(Username));
        Raise(nameof(Password));
        Raise(nameof(PreferHostnames));
        Raise(nameof(TimeoutSeconds));
        Raise(nameof(EndpointSummary));
        Raise(nameof(CredentialStatus));
        Raise(nameof(PlaintextWarningVisible));
    }

    /// <summary>Builds the stored form, throwing when a field cannot be parsed.</summary>
    public ProxyConfiguration ToProxyConfiguration()
    {
        if (!ushort.TryParse(Port.Trim(), out var port) || port == 0)
        {
            throw new Core.Configuration.ConfigurationValidationException(
                Core.Configuration.ConfigurationValidationCode.InvalidProxyPort,
                $"\"{Port}\" is not a valid port. Enter a number between 1 and 65535.");
        }

        if (!double.TryParse(TimeoutSeconds.Trim(), out var seconds) || seconds <= 0)
        {
            throw new Core.Configuration.ConfigurationValidationException(
                Core.Configuration.ConfigurationValidationCode.NonPositiveTimeout,
                $"\"{TimeoutSeconds}\" is not a valid timeout. Enter a number of seconds greater than zero.");
        }

        return new ProxyConfiguration
        {
            Id = _id,
            DisplayName = string.IsNullOrWhiteSpace(DisplayName) ? "Proxy" : DisplayName.Trim(),
            Type = Type,
            Endpoint = new ProxyEndpoint { Host = Host.Trim(), Port = port },
            Credential = RequiresAuthentication
                ? new CredentialReference { Username = Username.Trim(), SecretKey = "splitlane/proxy" }
                : null,
            IsEnabled = true,
            HandshakeTimeoutMilliseconds = (int)(seconds * 1000),
            PreferHostnames = PreferHostnames,
        };
    }

    private void RaiseTypeDependents()
    {
        Raise(nameof(Type));
        Raise(nameof(IsSocks5));
        Raise(nameof(IsHttp));
        Raise(nameof(TypeBadge));
        Raise(nameof(AuthenticationSummary));
        Raise(nameof(PlaintextWarning));
        Raise(nameof(UdpNote));
    }

    /// <summary>Writes the password to the credential store, if one was typed.</summary>
    public void PersistCredential()
    {
        if (!RequiresAuthentication)
        {
            _main.Store.ClearCredential();
            return;
        }

        if (_passwordEdited && Password.Length > 0)
        {
            _main.Store.SaveCredential(Password);
            _password = string.Empty;
            _passwordEdited = false;
            Raise(nameof(Password));
            Raise(nameof(CredentialStatus));
        }
    }

    private async Task TestAsync()
    {
        TestResult = "Testing…";
        TestFailed = false;

        var reply = await _main.Engine.TestProxyAsync().ConfigureAwait(true);

        if (!reply.Connected)
        {
            TestFailed = true;
            TestResult = reply.Message ?? "The engine is not running, so it cannot test the proxy.";
            return;
        }

        if (reply.Response?.ProxyTest is not { } result)
        {
            TestFailed = true;
            TestResult = reply.Message ?? "The engine did not return a result.";
            return;
        }

        TestFailed = !result.Succeeded;
        TestResult = result.LatencyMilliseconds is { } latency
            ? $"{result.Detail} ({latency:F0} ms)"
            : result.Detail ?? (result.Succeeded ? "Reachable." : "Unreachable.");
    }
}
