using System.Collections.Concurrent;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using SplitLane.Core.Ipc;
using SplitLane.Core.Logging;
using SplitLane.Core.Models;
using SplitLane.Engine.Ipc;
using SplitLane.Engine.Runtime;

namespace SplitLane.Engine.Tests.Security;

/// <summary>
/// SL-SEC-006: the proxy password is kept where only the service can read it, used only for the
/// protocol, host, port and account it was entered for, moved out of the old user-readable file, and
/// never written to logs or diagnostics.
/// </summary>
[Trait("Category", "Security")]
public sealed class CredentialIsolationSecurityTests : IDisposable
{
    private static readonly SecurityIdentifier Me = WindowsIdentity.GetCurrent().User!;

    // A value that cannot appear in a log line by accident.
    private const string Password = "pw-SL-SEC-006-7f3a9c";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "sl-sec006-" + Guid.NewGuid().ToString("N"));

    public CredentialIsolationSecurityTests() => Directory.CreateDirectory(_root);

    private ProtectedDirectory Secrets() => new(Path.Combine(_root, "Secrets"), UserAccess.None, [Me], checkAncestry: false);

    private ProxyCredentialStore Store() => new(Secrets());

    private static ProxyConfiguration Proxy(
        string host = "proxy.corp.example", ushort port = 3128, string user = "alice",
        ProxyProtocolType type = ProxyProtocolType.Http) => new()
    {
        Type = type,
        Endpoint = new ProxyEndpoint { Host = host, Port = port },
        Credential = new CredentialReference { Username = user },
    };

    private static ProxyCredentialBinding BindingFor(ProxyConfiguration proxy) => ProxyCredentialBinding.For(proxy)!;

    [Fact]
    public void The_password_is_used_for_the_proxy_it_was_entered_for()
    {
        var store = Store();
        store.Save(BindingFor(Proxy()), Password);

        var credential = store.Resolve(Proxy());

        Assert.NotNull(credential);
        Assert.Equal("alice", credential.Username);
        Assert.Equal(Password, credential.Password);
    }

    [Theory]
    [InlineData("attacker.example", 3128, "alice", ProxyProtocolType.Http)]   // another host
    [InlineData("proxy.corp.example", 8080, "alice", ProxyProtocolType.Http)] // another port
    [InlineData("proxy.corp.example", 3128, "mallory", ProxyProtocolType.Http)] // another account
    [InlineData("proxy.corp.example", 3128, "alice", ProxyProtocolType.Socks5)] // another protocol
    public void The_password_does_not_follow_the_proxy_to_another_place(string host, ushort port, string user, ProxyProtocolType type)
    {
        var store = Store();
        store.Save(BindingFor(Proxy()), Password);

        Assert.Null(store.Resolve(Proxy(host, port, user, type)));
    }

    [Fact]
    public void Host_case_does_not_matter_but_everything_else_does()
    {
        var store = Store();
        store.Save(BindingFor(Proxy()), Password);

        Assert.NotNull(store.Resolve(Proxy(host: "PROXY.corp.example")));
    }

    [Fact]
    public void The_service_store_grants_ordinary_users_nothing()
    {
        // The production directory: SYSTEM and Administrators, inheritance cut, no entry for anyone else.
        var production = new ProtectedDirectory(Path.Combine(_root, "production"), UserAccess.None);
        var descriptor = production.Descriptor();

        Assert.True(descriptor.AreAccessRulesProtected);
        var principals = descriptor.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Select(rule => rule.IdentityReference.Value)
            .ToHashSet();
        Assert.Equal(new HashSet<string> { "S-1-5-18", "S-1-5-32-544" }, principals);
    }

    [Fact]
    public void A_password_file_in_a_directory_others_could_write_is_not_believed()
    {
        var store = Store();
        store.Save(BindingFor(Proxy()), Password);

        // Somebody widens the directory's permissions. The service no longer trusts what is in it.
        var directory = new DirectoryInfo(Path.Combine(_root, "Secrets"));
        var security = directory.GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.Modify, AccessControlType.Allow));
        directory.SetAccessControl(security);

        Assert.Null(store.Resolve(Proxy()));
    }

    [Fact]
    public void The_password_is_not_on_disk_in_the_clear()
    {
        Store().Save(BindingFor(Proxy()), Password);

        foreach (var file in Directory.EnumerateFiles(_root, "*", SearchOption.AllDirectories))
        {
            Assert.DoesNotContain(Password, File.ReadAllText(file), StringComparison.Ordinal);
        }
    }

    [Fact]
    public void The_old_user_readable_file_is_migrated_and_deleted()
    {
        var legacy = Path.Combine(_root, "credential.bin");
        File.WriteAllBytes(legacy, ProtectedData.Protect(Encoding.UTF8.GetBytes(Password), null, DataProtectionScope.LocalMachine));

        var store = Store();
        Assert.True(store.MigrateLegacy(legacy, Proxy()));

        Assert.False(File.Exists(legacy));
        Assert.Equal(Password, store.Resolve(Proxy())!.Password);
        Assert.Null(store.Resolve(Proxy(host: "attacker.example")));
    }

    [Fact]
    public void An_old_file_with_no_account_to_bind_it_to_is_deleted_anyway()
    {
        var legacy = Path.Combine(_root, "credential.bin");
        File.WriteAllBytes(legacy, ProtectedData.Protect(Encoding.UTF8.GetBytes(Password), null, DataProtectionScope.LocalMachine));

        var store = Store();
        Assert.False(store.MigrateLegacy(legacy, ProxyConfiguration.Default));

        Assert.False(File.Exists(legacy));
        Assert.Null(store.Binding);
    }

    [Fact]
    public void The_password_never_reaches_logs_messages_or_status()
    {
        var sink = new CapturingSink();
        SplitLaneLog.AddSink(sink);

        var store = Store();
        store.Save(BindingFor(Proxy()), Password);
        store.Resolve(Proxy());
        store.Resolve(Proxy(host: "attacker.example")); // logs a mismatch

        var update = new ProxyCredentialUpdate(ProxyProtocolType.Http, "proxy.corp.example", 3128, "alice", Password);
        ControlServer.ProxyCredentialAcceptable(update with { Port = 0 }, out var refusal);

        Assert.DoesNotContain(Password, update.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Password, refusal, StringComparison.Ordinal);
        Assert.DoesNotContain(Password, store.Binding!.Display, StringComparison.Ordinal);
        Assert.DoesNotContain(sink.Lines, line => line.Contains(Password, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("", "alice", "pw")]
    [InlineData("proxy", "", "pw")]
    [InlineData("proxy", "alice", "")]
    [InlineData("proxy\n", "alice", "pw")]
    public void The_service_refuses_a_credential_that_names_nothing(string host, string user, string password)
    {
        var update = new ProxyCredentialUpdate(ProxyProtocolType.Http, host, 3128, user, password);
        Assert.False(ControlServer.ProxyCredentialAcceptable(update, out _));
    }

    private sealed class CapturingSink : ILogSink
    {
        public ConcurrentBag<string> Lines { get; } = [];

        public void Write(LogLevel level, string category, string message) => Lines.Add(message);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }
}
