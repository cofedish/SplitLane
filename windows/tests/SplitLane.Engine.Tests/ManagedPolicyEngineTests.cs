using System.Security.AccessControl;
using SplitLane.Core.Configuration;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;
using SplitLane.Engine.Runtime;
using SplitLane.Engine.Update;

namespace SplitLane.Engine.Tests;

/// <summary>
/// The managed policy in the engine: when a policy file is trusted, and what it changes.
/// </summary>
/// <remarks>
/// The trust decision is exercised both as a pure function over owners and access entries, and once for
/// real: a policy file created by the account running the tests - an ordinary user, like anyone who can
/// write to <c>%ProgramData%\SplitLane</c> - must be refused.
/// </remarks>
public sealed class ManagedPolicyEngineTests : IDisposable
{
    private const string System = "S-1-5-18";
    private const string Administrators = "S-1-5-32-544";
    private const string Users = "S-1-5-32-545";
    private const string SomeUser = "S-1-5-21-1111111111-2222222222-3333333333-1001";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "splitlane-policy-" + Guid.NewGuid().ToString("N")[..8]);

    public ManagedPolicyEngineTests() => Directory.CreateDirectory(_root);

    private static AccessEntry Allow(string sid, FileSystemRights rights) => new(sid, rights, Allow: true);

    // ---- Trust ------------------------------------------------------------------------------------

    [Fact]
    public void AFileOwnedAndWritableOnlyByAdministratorsIsTrusted() =>
        Assert.Null(PolicyFileTrust.Problem(
            Administrators,
            [Allow(System, FileSystemRights.FullControl), Allow(Administrators, FileSystemRights.FullControl), Allow(Users, FileSystemRights.ReadAndExecute)],
            Administrators,
            [Allow(System, FileSystemRights.FullControl), Allow(Users, FileSystemRights.ReadAndExecute)]));

    [Fact]
    public void AFileAUserCreatedIsNotTrusted() =>
        Assert.Contains("owned by", PolicyFileTrust.Problem(SomeUser, [Allow(SomeUser, FileSystemRights.FullControl)], System, []));

    [Fact]
    public void AnAdministratorsFileInAFolderAUserOwnsIsNotTrusted() =>
        // The folder's owner can rewrite its permissions whenever it likes, then replace the file.
        Assert.Contains("folder is owned by", PolicyFileTrust.Problem(Administrators, [], SomeUser, []));

    [Theory]
    [InlineData(FileSystemRights.WriteData)]
    [InlineData(FileSystemRights.AppendData)]
    [InlineData(FileSystemRights.Write)]
    [InlineData(FileSystemRights.Modify)]
    [InlineData(FileSystemRights.Delete)]
    [InlineData(FileSystemRights.ChangePermissions)]
    [InlineData(FileSystemRights.TakeOwnership)]
    public void AFileUsersCanChangeIsNotTrusted(FileSystemRights rights) =>
        Assert.Contains("can modify", PolicyFileTrust.Problem(System, [Allow(Users, rights)], System, []));

    [Theory]
    [InlineData(FileSystemRights.DeleteSubdirectoriesAndFiles)]
    [InlineData(FileSystemRights.CreateFiles)]
    [InlineData(FileSystemRights.Delete)]
    [InlineData(FileSystemRights.ChangePermissions)]
    [InlineData(FileSystemRights.TakeOwnership)]
    public void AFileInAFolderUsersCanChangeIsNotTrusted(FileSystemRights rights) =>
        Assert.Contains("in its folder", PolicyFileTrust.Problem(
            System, [Allow(Users, FileSystemRights.Read)], System, [Allow(Users, rights)]));

    [Fact]
    public void ADenyEntryGrantsNothing() =>
        Assert.Null(PolicyFileTrust.Problem(System, [new AccessEntry(Users, FileSystemRights.FullControl, Allow: false)], System, []));

    [Fact]
    public void APolicyFileCreatedByTheTestAccountIsRefusedForReal()
    {
        var path = Path.Combine(_root, "policy.json");
        File.WriteAllText(path, PolicyMerger.Encode(new ManagedPolicy()));

        var load = new PolicyStore(path, PolicyFileTrust.Problem).Load();

        // Unelevated, the file is owned by the test account; on an elevated build agent it is owned by
        // Administrators but inherits an entry giving the account itself full control. Refused either
        // way, for either reason.
        Assert.Equal(PolicyState.Rejected, load.State);
        Assert.Null(load.Policy);
        Assert.Contains("was not used", load.Detail);
    }

    [Fact]
    public void NoPolicyFileMeansNoPolicy()
    {
        var load = new PolicyStore(Path.Combine(_root, "absent.json"), PolicyFileTrust.Problem).Load();

        Assert.Equal(PolicyState.None, load.State);
    }

    [Fact]
    public void AnUnreadablePolicyIsRejectedWithItsReason()
    {
        var path = Path.Combine(_root, "policy.json");
        File.WriteAllText(path, "{ \"schemaVersion\": 1, \"unknownField\": true }");

        var load = new PolicyStore(path, (_, _) => null).Load();

        Assert.Equal(PolicyState.Rejected, load.State);
        Assert.Contains("could not be read", load.Detail);
    }

    // ---- In the running engine ----------------------------------------------------------------------

    private static AppIdentity Chat() => new()
    {
        ExecutablePath = @"C:\Program Files\Contoso\Chat\chat.exe",
        DisplayName = "Contoso Chat",
        Kind = IdentityKind.Signed,
        SignerSubject = PublisherName.Canonical("CN=Contoso Ltd, O=Contoso Ltd, C=US"),
        BinaryName = "chat.exe",
    };

    private (EngineRuntime Runtime, string PolicyPath) RuntimeWithPolicy(
        ManagedPolicy? policy, RuntimeConfiguration? user = null, bool verifyAbsence = false)
    {
        var policyPath = Path.Combine(_root, "Policy", "policy.json");
        Directory.CreateDirectory(Path.GetDirectoryName(policyPath)!);
        if (policy is not null)
        {
            File.WriteAllText(policyPath, PolicyMerger.Encode(policy));
        }

        var store = new ConfigurationStore(Path.Combine(_root, "configuration.v2.json"), Path.Combine(_root, "credential.bin"));
        if (user is not null)
        {
            store.Save(user);
        }

        // Trust is decided above for real; here the file stands in for one an administrator placed.
        var runtime = new EngineRuntime(
            store,
            new EngineOptions(EnableDivert: false),
            new Flows.ImageCatalog(workers: 1),
            Platform.WindowsImageInspector.Instance,
            new PolicyStore(policyPath, (_, _) => null, verifyAbsence));

        return (runtime, policyPath);
    }

    [Fact]
    public async Task APolicyIsAppliedOnTopOfTheUsersConfigurationAndRevokedByRemoval()
    {
        var (runtime, policyPath) = RuntimeWithPolicy(
            new ManagedPolicy { Rules = [new AppRule { Identity = Chat() }], ForceRoutingEnabled = true },
            RuntimeConfiguration.Empty with { IsRoutingEnabled = false });
        await using var _ = runtime;

        runtime.LoadConfiguration();

        Assert.Equal(PolicyState.Applied, runtime.Policy.State);
        Assert.True(runtime.Configuration.IsRoutingEnabled);
        Assert.False(runtime.UserConfiguration.IsRoutingEnabled);
        Assert.True(runtime.IsRoutingLockedByPolicy);
        Assert.Equal(1, runtime.Status().ManagedRuleCount);
        Assert.True(runtime.Status().RoutingLockedByPolicy);

        File.Delete(policyPath);
        runtime.ReloadPolicy();

        Assert.Equal(PolicyState.None, runtime.Policy.State);
        Assert.Empty(runtime.Configuration.Rules);
        Assert.False(runtime.Configuration.IsRoutingEnabled);
        Assert.False(runtime.IsRoutingLockedByPolicy);
    }

    [Fact]
    public async Task APolicyFileHeldOpenByAUserDoesNotDropTheLastPolicyThatVerified()
    {
        // Found in review: every user could read the file, open it without sharing, and make the
        // engine's read fail - which dropped the policy, and forced routing with it.
        var (runtime, policyPath) = RuntimeWithPolicy(
            new ManagedPolicy { Rules = [new AppRule { Identity = Chat() }], ForceRoutingEnabled = true });
        await using var disposable = runtime;
        runtime.LoadConfiguration();

        using (new FileStream(policyPath, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            runtime.ReloadPolicy();

            Assert.Equal(PolicyState.Applied, runtime.Policy.State);
            Assert.True(runtime.IsRoutingLockedByPolicy);
            Assert.Single(runtime.Configuration.Rules);
            Assert.Contains("refused", runtime.Policy.Detail);
        }
    }

    [Fact]
    public async Task APolicyThatVanishesFromAFolderOthersControlIsNotTakenAsRevoked()
    {
        // Found in re-review: a folder above the policy that a user owns can be renamed, taking the
        // policy with it, and "the file is gone" would then read as the administrator revoking it.
        // The test's temporary folder is owned by the test account, which is exactly that situation.
        var (runtime, policyPath) = RuntimeWithPolicy(
            new ManagedPolicy { Rules = [new AppRule { Identity = Chat() }], ForceRoutingEnabled = true },
            verifyAbsence: true);
        await using var disposable = runtime;
        runtime.LoadConfiguration();

        File.Delete(policyPath);
        runtime.ReloadPolicy();

        Assert.Equal(PolicyState.Applied, runtime.Policy.State);
        Assert.True(runtime.IsRoutingLockedByPolicy);
        Assert.Contains("a newer read was refused", runtime.Policy.Detail);
    }

    [Fact]
    public void AncestorsAUserOwnsAreReported() =>
        Assert.Contains("owned by", PolicyFileTrust.AncestryProblem(Path.Combine(_root, "Policy")));

    [Fact]
    public void AnOversizedConfigurationIsRefusedBeforeItIsRead()
    {
        var path = Path.Combine(_root, "configuration.v2.json");
        using (var file = File.Create(path))
        {
            file.SetLength(ConfigurationStore.MaxConfigurationBytes + 1);
        }

        var store = new ConfigurationStore(path, Path.Combine(_root, "credential.bin"));
        var loaded = store.LoadOrDefault(out var error);

        Assert.Same(RuntimeConfiguration.Empty, loaded);
        Assert.Contains("larger than", error);
    }

    [Fact]
    public async Task SavingTheUsersConfigurationDoesNotLoseThePolicy()
    {
        var (runtime, _) = RuntimeWithPolicy(new ManagedPolicy { Rules = [new AppRule { Identity = Chat() }] });
        await using var disposable = runtime;
        runtime.LoadConfiguration();

        runtime.Save(RuntimeConfiguration.Empty.WithNextGeneration());

        Assert.Single(runtime.Configuration.Rules);
        Assert.True(runtime.Configuration.Rules[0].IsManaged);
        Assert.Empty(runtime.UserConfiguration.Rules);
    }

    [Fact]
    public async Task SelfUpdateIsOffWhenThePolicySaysSo()
    {
        var (runtime, _) = RuntimeWithPolicy(new ManagedPolicy { DisableSelfUpdate = true });
        await using var disposable = runtime;

        runtime.LoadConfiguration();
        var state = await runtime.Updates.CheckAsync();

        Assert.True(runtime.Updates.DisabledByPolicy);
        Assert.Equal(UpdateState.Unknown, state);
        Assert.Contains("policy", runtime.Updates.LastError);
        Assert.False(await runtime.Updates.ApplyAsync());
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
