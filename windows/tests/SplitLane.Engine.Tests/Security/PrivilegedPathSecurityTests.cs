using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using SplitLane.Core.Models;
using SplitLane.Engine.Runtime;

namespace SplitLane.Engine.Tests.Security;

/// <summary>
/// SL-SEC-007: nothing the service writes can be steered by a name or a folder an ordinary user
/// prepared in <c>%ProgramData%\SplitLane</c>. Service data lives in directories the service created
/// with its own permissions; the one shared file, the configuration, is written under a fresh
/// exclusive name.
/// </summary>
[Trait("Category", "Security")]
public sealed class PrivilegedPathSecurityTests : IDisposable
{
    private static readonly SecurityIdentifier Me = WindowsIdentity.GetCurrent().User!;
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);

    private readonly string _root = Path.Combine(Path.GetTempPath(), "sl-sec007-" + Guid.NewGuid().ToString("N"));

    public PrivilegedPathSecurityTests() => Directory.CreateDirectory(_root);

    // ---- Configuration -----------------------------------------------------------------------------

    [Fact]
    public void A_temporary_file_prepared_in_advance_is_never_written_through()
    {
        var path = Path.Combine(_root, "configuration.v2.json");
        var planted = path + ".tmp";
        File.WriteAllText(planted, "prepared by somebody else");

        var store = new ConfigurationStore(path, Path.Combine(_root, "credential.bin"));
        store.Save(RuntimeConfiguration.Empty);
        store.Save(RuntimeConfiguration.Empty);

        Assert.Equal("prepared by somebody else", File.ReadAllText(planted));
        Assert.NotNull(store.Load());
    }

    [Fact]
    public void Saving_leaves_no_temporary_files_behind()
    {
        var path = Path.Combine(_root, "configuration.v2.json");
        var store = new ConfigurationStore(path, Path.Combine(_root, "credential.bin"));

        for (var i = 0; i < 5; i++)
        {
            store.Save(RuntimeConfiguration.Empty);
        }

        Assert.Equal(["configuration.v2.json"], Directory.EnumerateFiles(_root).Select(Path.GetFileName));
    }

    // ---- Logs --------------------------------------------------------------------------------------

    [Fact]
    public void The_log_directory_lets_users_read_and_nothing_else()
    {
        var logs = new ProtectedDirectory(Path.Combine(_root, "production-logs"), UserAccess.Read);
        var rules = logs.Descriptor().GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToList();

        Assert.True(logs.Descriptor().AreAccessRulesProtected);
        var users = Assert.Single(rules, rule => rule.IdentityReference.Value == Users.Value);
        Assert.Equal(AccessControlType.Allow, users.AccessControlType);
        Assert.Equal(FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize, users.FileSystemRights | FileSystemRights.Synchronize);
        Assert.Equal(
            new HashSet<string> { "S-1-5-18", "S-1-5-32-544", Users.Value },
            rules.Select(rule => rule.IdentityReference.Value).ToHashSet());
    }

    [Fact]
    public void A_log_directory_a_user_created_first_is_moved_aside_with_whatever_was_planted_in_it()
    {
        var path = Path.Combine(_root, "logs");
        Directory.CreateDirectory(path); // inherits the parent's permissions, like a user-made folder
        File.WriteAllText(Path.Combine(path, "engine.log"), "planted");

        var logs = new ProtectedDirectory(path, UserAccess.Read, [Me], checkAncestry: false);
        logs.Ensure();

        Assert.Null(logs.Problem(path));
        Assert.False(File.Exists(Path.Combine(path, "engine.log")));
        Assert.Single(Directory.EnumerateDirectories(_root, "logs.untrusted-*"));
    }

    [Fact]
    public void A_junction_where_the_log_directory_belongs_is_never_followed()
    {
        var target = Path.Combine(_root, "somewhere-else");
        Directory.CreateDirectory(target);
        var path = Path.Combine(_root, "logs");
        Junction(path, target);

        var logs = new ProtectedDirectory(path, UserAccess.Read, [Me], checkAncestry: false);
        logs.Ensure();
        File.WriteAllText(Path.Combine(path, "engine.log"), "written by the service");

        Assert.Empty(Directory.EnumerateFileSystemEntries(target));
        Assert.Equal(0, (int)(File.GetAttributes(path) & FileAttributes.ReparsePoint));
    }

    [Fact]
    public void A_readable_directory_that_users_could_write_is_not_trusted()
    {
        var path = Path.Combine(_root, "logs");
        var logs = new ProtectedDirectory(path, UserAccess.Read, [Me], checkAncestry: false);
        logs.Ensure();

        var directory = new DirectoryInfo(path);
        var security = directory.GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.CreateFiles, AccessControlType.Allow));
        directory.SetAccessControl(security);

        Assert.NotNull(logs.Problem(path));
    }

    [Fact]
    public void A_service_only_directory_that_users_could_even_read_is_not_trusted()
    {
        var path = Path.Combine(_root, "secrets");
        var secrets = new ProtectedDirectory(path, UserAccess.None, [Me], checkAncestry: false);
        secrets.Ensure();

        var directory = new DirectoryInfo(path);
        var security = directory.GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.ReadAndExecute, AccessControlType.Allow));
        directory.SetAccessControl(security);

        Assert.NotNull(secrets.Problem(path));
    }

    private static void Junction(string link, string target)
    {
        using var process = Process.Start(new ProcessStartInfo(
            Path.Combine(Environment.SystemDirectory, "cmd.exe"), ["/c", "mklink", "/J", link, target])
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
        })!;
        process.WaitForExit();
        Assert.Equal(0, process.ExitCode);
    }

    public void Dispose()
    {
        try
        {
            foreach (var entry in Directory.EnumerateDirectories(_root))
            {
                if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0)
                {
                    Directory.Delete(entry);
                }
            }

            Directory.Delete(_root, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }
}
