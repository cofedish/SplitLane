using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using SplitLane.Core.Configuration;
using SplitLane.Core.Logging;
using SplitLane.Core.Models;

namespace SplitLane.Engine.Runtime;

/// <summary>Whether a managed policy is in force, and why not when it is not.</summary>
public enum PolicyState
{
    /// <summary>There is no policy file. The user's configuration is all there is.</summary>
    None,

    /// <summary>A trusted policy was read and is in force.</summary>
    Applied,

    /// <summary>
    /// A policy file exists and was not used: its owner or permissions would let a non-administrator
    /// change it, or it could not be read. Reported loudly; the user's configuration applies.
    /// </summary>
    Rejected,
}

/// <summary>The result of reading the policy file.</summary>
/// <param name="Policy">The policy, when one is in force.</param>
/// <param name="State">What happened.</param>
/// <param name="Detail">A sentence for the log, the status and support.</param>
/// <param name="AbsenceVerified">
/// For <see cref="PolicyState.None"/>: whether nobody but an administrator could have made the file
/// absent. False when some folder above it could be renamed or deleted by someone else, in which case
/// a policy that was in force stays in force.
/// </param>
public sealed record PolicyLoad(ManagedPolicy? Policy, PolicyState State, string Detail, bool AbsenceVerified = true)
{
    /// <summary>No policy file.</summary>
    public static PolicyLoad Absent(string path) => new(null, PolicyState.None, $"no policy at {path}");
}

/// <summary>One access-control entry, reduced to what trust depends on.</summary>
/// <param name="Sid">The principal.</param>
/// <param name="Rights">What it is allowed.</param>
/// <param name="Allow">Allow or deny.</param>
internal readonly record struct AccessEntry(string Sid, FileSystemRights Rights, bool Allow);

/// <summary>
/// Decides whether a policy file is one only an administrator could have put there.
/// </summary>
/// <remarks>
/// <para>
/// The whole point of a managed policy is that the user cannot change it, and the file lives in a tree -
/// <c>%ProgramData%\SplitLane</c> - that every interactive user can write to, because the unelevated app
/// writes the user's configuration there. A file a user created, or one that inherited that tree's
/// permissions, would make "managed" mean nothing. So the engine reads the policy only when:
/// </para>
/// <list type="bullet">
/// <item>neither the file nor its folder is a link (a junction or symbolic link would let the file
/// judged and the file read be different files);</item>
/// <item>the file and its folder are owned by SYSTEM, Administrators or TrustedInstaller - a file or
/// folder a user created is owned by that user, and an owner can always rewrite its permissions;</item>
/// <item>no allow entry on the file gives anyone else the right to write, append, delete, or change
/// its permissions or owner;</item>
/// <item>no allow entry on the folder gives anyone else the right to create or delete files in it, to
/// delete it, or to change its permissions or owner.</item>
/// </list>
/// <para>
/// The file's own security is read from the handle its contents are then read from, so what was judged
/// is what is applied.
/// </para>
/// </remarks>
internal static class PolicyFileTrust
{
    private static readonly HashSet<string> Administrative = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-5-18",      // LocalSystem
        "S-1-5-32-544",  // BUILTIN\Administrators
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", // NT SERVICE\TrustedInstaller
    };

    /// <summary>Rights on the file that let a principal change what it says, or who controls it.</summary>
    private const FileSystemRights ModifyingFile =
        FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete |
        FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    /// <summary>Rights on the folder that let a principal put a different file where the policy is.</summary>
    private const FileSystemRights ModifyingFolder =
        FileSystemRights.CreateFiles | FileSystemRights.CreateDirectories |
        FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.Delete |
        FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    /// <summary>GENERIC_ALL and GENERIC_WRITE, which can appear in a raw mask.</summary>
    private const int GenericModifying = 0x10000000 | 0x40000000;

    /// <summary>Why a policy file cannot be trusted, or null when it can. Pure.</summary>
    public static string? Problem(
        string fileOwnerSid,
        IEnumerable<AccessEntry> fileEntries,
        string folderOwnerSid,
        IEnumerable<AccessEntry> folderEntries)
    {
        if (!Administrative.Contains(fileOwnerSid))
        {
            return $"it is owned by {Describe(fileOwnerSid)}, not by SYSTEM or Administrators";
        }

        if (!Administrative.Contains(folderOwnerSid))
        {
            return $"its folder is owned by {Describe(folderOwnerSid)}, not by SYSTEM or Administrators";
        }

        foreach (var entry in fileEntries)
        {
            if (Grants(entry, ModifyingFile))
            {
                return $"{Describe(entry.Sid)} can modify it";
            }
        }

        return FolderProblem(folderOwnerSid, folderEntries);
    }

    /// <summary>Why a policy folder cannot hold a trusted policy, or null when it can. Pure.</summary>
    public static string? FolderProblem(string folderOwnerSid, IEnumerable<AccessEntry> folderEntries)
    {
        if (!Administrative.Contains(folderOwnerSid))
        {
            return $"its folder is owned by {Describe(folderOwnerSid)}, not by SYSTEM or Administrators";
        }

        foreach (var entry in folderEntries)
        {
            if (Grants(entry, ModifyingFolder))
            {
                return $"{Describe(entry.Sid)} can add, delete or re-permission files in its folder";
            }
        }

        return null;
    }

    /// <summary>
    /// Judges an opened policy file and its folder. The file's owner and entries come from the open
    /// handle; the folder's from the folder, which is also checked for being a link.
    /// </summary>
    public static string? Problem(FileStream file, string folder)
    {
        if (IsLink(folder))
        {
            return "its folder is a link";
        }

        if (AncestryProblem(folder) is { } ancestry)
        {
            return ancestry;
        }

        var fileSecurity = file.GetAccessControl();
        var folderSecurity = new DirectoryInfo(folder).GetAccessControl();

        return Problem(
            OwnerOf(fileSecurity), Entries(fileSecurity), OwnerOf(folderSecurity), Entries(folderSecurity));
    }

    /// <summary>Whether a folder, as it is on disk, may hold a trusted policy.</summary>
    public static string? FolderProblem(string folder)
    {
        if (IsLink(folder))
        {
            return "it is a link";
        }

        var security = new DirectoryInfo(folder).GetAccessControl();
        return FolderProblem(OwnerOf(security), Entries(security));
    }

    /// <summary>
    /// Why the folders above the policy folder would let someone else move it out of the way, or null.
    /// </summary>
    /// <remarks>
    /// A file can be perfectly protected and still be made to disappear by renaming a folder above it.
    /// <c>%ProgramData%\SplitLane</c> in particular is created by whichever process gets there first,
    /// and a folder a user creates there is theirs: owned by them and, through the inherited CREATOR
    /// OWNER entry, fully controlled by them - rename included. So every folder from the policy
    /// folder's parent up to the root of the volume must be owned by an administrative principal and
    /// grant nobody else the right to delete, rename, re-permission or take it, or to delete what is
    /// in it.
    /// </remarks>
    public static string? AncestryProblem(string folder)
    {
        var current = Path.GetDirectoryName(Path.GetFullPath(folder));

        while (!string.IsNullOrEmpty(current))
        {
            if (Directory.Exists(current))
            {
                if (IsLink(current))
                {
                    return $"{current} is a link";
                }

                var security = new DirectoryInfo(current).GetAccessControl();
                var owner = OwnerOf(security);
                if (!Administrative.Contains(owner) && !IsVolumeRoot(current))
                {
                    return $"{current} is owned by {Describe(owner)}, who could move the policy out of the way";
                }

                foreach (var entry in Entries(security))
                {
                    if (Grants(entry, ModifyingAncestor))
                    {
                        return $"{Describe(entry.Sid)} could move the policy out of the way through {current}";
                    }
                }
            }

            current = Path.GetDirectoryName(current);
        }

        return null;
    }

    /// <summary>Rights on a folder above the policy that let someone move what is below it.</summary>
    private const FileSystemRights ModifyingAncestor =
        FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
        FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    /// <summary>A drive root, whose owner varies by how the volume was made and cannot be renamed.</summary>
    private static bool IsVolumeRoot(string path) => Path.GetPathRoot(path) is { } root &&
        string.Equals(root.TrimEnd('\\'), path.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);

    /// <summary>Whether a path is a junction or symbolic link, judged without following it.</summary>
    public static bool IsLink(string path) =>
        (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;

    private static bool Grants(AccessEntry entry, FileSystemRights rights) =>
        entry.Allow && !Administrative.Contains(entry.Sid) &&
        ((entry.Rights & rights) != 0 || ((int)entry.Rights & GenericModifying) != 0);

    private static string OwnerOf(FileSystemSecurity security) =>
        security.GetOwner(typeof(SecurityIdentifier))?.Value ?? string.Empty;

    private static IEnumerable<AccessEntry> Entries(FileSystemSecurity security)
    {
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            // An inherit-only entry applies to children, not to this object.
            if (rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly))
            {
                continue;
            }

            yield return new AccessEntry(
                rule.IdentityReference.Value, rule.FileSystemRights, rule.AccessControlType == AccessControlType.Allow);
        }
    }

    private static string Describe(string sid)
    {
        try
        {
            return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value;
        }
        catch (Exception ex) when (ex is IdentityNotMappedException or ArgumentException or SystemException)
        {
            return sid;
        }
    }
}

/// <summary>
/// Reads the machine's managed policy, and says when it changes.
/// </summary>
/// <remarks>
/// A change is picked up by watching the folder, so a rule an administrator removes is revoked within a
/// second or two rather than at the next restart. The watcher is a hint, not a source of truth: every
/// change re-reads and re-judges the whole file.
/// </remarks>
public sealed class PolicyStore : IDisposable
{
    private const string LogCategory = "policy";

    /// <summary>The largest policy read. A real one is a few kilobytes.</summary>
    private const long MaxPolicyBytes = 1024 * 1024;

    private readonly Func<FileStream, string, string?> _trust;
    private FileSystemWatcher? _watcher;
    private Timer? _debounce;

    /// <summary>A store over the standard location.</summary>
    public PolicyStore()
        : this(SplitLanePaths.PolicyFile, PolicyFileTrust.Problem)
    {
    }

    /// <summary>A store over an explicit location and trust check. Used by tests and <c>--explain</c>.</summary>
    internal PolicyStore(string path, Func<FileStream, string, string?> trust, bool verifyAbsence = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        PolicyPath = path;
        _trust = trust ?? throw new ArgumentNullException(nameof(trust));
        _verifyAbsence = verifyAbsence;
    }

    private readonly bool _verifyAbsence;

    /// <summary>Where the policy is read from.</summary>
    public string PolicyPath { get; }

    /// <summary>Raised, debounced, when something in the policy folder changes.</summary>
    public event Action? Changed;

    /// <summary>Reads and judges the policy file.</summary>
    /// <remarks>
    /// One open, sharing read only, so the file cannot change between being judged and being read; its
    /// owner and permissions are taken from that handle.
    /// </remarks>
    public PolicyLoad Load()
    {
        var folder = Path.GetDirectoryName(PolicyPath)!;

        if (!File.Exists(PolicyPath))
        {
            // Gone is only gone if nobody but an administrator could have made it so.
            string? ancestry = null;
            if (_verifyAbsence)
            {
                ancestry = Directory.Exists(folder) ? PolicyFileTrust.FolderProblem(folder) : null;
                ancestry ??= PolicyFileTrust.AncestryProblem(folder);
            }

            return ancestry is null
                ? PolicyLoad.Absent(PolicyPath)
                : new PolicyLoad(null, PolicyState.None, $"no policy at {PolicyPath}, but {ancestry}", AbsenceVerified: false);
        }

        try
        {
            if (PolicyFileTrust.IsLink(PolicyPath))
            {
                return new PolicyLoad(null, PolicyState.Rejected, $"{PolicyPath} was not used: it is a link");
            }

            using var stream = new FileStream(PolicyPath, FileMode.Open, FileAccess.Read, FileShare.Read);

            if (_trust(stream, folder) is { } problem)
            {
                return new PolicyLoad(null, PolicyState.Rejected, $"{PolicyPath} was not used: {problem}");
            }

            if (stream.Length > MaxPolicyBytes)
            {
                return new PolicyLoad(null, PolicyState.Rejected, $"{PolicyPath} was not used: it is larger than {MaxPolicyBytes} bytes");
            }

            using var reader = new StreamReader(stream, Encoding.UTF8);
            var policy = PolicyMerger.Decode(reader.ReadToEnd());
            return new PolicyLoad(policy, PolicyState.Applied, $"{policy.Rules.Count} managed rules from {PolicyPath}");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                       System.Text.Json.JsonException or ConfigurationValidationException or
                                       InvalidOperationException)
        {
            return new PolicyLoad(null, PolicyState.Rejected, $"{PolicyPath} could not be read: {ex.Message}");
        }
    }

    /// <summary>
    /// Makes sure the policy folder exists, owned by Administrators and writable by SYSTEM and
    /// Administrators only. Run by the service, as SYSTEM.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Created with inheritance cut, because the folder above grants every user write access, and with
    /// no entry for users at all: the engine is the only reader, and a user who could open the file
    /// could hold it open without sharing and make every read of it fail.
    /// </para>
    /// <para>
    /// A folder that already exists and does not meet that - one a user created before the service
    /// first ran, or one an administrator made by hand and that inherited the tree's permissions - has
    /// its owner and permissions reset. Files a user put in it keep their owner and are refused when
    /// read. A folder that is a link is left alone and reported; every read of a policy through it is
    /// refused anyway.
    /// </para>
    /// </remarks>
    public void EnsureFolder()
    {
        var folder = Path.GetDirectoryName(PolicyPath)!;
        SecureRoot(Path.GetDirectoryName(folder)!);

        if (Directory.Exists(folder))
        {
            if (PolicyFileTrust.IsLink(folder))
            {
                SplitLaneLog.Error(LogCategory, $"{folder} is a link; no policy will be read through it");
                return;
            }

            if (PolicyFileTrust.FolderProblem(folder) is not { } problem)
            {
                return;
            }

            new DirectoryInfo(folder).SetAccessControl(AdministratorsOnly());
            SplitLaneLog.Warning(LogCategory, $"{folder} was not safe to hold a policy ({problem}); its owner and permissions were reset");
            return;
        }

        new DirectoryInfo(folder).Create(AdministratorsOnly());
        SplitLaneLog.Info(LogCategory, $"created {folder}, accessible to SYSTEM and Administrators only");
    }

    /// <summary>
    /// Gives the SplitLane state folder an administrative owner and the permissions it would have had
    /// if the service had created it, when someone else created it first.
    /// </summary>
    /// <remarks>
    /// The app writes the user's configuration here, so users keep read and create access, and the
    /// files they create stay theirs through CREATOR OWNER. What they lose is ownership of - and so
    /// the ability to rename or re-permission - the folder itself, which is what the policy folder
    /// inside it relies on.
    /// </remarks>
    private static void SecureRoot(string root)
    {
        if (!Directory.Exists(root) || PolicyFileTrust.IsLink(root))
        {
            return;
        }

        var security = new DirectoryInfo(root).GetAccessControl();
        var owner = security.GetOwner(typeof(SecurityIdentifier))?.Value ?? string.Empty;
        var fine = owner is "S-1-5-18" or "S-1-5-32-544" &&
                   PolicyFileTrust.AncestryProblem(Path.Combine(root, "x")) is null;

        if (fine)
        {
            return;
        }

        var repaired = new DirectorySecurity();
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        const InheritanceFlags Both = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

        repaired.SetOwner(administrators);
        repaired.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        repaired.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, Both, PropagationFlags.None, AccessControlType.Allow));
        repaired.AddAccessRule(new FileSystemAccessRule(
            administrators, FileSystemRights.FullControl, Both, PropagationFlags.None, AccessControlType.Allow));
        repaired.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.CreatorOwnerSid, null), FileSystemRights.FullControl, Both, PropagationFlags.InheritOnly, AccessControlType.Allow));
        repaired.AddAccessRule(new FileSystemAccessRule(
            users, FileSystemRights.ReadAndExecute, Both, PropagationFlags.None, AccessControlType.Allow));
        repaired.AddAccessRule(new FileSystemAccessRule(
            users, FileSystemRights.CreateFiles | FileSystemRights.CreateDirectories | FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes,
            InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));

        new DirectoryInfo(root).SetAccessControl(repaired);
        SplitLaneLog.Warning(LogCategory, $"{root} was not owned and permissioned as the service would have made it; it has been reset");
    }

    private static DirectorySecurity AdministratorsOnly()
    {
        var security = new DirectorySecurity();
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

        security.SetOwner(administrators);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        foreach (var sid in new[] { new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), administrators })
        {
            security.AddAccessRule(new FileSystemAccessRule(
                sid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        }

        return security;
    }

    /// <summary>Starts watching the policy folder. Idempotent; a folder that does not exist is not watched.</summary>
    public void Watch()
    {
        var folder = Path.GetDirectoryName(PolicyPath)!;
        if (_watcher is not null || !Directory.Exists(folder))
        {
            return;
        }

        _debounce = new Timer(_ => Changed?.Invoke(), null, Timeout.Infinite, Timeout.Infinite);
        _watcher = new FileSystemWatcher(folder, Path.GetFileName(PolicyPath))
        {
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.Security,
        };

        FileSystemEventHandler onChange = (_, _) => _debounce?.Change(TimeSpan.FromMilliseconds(500), Timeout.InfiniteTimeSpan);
        _watcher.Changed += onChange;
        _watcher.Created += onChange;
        _watcher.Deleted += onChange;
        _watcher.Renamed += (_, _) => _debounce?.Change(TimeSpan.FromMilliseconds(500), Timeout.InfiniteTimeSpan);
        _watcher.EnableRaisingEvents = true;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _watcher?.Dispose();
        _debounce?.Dispose();
        _watcher = null;
        _debounce = null;
    }
}
