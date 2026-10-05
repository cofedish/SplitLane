using System.Security.AccessControl;
using System.Security.Principal;

namespace SplitLane.Engine.Runtime;

/// <summary>What ordinary users may do in a <see cref="ProtectedDirectory"/>.</summary>
public enum UserAccess
{
    /// <summary>Nothing at all: not list it, not read what is in it.</summary>
    None,

    /// <summary>List it and read its files. Never create, change, rename or delete anything.</summary>
    Read,
}

/// <summary>Why a directory the service writes to could not be made trustworthy.</summary>
public sealed class UnsafeDirectoryException : IOException
{
    /// <summary>Builds the exception.</summary>
    public UnsafeDirectoryException(string message)
        : base(message)
    {
    }

    /// <summary>Builds the exception.</summary>
    public UnsafeDirectoryException(string message, Exception inner)
        : base(message, inner)
    {
    }
}

/// <summary>
/// A directory that only the service (and administrators) can write to, made so before anything is
/// written into it.
/// </summary>
/// <remarks>
/// <para>
/// <c>%ProgramData%\SplitLane</c> grants every user the right to create files and folders, because
/// the unelevated app writes the user's configuration there (SL-SEC-001, SL-SEC-007). Anything the
/// LocalSystem engine writes must therefore live in a sub-directory whose permissions it set itself,
/// at creation, with inheritance cut - otherwise a user can create the folder first, own it, and put a
/// junction, a pre-made file or a hard link where the service is about to write.
/// </para>
/// <para>
/// A directory that exists and is not trustworthy is moved aside and replaced, never repaired in
/// place. Re-permissioning it would not be enough: a handle someone opened while they still had write
/// access keeps that access after the permissions change, and files they already created stay theirs.
/// A fresh directory created with its security descriptor in the same call has no such history.
/// </para>
/// <para>
/// Nothing here follows a link. A junction or symbolic link at the path, or at any folder above it, is
/// refused (the path) or reported (an ancestor) rather than resolved.
/// </para>
/// </remarks>
public sealed class ProtectedDirectory
{
    private const int CreateAttempts = 3;

    /// <summary>Rights that let a principal put a different object into the directory or take it over.</summary>
    private const FileSystemRights Modifying =
        FileSystemRights.WriteData | FileSystemRights.AppendData |
        FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.Delete |
        FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership |
        FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes;

    /// <summary>GENERIC_ALL and GENERIC_WRITE in a raw mask.</summary>
    private const int GenericModifying = 0x10000000 | 0x40000000;

    private readonly IReadOnlyList<SecurityIdentifier> _writers;
    private readonly HashSet<string> _trusted;
    private readonly bool _checkAncestry;

    /// <summary>
    /// A directory writable by SYSTEM and Administrators only - what the service uses.
    /// </summary>
    public ProtectedDirectory(string path, UserAccess users)
        : this(
            path,
            users,
            [new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
             new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null)],
            checkAncestry: true)
    {
    }

    /// <summary>
    /// A directory writable by an explicit set of principals. Tests run unelevated and cannot create
    /// anything owned by SYSTEM, so they name their own account here; the rules applied are the same.
    /// </summary>
    internal ProtectedDirectory(
        string path, UserAccess users, IReadOnlyList<SecurityIdentifier> writers, bool checkAncestry)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(writers);
        if (writers.Count == 0)
        {
            throw new ArgumentException("At least one writer is required.", nameof(writers));
        }

        Path = System.IO.Path.GetFullPath(path);
        Users = users;
        _writers = writers;
        _checkAncestry = checkAncestry;

        _trusted = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "S-1-5-18",      // LocalSystem
            "S-1-5-32-544",  // BUILTIN\Administrators
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", // TrustedInstaller
        };

        foreach (var writer in writers)
        {
            _trusted.Add(writer.Value);
        }
    }

    /// <summary>The directory.</summary>
    public string Path { get; }

    /// <summary>What ordinary users may do in it.</summary>
    public UserAccess Users { get; }

    /// <summary>
    /// Makes sure the directory exists and is trustworthy, and returns its path.
    /// </summary>
    /// <exception cref="UnsafeDirectoryException">
    /// It could not be made trustworthy - a folder above it can be manipulated by someone else, or
    /// something kept replacing it. Callers must not write into it.
    /// </exception>
    public string Ensure()
    {
        if (_checkAncestry && PolicyFileTrust.AncestryProblem(Path) is { } ancestry)
        {
            throw new UnsafeDirectoryException($"{Path} cannot be protected: {ancestry}");
        }

        for (var attempt = 0; attempt < CreateAttempts; attempt++)
        {
            if (Exists(Path))
            {
                if (Problem(Path) is not { } problem)
                {
                    return Path;
                }

                Quarantine(Path, problem);
            }

            try
            {
                // The security descriptor goes in with the creation itself: there is no instant at
                // which the directory exists with the inherited, user-writable permissions.
                new DirectoryInfo(Path).Create(Descriptor());
            }
            catch (IOException) when (Exists(Path))
            {
                // Somebody else created it in between. Judged again on the next pass.
            }

            if (Exists(Path) && Problem(Path) is null)
            {
                return Path;
            }
        }

        throw new UnsafeDirectoryException(
            $"{Path} could not be created with protected permissions; something keeps replacing it");
    }

    /// <summary>
    /// Creates a new, uniquely named directory inside this one with the same protection, and returns
    /// its path. The name is random, so nobody can prepare anything under it in advance.
    /// </summary>
    public string CreateUniqueChild(string prefix)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(prefix);
        Ensure();

        for (var attempt = 0; attempt < CreateAttempts; attempt++)
        {
            var child = System.IO.Path.Combine(Path, $"{prefix}-{Guid.NewGuid():N}");

            if (Exists(child))
            {
                continue;
            }

            new DirectoryInfo(child).Create(Descriptor());

            if (Problem(child) is null)
            {
                return child;
            }
        }

        throw new UnsafeDirectoryException($"no protected directory could be created under {Path}");
    }

    /// <summary>Why a directory is not trustworthy, or null when it is.</summary>
    public string? Problem(string directory)
    {
        var attributes = File.GetAttributes(directory);

        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            return "it is a link";
        }

        if ((attributes & FileAttributes.Directory) == 0)
        {
            return "it is not a directory";
        }

        var security = new DirectoryInfo(directory).GetAccessControl();
        var owner = security.GetOwner(typeof(SecurityIdentifier))?.Value ?? string.Empty;

        if (!_trusted.Contains(owner))
        {
            return $"it is owned by {owner}";
        }

        if (!security.AreAccessRulesProtected)
        {
            return "it inherits permissions from the folder above";
        }

        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow || _trusted.Contains(rule.IdentityReference.Value))
            {
                continue;
            }

            if ((rule.FileSystemRights & Modifying) != 0 || ((int)rule.FileSystemRights & GenericModifying) != 0)
            {
                return $"{rule.IdentityReference.Value} may change what is in it";
            }

            if (Users == UserAccess.None)
            {
                return $"{rule.IdentityReference.Value} may read it";
            }
        }

        return null;
    }

    /// <summary>The security descriptor every protected directory is created with.</summary>
    internal DirectorySecurity Descriptor()
    {
        const InheritanceFlags Both = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        foreach (var writer in _writers)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                writer, FileSystemRights.FullControl, Both, PropagationFlags.None, AccessControlType.Allow));
        }

        if (Users == UserAccess.Read)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                FileSystemRights.ReadAndExecute, Both, PropagationFlags.None, AccessControlType.Allow));
        }

        return security;
    }

    private static bool Exists(string path)
    {
        // A dangling link is "there" for our purposes, and Directory.Exists would say it is not.
        try
        {
            _ = File.GetAttributes(path);
            return true;
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return false;
        }
    }

    /// <summary>
    /// Moves an untrustworthy directory out of the way. A link is renamed, not followed, so nothing it
    /// points at is touched.
    /// </summary>
    private static void Quarantine(string path, string problem)
    {
        var aside = $"{path}.untrusted-{Guid.NewGuid():N}";

        try
        {
            Directory.Move(path, aside);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new UnsafeDirectoryException($"{path} is not safe ({problem}) and could not be moved aside", ex);
        }

        Core.Logging.SplitLaneLog.Warning("paths", $"{path} was not safe for the service ({problem}); moved aside to {aside}");
    }
}
