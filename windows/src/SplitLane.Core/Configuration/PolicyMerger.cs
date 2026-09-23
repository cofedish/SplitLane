using System.Text.Json;
using SplitLane.Core.Models;

namespace SplitLane.Core.Configuration;

/// <summary>The configuration the engine routes by, and what the policy did to produce it.</summary>
/// <param name="Effective">User configuration with the policy applied on top.</param>
/// <param name="Notes">Managed rules that were ignored, and why. For the log and for support.</param>
/// <param name="ManagedRuleCount">Managed rules in force.</param>
/// <param name="UserRulesDropped">User rules left out: disallowed, or for an application the policy governs.</param>
public sealed record PolicyOutcome(
    RuntimeConfiguration Effective,
    IReadOnlyList<string> Notes,
    int ManagedRuleCount,
    int UserRulesDropped);

/// <summary>
/// Puts a managed policy on top of a user's configuration.
/// </summary>
/// <remarks>
/// <para>
/// Precedence is structural rather than a matter of rule ordering: managed rules are marked
/// <see cref="AppRule.IsManaged"/> and the snapshot looks them up before it looks at anything else, so
/// no user rule - however specific - can send a governed application somewhere the policy did not.
/// A user rule for the very same application is dropped outright rather than left to lose, so that what
/// the user sees listed is what applies.
/// </para>
/// <para>
/// Pure. Reading the policy file, and deciding whether its owner and permissions make it worth
/// reading, is the engine's job.
/// </para>
/// </remarks>
public static class PolicyMerger
{
    /// <summary>Applies a policy, or returns the user configuration unchanged when there is none.</summary>
    public static PolicyOutcome Merge(RuntimeConfiguration user, ManagedPolicy? policy)
    {
        ArgumentNullException.ThrowIfNull(user);

        if (policy is null)
        {
            return new PolicyOutcome(user, [], 0, 0);
        }

        var notes = new List<string>();
        var managed = new List<AppRule>(policy.Rules.Count);
        var governed = new HashSet<string>(StringComparer.Ordinal);

        foreach (var rule in policy.Rules)
        {
            var name = rule.Identity.DisplayName;

            if (!rule.Identity.IsVerified)
            {
                notes.Add($"managed rule '{name}' ignored: it names a path, which differs from machine to " +
                          "machine and changes on update; a managed rule must name a signed identity, a " +
                          "package family or a file hash (use SplitLane.Engine.exe --describe)");
                continue;
            }

            if (ConfigurationValidator.IncompleteIdentity(rule.Identity) is { } missing)
            {
                notes.Add($"managed rule '{name}' ignored: its identity has no {missing}");
                continue;
            }

            if (!governed.Add(rule.Identity.MatchKey))
            {
                notes.Add($"managed rule '{name}' ignored: another managed rule already covers that application");
                continue;
            }

            // Only a validator's corrections apply to a managed rule. Its lane and scope are the
            // administrator's; whether it is active is not the user's to toggle.
            var sanitized = ConfigurationValidator.Sanitize(new RuntimeConfiguration { Rules = [rule] }).Rules;
            if (sanitized.Count == 0)
            {
                notes.Add($"managed rule '{name}' ignored: its recorded path is not an absolute Windows path");
                continue;
            }

            managed.Add(sanitized[0] with { IsManaged = true, Status = RuleStatus.Active, StatusDetail = null });
        }

        // A managed rule for a whole package governs every binary in it, whatever the user's rule for
        // one of them says; such a rule could never fire, so it is left out rather than listed.
        var governedPackages = new HashSet<string>(
            managed.Where(rule => rule.Identity.Kind == IdentityKind.Package && rule.MatchMode != MatchMode.Exact)
                   .Select(rule => rule.Identity.PackageFamilyName!),
            StringComparer.OrdinalIgnoreCase);

        var userRules = new List<AppRule>(user.Rules.Count);
        var dropped = 0;

        foreach (var rule in user.Rules)
        {
            var packageGoverned = rule.Identity.Kind == IdentityKind.Package &&
                                  rule.Identity.PackageFamilyName is { } family &&
                                  governedPackages.Contains(family);

            if (!policy.AllowUserRules || packageGoverned || governed.Contains(rule.Identity.MatchKey))
            {
                dropped++;
                continue;
            }

            userRules.Add(rule with { IsManaged = false });
        }

        // A managed PROXY rule sends its application wherever the user's proxy points, when the policy
        // does not say where. A user who points it at a forwarder of their own has made the rule a
        // DIRECT one. Reported every time, because it is the one thing an administrator must decide.
        if (policy.Proxy is null && managed.Any(rule => rule.Action == RouteAction.Proxy))
        {
            notes.Add("managed PROXY rules use the proxy the user configured, because the policy sets no " +
                      "proxy; set \"proxy\" in the policy if the upstream must be the organisation's");
        }

        var effective = user with
        {
            Rules = [.. managed, .. userRules],
            IsRoutingEnabled = policy.ForceRoutingEnabled || user.IsRoutingEnabled,
            Proxy = policy.Proxy ?? user.Proxy,
        };

        return new PolicyOutcome(effective, notes, managed.Count, dropped);
    }

    /// <summary>
    /// Decodes a policy document, refusing one from a newer build and any field this build does not know.
    /// </summary>
    public static ManagedPolicy Decode(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);

        using (var document = JsonDocument.Parse(json))
        {
            if (document.RootElement.TryGetProperty("schemaVersion", out var version) &&
                version.TryGetInt32(out var schema) &&
                schema > ManagedPolicy.CurrentSchema)
            {
                throw new ConfigurationValidationException(
                    ConfigurationValidationCode.UnsupportedSchemaVersion,
                    $"Policy schema version {schema} is newer than the supported version {ManagedPolicy.CurrentSchema}");
            }
        }

        return JsonSerializer.Deserialize<ManagedPolicy>(json, ConfigurationCodec.Options)
            ?? throw new ConfigurationValidationException(
                ConfigurationValidationCode.EmptyExecutablePath, "Policy document was empty");
    }

    /// <summary>Encodes a policy for an administrator to deploy.</summary>
    public static string Encode(ManagedPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        return JsonSerializer.Serialize(policy, ConfigurationCodec.FileOptions);
    }
}
