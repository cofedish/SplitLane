using System.Text.Json;
using System.Text.Json.Serialization;
using SplitLane.Core.Models;

namespace SplitLane.Core.Configuration;

/// <summary>
/// The one place configuration and IPC turn into bytes.
/// </summary>
/// <remarks>
/// <para>
/// Centralised so the serialiser options are identical everywhere. The app writes configuration, the
/// engine reads it, and both exchange IPC messages over the same pipe; three different
/// <c>JsonSerializerOptions</c> would be three chances for an enum to round-trip as a number in one
/// direction and a string in the other.
/// </para>
/// <para>
/// Enums are written as strings on purpose. A stored configuration outlives the build that wrote it,
/// and inserting a new member into <see cref="RouteAction"/> must not silently reinterpret every
/// stored rule.
/// </para>
/// </remarks>
public static class ConfigurationCodec
{
    /// <summary>Serialiser options shared by configuration storage and IPC.</summary>
    public static JsonSerializerOptions Options { get; } = CreateOptions(indented: false);

    /// <summary>Options for the on-disk file, which a human is expected to read occasionally.</summary>
    public static JsonSerializerOptions FileOptions { get; } = CreateOptions(indented: true);

    private static JsonSerializerOptions CreateOptions(bool indented) => new()
    {
        WriteIndented = indented,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
        // A configuration carrying a field this build does not know about was written by a newer
        // build. The schema check rejects it explicitly with a message the user can act on, which is
        // better than a serialiser exception — but the strict setting stays on so a typo in a
        // hand-edited file is reported rather than silently ignored.
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    /// <summary>Encodes a configuration for storage.</summary>
    public static string EncodeToJson(RuntimeConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        return JsonSerializer.Serialize(configuration, FileOptions);
    }

    /// <summary>
    /// Decodes a configuration, validating the schema version before anything else.
    /// </summary>
    /// <remarks>
    /// The version check happens first and separately: a configuration from a newer build must be
    /// refused with a clear message rather than partially deserialised into a shape this build
    /// misunderstands.
    /// </remarks>
    public static RuntimeConfiguration DecodeFromJson(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);

        var probed = JsonSerializer.Deserialize<SchemaProbe>(json, PermissiveProbeOptions);
        if (probed?.Version is { } version && !version.IsReadable)
        {
            throw new ConfigurationValidationException(
                ConfigurationValidationCode.UnsupportedSchemaVersion,
                $"Configuration schema version {version.SchemaVersion} is newer than the supported " +
                $"version {ConfigurationVersion.CurrentSchema}");
        }

        var configuration = JsonSerializer.Deserialize<RuntimeConfiguration>(json, Options)
            ?? throw new ConfigurationValidationException(
                ConfigurationValidationCode.EmptyExecutablePath, "Configuration document was empty");

        return configuration;
    }

    /// <summary>Reads only the version stamp, tolerating fields this build does not know.</summary>
    private static JsonSerializerOptions PermissiveProbeOptions { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Skip,
    };

    private sealed record SchemaProbe(ConfigurationVersion? Version);
}
