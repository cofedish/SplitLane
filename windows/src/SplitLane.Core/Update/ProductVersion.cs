using System.Globalization;

namespace SplitLane.Core.Update;

/// <summary>
/// A product version, and whether one is newer than another.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately not <see cref="System.Version"/>. Versions arrive here from three places that spell
/// them differently - a git tag as <c>v0.6.0</c>, an MSI as <c>0.6.0.0</c>, and an assembly as
/// <c>0.6.0.0</c> - and comparing those with string equality or with a type that treats a missing
/// field as -1 gets "already up to date" wrong in both directions.
/// </para>
/// <para>
/// Missing fields are zero. <c>0.6</c>, <c>0.6.0</c> and <c>0.6.0.0</c> are the same version, which
/// is what everyone means by them.
/// </para>
/// </remarks>
public readonly record struct ProductVersion(int Major, int Minor, int Patch, int Build)
    : IComparable<ProductVersion>
{
    /// <summary>Parses a version, tolerating a leading "v" and fewer than four fields.</summary>
    /// <returns>False when the text is not a version at all.</returns>
    public static bool TryParse(string? text, out ProductVersion version)
    {
        version = default;

        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var trimmed = text.Trim();
        if (trimmed.StartsWith('v') || trimmed.StartsWith('V'))
        {
            trimmed = trimmed[1..];
        }

        var fields = trimmed.Split('.');
        if (fields.Length is 0 or > 4)
        {
            return false;
        }

        Span<int> parsed = stackalloc int[4];

        for (var i = 0; i < fields.Length; i++)
        {
            if (!int.TryParse(fields[i], NumberStyles.None, CultureInfo.InvariantCulture, out var value))
            {
                return false;
            }

            parsed[i] = value;
        }

        version = new ProductVersion(parsed[0], parsed[1], parsed[2], parsed[3]);
        return true;
    }

    /// <summary>Parses a version, or returns the zero version.</summary>
    public static ProductVersion Parse(string? text) =>
        TryParse(text, out var version) ? version : default;

    /// <inheritdoc />
    public int CompareTo(ProductVersion other)
    {
        var major = Major.CompareTo(other.Major);
        if (major != 0)
        {
            return major;
        }

        var minor = Minor.CompareTo(other.Minor);
        if (minor != 0)
        {
            return minor;
        }

        var patch = Patch.CompareTo(other.Patch);
        return patch != 0 ? patch : Build.CompareTo(other.Build);
    }

    /// <summary>Whether this version is newer than another.</summary>
    public bool IsNewerThan(ProductVersion other) => CompareTo(other) > 0;

    /// <inheritdoc />
    public override string ToString() =>
        Build == 0
            ? string.Create(CultureInfo.InvariantCulture, $"{Major}.{Minor}.{Patch}")
            : string.Create(CultureInfo.InvariantCulture, $"{Major}.{Minor}.{Patch}.{Build}");

    public static bool operator <(ProductVersion left, ProductVersion right) => left.CompareTo(right) < 0;

    public static bool operator >(ProductVersion left, ProductVersion right) => left.CompareTo(right) > 0;

    public static bool operator <=(ProductVersion left, ProductVersion right) => left.CompareTo(right) <= 0;

    public static bool operator >=(ProductVersion left, ProductVersion right) => left.CompareTo(right) >= 0;
}
