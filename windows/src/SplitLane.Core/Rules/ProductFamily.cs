using System.Text;

namespace SplitLane.Core.Rules;

/// <summary>
/// The product half of a signed application's family, and the products too widely shared to be one.
/// </summary>
/// <remarks>
/// <para>
/// "Include helpers" on a signed application covers the same publisher's binaries that carry the
/// same product name. That is the signed counterpart of ADR W-0003's install directory, and it has the
/// same hazard: some product names belong to a platform that hosts other people's applications rather
/// than to an application. Every binary in <c>System32</c> is "Microsoft® Windows® Operating System";
/// every Electron application that did not rename itself is "Electron". A family on one of those would
/// put everything built on the platform into the proxy lane.
/// </para>
/// <para>
/// So those names are refused for product matching, exactly as <c>System32</c> is refused as a family
/// root. The rule still matches its own binary, and the install-directory family still applies where
/// the directory is safe.
/// </para>
/// </remarks>
public static class ProductFamily
{
    /// <summary>Product names that belong to a platform or runtime, normalised.</summary>
    private static readonly HashSet<string> SharedProducts = new(StringComparer.Ordinal)
    {
        "MICROSOFT WINDOWS OPERATING SYSTEM",
        "WINDOWS OPERATING SYSTEM",
        "MICROSOFT .NET",
        "MICROSOFT .NET FRAMEWORK",
        ".NET",
        "MICROSOFT EDGE WEBVIEW2",
        "WINDOWS POWERSHELL",
        "POWERSHELL",
        "ELECTRON",
        "CHROMIUM",
        "NODE.JS",
        "OPENJDK PLATFORM BINARY",
        "JAVA PLATFORM SE BINARY",
        "PYTHON",
    };

    /// <summary>
    /// A product name in comparable form: trademark signs removed, whitespace collapsed, upper case.
    /// </summary>
    public static string Normalize(string? productName)
    {
        if (string.IsNullOrWhiteSpace(productName))
        {
            return string.Empty;
        }

        var text = productName
            .Replace("®", string.Empty, StringComparison.Ordinal)
            .Replace("™", string.Empty, StringComparison.Ordinal)
            .Replace("(R)", string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace("(TM)", string.Empty, StringComparison.OrdinalIgnoreCase);

        var builder = new StringBuilder(text.Length);
        var pendingSpace = false;

        foreach (var character in text.Trim())
        {
            if (char.IsWhiteSpace(character))
            {
                pendingSpace = true;
                continue;
            }

            if (pendingSpace && builder.Length > 0)
            {
                builder.Append(' ');
            }

            pendingSpace = false;
            builder.Append(char.ToUpperInvariant(character));
        }

        return builder.ToString();
    }

    /// <summary>
    /// Common names of the certificates Windows itself is signed with, canonical form.
    /// </summary>
    /// <remarks>
    /// The product-name list alone is not enough, and a machine with a Russian display language
    /// showed why: <c>notepad.exe</c> reports its product as "Операционная система Microsoft®
    /// Windows®", because the version strings of Windows components are localised. No list of names
    /// can keep up with every language, so the operating system is recognised by who signed it
    /// instead, and no product family is ever rooted in what those certificates sign.
    /// </remarks>
    private static readonly HashSet<string> PlatformSigners = new(StringComparer.Ordinal)
    {
        "MICROSOFT WINDOWS",
        "MICROSOFT WINDOWS PUBLISHER",
        "MICROSOFT WINDOWS THIRD PARTY APPLICATION COMPONENT",
        "MICROSOFT 3RD PARTY APPLICATION COMPONENT",
        "MICROSOFT WINDOWS HARDWARE COMPATIBILITY PUBLISHER",
    };

    /// <summary>Whether two product names are the same product.</summary>
    public static bool Same(string? left, string? right) =>
        Normalize(left).Equals(Normalize(right), StringComparison.Ordinal);

    /// <summary>
    /// Whether a product name can root a family: present, not a platform shared by other applications,
    /// and not signed by one of the certificates the operating system itself is signed with.
    /// </summary>
    /// <param name="productName">The product name from the version resource.</param>
    /// <param name="signerSubject">The canonical signer key (<see cref="PublisherName"/>), when known.</param>
    public static bool CanRootFamily(string? productName, string? signerSubject = null)
    {
        var normalized = Normalize(productName);
        if (normalized.Length == 0 || SharedProducts.Contains(normalized))
        {
            return false;
        }

        return PublisherName.CommonNameOf(signerSubject) is not { } commonName ||
               !PlatformSigners.Contains(commonName);
    }
}
