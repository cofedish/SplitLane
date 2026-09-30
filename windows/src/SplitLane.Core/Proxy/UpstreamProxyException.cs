using System.Globalization;
using System.Text;
using SplitLane.Core.Models;

namespace SplitLane.Core.Proxy;

/// <summary>
/// A connection to the upstream that could not be made, for either protocol.
/// </summary>
/// <remarks>
/// <para>
/// Carries what support needs to act without a packet capture: the stage, the proxy, the
/// destination, how long it took, the operating system's error, the HTTP status and the
/// authentication scheme. None of those is secret. What it never carries is the credential or any
/// header that encodes it - there is no field for one, and the messages are built from the fields.
/// </para>
/// <para>
/// <see cref="Category"/> is the closed vocabulary the Activity list shows; <see cref="Describe"/> is
/// the full sentence for the log and the proxy test.
/// </para>
/// </remarks>
public sealed class UpstreamProxyException : Exception
{
    /// <summary>Builds a failure.</summary>
    public UpstreamProxyException(
        ConnectionErrorCategory category,
        UpstreamStage stage,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        Category = category;
        Stage = stage;
    }

    /// <summary>What went wrong, as the UI groups it.</summary>
    public ConnectionErrorCategory Category { get; }

    /// <summary>Where it went wrong.</summary>
    public UpstreamStage Stage { get; }

    /// <summary>Which protocol was being spoken.</summary>
    public ProxyProtocolType Protocol { get; init; }

    /// <summary>The proxy, as <c>host:port</c>.</summary>
    public string? Endpoint { get; init; }

    /// <summary>Where the tunnel was meant to go, as <c>host:port</c>.</summary>
    public string? Destination { get; init; }

    /// <summary>From the start of the attempt to the failure.</summary>
    public double ElapsedMilliseconds { get; init; }

    /// <summary>The HTTP status the proxy answered with, when it answered.</summary>
    public int? StatusCode { get; init; }

    /// <summary>The authentication scheme in use or on offer, when there was one.</summary>
    public string? AuthenticationScheme { get; init; }

    /// <summary>The socket error, when the operating system reported one.</summary>
    public string? OsError { get; init; }

    /// <summary>
    /// Whether retrying could plausibly succeed. Used for the log level, never to send a selected
    /// application DIRECT instead (ADR 0003).
    /// </summary>
    public bool IsTransient => Category is ConnectionErrorCategory.TimedOut
        or ConnectionErrorCategory.UpstreamUnreachable
        or ConnectionErrorCategory.DestinationUnreachable;

    /// <summary>
    /// One line with everything known about the failure, safe to log and to show.
    /// </summary>
    public string Describe()
    {
        var text = new StringBuilder();
        text.Append(Stage.LogName()).Append(" failed: ").Append(Message);
        text.Append(" [").Append(Protocol.DisplayName());

        if (Endpoint is not null)
        {
            text.Append(" proxy ").Append(Endpoint);
        }

        if (Destination is not null)
        {
            text.Append(", destination ").Append(Destination);
        }

        text.Append(", ").Append(ElapsedMilliseconds.ToString("F0", CultureInfo.InvariantCulture)).Append(" ms");

        if (StatusCode is { } status)
        {
            text.Append(", HTTP ").Append(status.ToString(CultureInfo.InvariantCulture));
        }

        if (AuthenticationScheme is not null)
        {
            text.Append(", scheme ").Append(AuthenticationScheme);
        }

        if (OsError is not null)
        {
            text.Append(", os ").Append(OsError);
        }

        return text.Append(']').ToString();
    }

    /// <inheritdoc />
    public override string ToString() => $"{Category}: {Describe()}";
}
