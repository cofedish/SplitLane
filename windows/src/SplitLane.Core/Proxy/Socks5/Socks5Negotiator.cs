using System.Text;

namespace SplitLane.Core.Proxy.Socks5;

/// <summary>
/// SOCKS5 username/password credential (RFC 1929).
/// </summary>
/// <remarks>
/// Redacts itself in every textual form. A credential must never reach a log, and the cheapest way
/// to guarantee that is to make the accidental interpolation harmless.
/// </remarks>
public sealed class Socks5Credential(string username, string password)
{
    /// <summary>The username. Not a secret.</summary>
    public string Username { get; } = username ?? throw new ArgumentNullException(nameof(username));

    /// <summary>The password.</summary>
    public string Password { get; } = password ?? throw new ArgumentNullException(nameof(password));

    /// <summary>RFC 1929 length-prefixes both fields with a single byte.</summary>
    public bool IsEncodable
    {
        get
        {
            var u = Encoding.UTF8.GetByteCount(Username);
            var p = Encoding.UTF8.GetByteCount(Password);
            return u is >= 1 and <= 255 && p <= 255;
        }
    }

    /// <inheritdoc />
    public override string ToString() => $"Socks5Credential(username: {Username}, password: <redacted>)";
}

/// <summary>What the caller should do next.</summary>
public enum Socks5StepKind
{
    /// <summary>Write <see cref="Socks5Step.Bytes"/> upstream, then feed any reply back in.</summary>
    Send,

    /// <summary>The current message is incomplete; wait for more bytes.</summary>
    NeedMoreBytes,

    /// <summary>The tunnel is open.</summary>
    Established,
}

/// <summary>One instruction from the handshake state machine.</summary>
/// <param name="Kind">What to do.</param>
/// <param name="Bytes">Bytes to send, for <see cref="Socks5StepKind.Send"/>.</param>
/// <param name="Connection">Result, for <see cref="Socks5StepKind.Established"/>.</param>
public readonly record struct Socks5Step(
    Socks5StepKind Kind,
    byte[]? Bytes = null,
    Socks5ConnectionInfo? Connection = null);

/// <summary>Result of a successful CONNECT.</summary>
/// <param name="BoundAddress">The address the proxy bound on our behalf. Informational; most servers return 0.0.0.0.</param>
/// <param name="BoundPort">The port it bound.</param>
/// <param name="Method">Which authentication method the server chose.</param>
/// <param name="LeftoverBytes">
/// Bytes that arrived after the CONNECT reply. A server may coalesce its reply with the first bytes
/// of the relayed stream into one TCP segment. Dropping them looks like a rare, unreproducible
/// truncation of the first response, so they are handed back and prepended to the relay.
/// </param>
public sealed record Socks5ConnectionInfo(
    Socks5Address BoundAddress,
    ushort BoundPort,
    Socks5Method Method,
    byte[] LeftoverBytes);

/// <summary>
/// The SOCKS5 handshake as a pure state machine.
/// </summary>
/// <remarks>
/// No sockets, no queues, no async: bytes in, actions out. That is what makes the protocol
/// exhaustively testable — every truncation offset, every malformed field, every rejection code —
/// with <c>dotnet test</c> and no network at all. <c>Socks5Client</c> in the engine supplies the I/O.
///
/// <para>
/// The negotiator owns an accumulation buffer because TCP is a stream: a two-byte method selection
/// can arrive as two separate one-byte reads, and a CONNECT reply can arrive glued to application
/// data.
/// </para>
/// </remarks>
public sealed class Socks5Negotiator
{
    /// <summary>Where the handshake is.</summary>
    public enum State
    {
        /// <summary>Nothing sent yet.</summary>
        Initial,

        /// <summary>Greeting sent, waiting for the method selection.</summary>
        AwaitingMethodSelection,

        /// <summary>Credentials sent, waiting for the sub-negotiation reply.</summary>
        AwaitingAuthenticationReply,

        /// <summary>CONNECT sent, waiting for the reply.</summary>
        AwaitingConnectReply,

        /// <summary>Tunnel open.</summary>
        Established,

        /// <summary>Terminally failed.</summary>
        Failed,
    }

    private readonly Socks5Address _destination;
    private readonly ushort _port;
    private readonly Socks5Credential? _credential;
    private readonly Socks5Command _command;
    private readonly List<byte> _buffer = [];
    private Socks5Method _selectedMethod = Socks5Method.NoAuthentication;

    /// <summary>
    /// Builds a handshake for one destination.
    /// </summary>
    /// <param name="destination">Where the tunnel goes, or the address datagrams will come from.</param>
    /// <param name="port">Its port.</param>
    /// <param name="credential">Username and password, when the proxy asks for them.</param>
    /// <param name="command">
    /// What to ask the proxy for. <see cref="Socks5Command.Connect"/> opens a tunnel;
    /// <see cref="Socks5Command.UdpAssociate"/> asks for a datagram relay, and the reply's bound
    /// address is then where datagrams are sent rather than a confirmation nobody reads.
    /// </param>
    public Socks5Negotiator(
        Socks5Address destination,
        ushort port,
        Socks5Credential? credential = null,
        Socks5Command command = Socks5Command.Connect)
    {
        _destination = destination;
        _port = port;
        _credential = credential;
        _command = command;
    }

    /// <summary>Current state.</summary>
    public State CurrentState { get; private set; } = State.Initial;

    /// <summary>Produces the client greeting. Must be called exactly once, before <see cref="Receive"/>.</summary>
    public Socks5Step Start()
    {
        if (CurrentState != State.Initial)
        {
            throw Socks5Exception.ProtocolViolation($"Start() called in state {CurrentState}");
        }

        if (_credential is not null && !_credential.IsEncodable)
        {
            CurrentState = State.Failed;
            throw Socks5Exception.CredentialTooLong();
        }

        // Offer username/password only when a credential exists. Offering it unconditionally would
        // invite a server to select it and then be told there is nothing to send.
        var methods = _credential is null
            ? new[] { (byte)Socks5Method.NoAuthentication }
            : [(byte)Socks5Method.NoAuthentication, (byte)Socks5Method.UsernamePassword];

        var greeting = new byte[methods.Length + 2];
        greeting[0] = Socks5.Version;
        greeting[1] = (byte)methods.Length;
        methods.CopyTo(greeting, 2);

        CurrentState = State.AwaitingMethodSelection;
        return new Socks5Step(Socks5StepKind.Send, greeting);
    }

    /// <summary>
    /// Feeds received bytes into the handshake.
    /// </summary>
    /// <remarks>
    /// Safe to call with partial data: whatever cannot be parsed yet stays buffered and
    /// <see cref="Socks5StepKind.NeedMoreBytes"/> is returned.
    /// </remarks>
    public Socks5Step Receive(ReadOnlySpan<byte> incoming)
    {
        if (CurrentState == State.Failed)
        {
            throw Socks5Exception.ProtocolViolation("Receive() after failure");
        }

        if (CurrentState == State.Established)
        {
            throw Socks5Exception.ProtocolViolation("Receive() after the handshake completed");
        }

        _buffer.AddRange(incoming);

        try
        {
            return CurrentState switch
            {
                State.AwaitingMethodSelection => HandleMethodSelection(),
                State.AwaitingAuthenticationReply => HandleAuthenticationReply(),
                State.AwaitingConnectReply => HandleConnectReply(),
                State.Initial => throw Socks5Exception.ProtocolViolation("Receive() before Start()"),
                _ => throw Socks5Exception.ProtocolViolation("unreachable state"),
            };
        }
        catch (Socks5Exception ex) when (ex.Code == Socks5ErrorCode.IncompleteResponse)
        {
            // Not a failure — the rest of the message has not arrived. State is unchanged and the
            // buffer still holds everything, so the next call re-parses from the top.
            return new Socks5Step(Socks5StepKind.NeedMoreBytes);
        }
        catch
        {
            CurrentState = State.Failed;
            throw;
        }
    }

    private Socks5Step HandleMethodSelection()
    {
        var span = System.Runtime.InteropServices.CollectionsMarshal.AsSpan(_buffer);
        var reader = new ByteReader(span);
        var version = reader.ReadUInt8();
        var rawMethod = reader.ReadUInt8();

        if (version != Socks5.Version)
        {
            throw Socks5Exception.UnexpectedVersion(version);
        }

        if (!Enum.IsDefined(typeof(Socks5Method), rawMethod))
        {
            throw Socks5Exception.UnsupportedMethod(rawMethod);
        }

        var method = (Socks5Method)rawMethod;
        if (method == Socks5Method.NoAcceptableMethods)
        {
            throw Socks5Exception.NoAcceptableMethod();
        }

        _buffer.RemoveRange(0, reader.Offset);
        _selectedMethod = method;

        switch (method)
        {
            case Socks5Method.NoAuthentication:
                CurrentState = State.AwaitingConnectReply;
                return new Socks5Step(Socks5StepKind.Send, EncodeConnectRequest());

            case Socks5Method.UsernamePassword:
                if (_credential is null)
                {
                    throw Socks5Exception.AuthenticationRequired();
                }

                CurrentState = State.AwaitingAuthenticationReply;
                return new Socks5Step(Socks5StepKind.Send, EncodeAuthentication(_credential));

            default:
                // GSSAPI is never offered, so a server selecting it is out of contract.
                throw Socks5Exception.UnsupportedMethod(rawMethod);
        }
    }

    private Socks5Step HandleAuthenticationReply()
    {
        var span = System.Runtime.InteropServices.CollectionsMarshal.AsSpan(_buffer);
        var reader = new ByteReader(span);
        var version = reader.ReadUInt8();
        var status = reader.ReadUInt8();

        // RFC 1929 versions its sub-negotiation independently at 0x01. Some servers mistakenly echo
        // 0x05 here; both are accepted because rejecting the common bug helps nobody, and the status
        // byte is what actually carries the decision.
        if (version != Socks5.AuthSubnegotiationVersion && version != Socks5.Version)
        {
            throw Socks5Exception.UnexpectedVersion(version);
        }

        if (status != Socks5.AuthenticationSuccessStatus)
        {
            throw Socks5Exception.AuthenticationFailed();
        }

        _buffer.RemoveRange(0, reader.Offset);
        CurrentState = State.AwaitingConnectReply;
        return new Socks5Step(Socks5StepKind.Send, EncodeConnectRequest());
    }

    private Socks5Step HandleConnectReply()
    {
        var span = System.Runtime.InteropServices.CollectionsMarshal.AsSpan(_buffer);
        var reader = new ByteReader(span);
        var version = reader.ReadUInt8();
        var rawReply = reader.ReadUInt8();
        var reserved = reader.ReadUInt8();

        if (version != Socks5.Version)
        {
            throw Socks5Exception.UnexpectedVersion(version);
        }

        if (reserved != Socks5.Reserved)
        {
            throw Socks5Exception.Malformed($"reserved byte was 0x{reserved:x2}");
        }

        if (!Enum.IsDefined(typeof(Socks5ReplyCode), rawReply))
        {
            throw Socks5Exception.UnknownReply(rawReply);
        }

        var reply = (Socks5ReplyCode)rawReply;

        // The address is parsed even on failure: the reply is a fixed shape, and consuming it keeps
        // the buffer coherent if a caller ever chooses to continue.
        var boundAddress = Socks5Address.Decode(ref reader);
        var boundPort = reader.ReadUInt16();

        if (!reply.IsSuccess())
        {
            throw Socks5Exception.RequestRejected(reply);
        }

        _buffer.RemoveRange(0, reader.Offset);
        var leftover = _buffer.ToArray();
        _buffer.Clear();
        CurrentState = State.Established;

        return new Socks5Step(
            Socks5StepKind.Established,
            Connection: new Socks5ConnectionInfo(boundAddress, boundPort, _selectedMethod, leftover));
    }

    private byte[] EncodeConnectRequest()
    {
        var address = _destination.Encode();
        var request = new byte[address.Length + 5];
        request[0] = Socks5.Version;
        request[1] = (byte)_command;
        request[2] = Socks5.Reserved;
        address.CopyTo(request, 3);
        request[^2] = (byte)(_port >> 8);
        request[^1] = (byte)(_port & 0xFF);
        return request;
    }

    private static byte[] EncodeAuthentication(Socks5Credential credential)
    {
        var username = Encoding.UTF8.GetBytes(credential.Username);
        var password = Encoding.UTF8.GetBytes(credential.Password);

        if (username.Length is < 1 or > 255 || password.Length > 255)
        {
            throw Socks5Exception.CredentialTooLong();
        }

        var message = new byte[username.Length + password.Length + 3];
        message[0] = Socks5.AuthSubnegotiationVersion;
        message[1] = (byte)username.Length;
        username.CopyTo(message, 2);
        message[2 + username.Length] = (byte)password.Length;
        password.CopyTo(message, 3 + username.Length);
        return message;
    }
}
