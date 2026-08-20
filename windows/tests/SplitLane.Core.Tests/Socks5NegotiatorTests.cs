using System.Text;
using SplitLane.Core.Proxy.Socks5;

namespace SplitLane.Core.Tests;

/// <summary>
/// The SOCKS5 handshake, driven byte by byte.
/// </summary>
/// <remarks>
/// Because the negotiator is a pure state machine, every truncation offset and every malformed field
/// is reachable from a unit test with no socket. That is the entire reason it is shaped this way.
/// </remarks>
public sealed class Socks5NegotiatorTests
{
    private static Socks5Negotiator ForExample(Socks5Credential? credential = null)
        => new(Socks5Address.FromDomain("example.com"), 443, credential);

    private static byte[] MethodSelection(Socks5Method method) => [Socks5.Version, (byte)method];

    private static byte[] ConnectReply(Socks5ReplyCode code = Socks5ReplyCode.Succeeded)
        => [Socks5.Version, (byte)code, 0x00, (byte)Socks5AddressType.IPv4, 0, 0, 0, 0, 0, 0];

    // ---- Greeting -------------------------------------------------------------------------

    [Fact]
    public void GreetingOffersOnlyNoAuthWhenThereIsNoCredential()
    {
        var step = ForExample().Start();

        Assert.Equal(Socks5StepKind.Send, step.Kind);
        Assert.Equal([Socks5.Version, 1, (byte)Socks5Method.NoAuthentication], step.Bytes);
    }

    [Fact]
    public void GreetingOffersUsernamePasswordOnlyWhenACredentialExists()
    {
        var step = ForExample(new Socks5Credential("user", "pass")).Start();

        Assert.Equal(
            [Socks5.Version, 2, (byte)Socks5Method.NoAuthentication, (byte)Socks5Method.UsernamePassword],
            step.Bytes);
    }

    [Fact]
    public void StartTwiceIsAProtocolViolation()
    {
        var negotiator = ForExample();
        negotiator.Start();

        var error = Assert.Throws<Socks5Exception>(() => negotiator.Start());
        Assert.Equal(Socks5ErrorCode.ProtocolViolation, error.Code);
    }

    [Fact]
    public void ReceiveBeforeStartIsAProtocolViolation()
    {
        var error = Assert.Throws<Socks5Exception>(() => ForExample().Receive([Socks5.Version, 0]));
        Assert.Equal(Socks5ErrorCode.ProtocolViolation, error.Code);
    }

    // ---- No-auth path ---------------------------------------------------------------------

    [Fact]
    public void NoAuthSelectionSendsTheConnectRequest()
    {
        var negotiator = ForExample();
        negotiator.Start();

        var step = negotiator.Receive(MethodSelection(Socks5Method.NoAuthentication));

        Assert.Equal(Socks5StepKind.Send, step.Kind);

        var expected = new List<byte>
        {
            Socks5.Version, (byte)Socks5Command.Connect, 0x00, (byte)Socks5AddressType.Domain, 11,
        };
        expected.AddRange(Encoding.UTF8.GetBytes("example.com"));
        expected.AddRange([0x01, 0xBB]); // 443

        Assert.Equal(expected, step.Bytes);
    }

    [Fact]
    public void SuccessfulConnectEstablishesTheTunnel()
    {
        var negotiator = ForExample();
        negotiator.Start();
        negotiator.Receive(MethodSelection(Socks5Method.NoAuthentication));

        var step = negotiator.Receive(ConnectReply());

        Assert.Equal(Socks5StepKind.Established, step.Kind);
        Assert.Equal(Socks5Negotiator.State.Established, negotiator.CurrentState);
        Assert.Equal(Socks5Method.NoAuthentication, step.Connection!.Method);
        Assert.Empty(step.Connection.LeftoverBytes);
    }

    // ---- Partial delivery ------------------------------------------------------------------

    [Fact]
    public void AMethodSelectionSplitAcrossTwoReadsStillParses()
    {
        var negotiator = ForExample();
        negotiator.Start();

        Assert.Equal(Socks5StepKind.NeedMoreBytes, negotiator.Receive([Socks5.Version]).Kind);
        Assert.Equal(Socks5StepKind.Send, negotiator.Receive([(byte)Socks5Method.NoAuthentication]).Kind);
    }

    [Fact]
    public void AConnectReplyDeliveredOneByteAtATimeStillParses()
    {
        var negotiator = ForExample();
        negotiator.Start();
        negotiator.Receive(MethodSelection(Socks5Method.NoAuthentication));

        var reply = ConnectReply();
        for (var i = 0; i < reply.Length - 1; i++)
        {
            Assert.Equal(Socks5StepKind.NeedMoreBytes, negotiator.Receive([reply[i]]).Kind);
        }

        Assert.Equal(Socks5StepKind.Established, negotiator.Receive([reply[^1]]).Kind);
    }

    [Fact]
    public void TruncationAtEveryOffsetIsRecoverable()
    {
        var reply = ConnectReply();

        for (var cut = 1; cut < reply.Length; cut++)
        {
            var negotiator = ForExample();
            negotiator.Start();
            negotiator.Receive(MethodSelection(Socks5Method.NoAuthentication));

            Assert.Equal(Socks5StepKind.NeedMoreBytes, negotiator.Receive(reply.AsSpan(0, cut)).Kind);
            Assert.Equal(Socks5StepKind.Established, negotiator.Receive(reply.AsSpan(cut)).Kind);
        }
    }

    [Fact]
    public void BytesGluedToTheConnectReplyAreHandedBackNotDropped()
    {
        // A server may coalesce its reply with the first bytes of the relayed stream into one
        // segment. Dropping them looks like a rare, unreproducible truncation of the first response.
        var negotiator = ForExample();
        negotiator.Start();
        negotiator.Receive(MethodSelection(Socks5Method.NoAuthentication));

        var payload = "HTTP/1.1 200 OK"u8.ToArray();
        var step = negotiator.Receive([.. ConnectReply(), .. payload]);

        Assert.Equal(Socks5StepKind.Established, step.Kind);
        Assert.Equal(payload, step.Connection!.LeftoverBytes);
    }

    // ---- Authentication ---------------------------------------------------------------------

    [Fact]
    public void UsernamePasswordSubNegotiationUsesItsOwnVersionByte()
    {
        var negotiator = ForExample(new Socks5Credential("user", "pass"));
        negotiator.Start();

        var step = negotiator.Receive(MethodSelection(Socks5Method.UsernamePassword));

        // 0x01, not 0x05 — RFC 1929 versions itself independently.
        Assert.Equal(Socks5.AuthSubnegotiationVersion, step.Bytes![0]);
        Assert.Equal(
            [0x01, 4, (byte)'u', (byte)'s', (byte)'e', (byte)'r', 4, (byte)'p', (byte)'a', (byte)'s', (byte)'s'],
            step.Bytes);
    }

    [Fact]
    public void AuthenticationSuccessProceedsToConnect()
    {
        var negotiator = ForExample(new Socks5Credential("user", "pass"));
        negotiator.Start();
        negotiator.Receive(MethodSelection(Socks5Method.UsernamePassword));

        var step = negotiator.Receive([Socks5.AuthSubnegotiationVersion, 0x00]);

        Assert.Equal(Socks5StepKind.Send, step.Kind);
        Assert.Equal(Socks5Negotiator.State.AwaitingConnectReply, negotiator.CurrentState);
    }

    [Fact]
    public void AServerEchoingVersionFiveInTheAuthReplyIsTolerated()
    {
        // A known-common server bug. The status byte is what carries the decision.
        var negotiator = ForExample(new Socks5Credential("user", "pass"));
        negotiator.Start();
        negotiator.Receive(MethodSelection(Socks5Method.UsernamePassword));

        Assert.Equal(Socks5StepKind.Send, negotiator.Receive([Socks5.Version, 0x00]).Kind);
    }

    [Fact]
    public void AuthenticationFailureIsReportedAsSuch()
    {
        var negotiator = ForExample(new Socks5Credential("user", "wrong"));
        negotiator.Start();
        negotiator.Receive(MethodSelection(Socks5Method.UsernamePassword));

        var error = Assert.Throws<Socks5Exception>(() =>
            negotiator.Receive([Socks5.AuthSubnegotiationVersion, 0x01]));

        Assert.Equal(Socks5ErrorCode.AuthenticationFailed, error.Code);
        Assert.Equal(Socks5Negotiator.State.Failed, negotiator.CurrentState);
    }

    [Fact]
    public void SelectingUsernamePasswordWithNoCredentialIsRefused()
    {
        var negotiator = ForExample();
        negotiator.Start();

        var error = Assert.Throws<Socks5Exception>(() =>
            negotiator.Receive(MethodSelection(Socks5Method.UsernamePassword)));

        Assert.Equal(Socks5ErrorCode.AuthenticationRequired, error.Code);
    }

    [Fact]
    public void AnOverlongCredentialIsRejectedBeforeAnythingIsSent()
    {
        var negotiator = ForExample(new Socks5Credential(new string('u', 256), "pass"));

        var error = Assert.Throws<Socks5Exception>(() => negotiator.Start());

        Assert.Equal(Socks5ErrorCode.CredentialTooLong, error.Code);
    }

    [Fact]
    public void CredentialRedactsItsPasswordInEveryTextualForm()
    {
        var credential = new Socks5Credential("user", "hunter2");

        Assert.DoesNotContain("hunter2", credential.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("hunter2", $"{credential}", StringComparison.Ordinal);
    }

    // ---- Rejections --------------------------------------------------------------------------

    [Fact]
    public void NoAcceptableMethodsIsReportedAsSuch()
    {
        var negotiator = ForExample();
        negotiator.Start();

        var error = Assert.Throws<Socks5Exception>(() =>
            negotiator.Receive(MethodSelection(Socks5Method.NoAcceptableMethods)));

        Assert.Equal(Socks5ErrorCode.NoAcceptableAuthenticationMethod, error.Code);
    }

    [Fact]
    public void AMethodNeverOfferedIsRefused()
    {
        var negotiator = ForExample();
        negotiator.Start();

        var error = Assert.Throws<Socks5Exception>(() => negotiator.Receive([Socks5.Version, 0x01]));

        Assert.Equal(Socks5ErrorCode.UnsupportedAuthenticationMethod, error.Code);
    }

    [Fact]
    public void AWrongVersionByteIsRefused()
    {
        var negotiator = ForExample();
        negotiator.Start();

        var error = Assert.Throws<Socks5Exception>(() => negotiator.Receive([0x04, 0x00]));

        Assert.Equal(Socks5ErrorCode.UnexpectedVersion, error.Code);
    }

    [Theory]
    [InlineData(Socks5ReplyCode.GeneralFailure)]
    [InlineData(Socks5ReplyCode.ConnectionNotAllowed)]
    [InlineData(Socks5ReplyCode.NetworkUnreachable)]
    [InlineData(Socks5ReplyCode.HostUnreachable)]
    [InlineData(Socks5ReplyCode.ConnectionRefused)]
    [InlineData(Socks5ReplyCode.TtlExpired)]
    [InlineData(Socks5ReplyCode.CommandNotSupported)]
    [InlineData(Socks5ReplyCode.AddressTypeNotSupported)]
    public void EveryRejectionCodeIsSurfacedVerbatim(Socks5ReplyCode code)
    {
        var negotiator = ForExample();
        negotiator.Start();
        negotiator.Receive(MethodSelection(Socks5Method.NoAuthentication));

        var error = Assert.Throws<Socks5Exception>(() => negotiator.Receive(ConnectReply(code)));

        Assert.Equal(Socks5ErrorCode.RequestRejected, error.Code);
        Assert.Equal(code, error.ReplyCode);
    }

    [Fact]
    public void AnUnknownReplyCodeIsNamedRatherThanGuessedAt()
    {
        var negotiator = ForExample();
        negotiator.Start();
        negotiator.Receive(MethodSelection(Socks5Method.NoAuthentication));

        var error = Assert.Throws<Socks5Exception>(() =>
            negotiator.Receive([Socks5.Version, 0x42, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));

        Assert.Equal(Socks5ErrorCode.UnknownReplyCode, error.Code);
    }

    [Fact]
    public void ANonZeroReservedByteIsMalformed()
    {
        var negotiator = ForExample();
        negotiator.Start();
        negotiator.Receive(MethodSelection(Socks5Method.NoAuthentication));

        var error = Assert.Throws<Socks5Exception>(() =>
            negotiator.Receive([Socks5.Version, 0x00, 0x99, 0x01, 0, 0, 0, 0, 0, 0]));

        Assert.Equal(Socks5ErrorCode.MalformedResponse, error.Code);
    }

    [Fact]
    public void AnUnknownAddressTypeInTheReplyIsRefused()
    {
        var negotiator = ForExample();
        negotiator.Start();
        negotiator.Receive(MethodSelection(Socks5Method.NoAuthentication));

        var error = Assert.Throws<Socks5Exception>(() =>
            negotiator.Receive([Socks5.Version, 0x00, 0x00, 0x07, 0, 0, 0, 0, 0, 0]));

        Assert.Equal(Socks5ErrorCode.UnsupportedAddressType, error.Code);
    }

    [Fact]
    public void AHostileDomainLengthCanOnlyStall()
    {
        // The server chooses the length byte. The bounds check means an absurd value produces
        // "waiting for more bytes", never an over-read.
        var negotiator = ForExample();
        negotiator.Start();
        negotiator.Receive(MethodSelection(Socks5Method.NoAuthentication));

        var step = negotiator.Receive([Socks5.Version, 0x00, 0x00, (byte)Socks5AddressType.Domain, 0xFF, 0x41]);

        Assert.Equal(Socks5StepKind.NeedMoreBytes, step.Kind);
    }

    [Fact]
    public void ReceiveAfterFailureIsRefused()
    {
        var negotiator = ForExample();
        negotiator.Start();
        Assert.Throws<Socks5Exception>(() => negotiator.Receive([0x04, 0x00]));

        var error = Assert.Throws<Socks5Exception>(() => negotiator.Receive([0x05, 0x00]));
        Assert.Equal(Socks5ErrorCode.ProtocolViolation, error.Code);
    }

    [Fact]
    public void ReceiveAfterEstablishedIsRefused()
    {
        var negotiator = ForExample();
        negotiator.Start();
        negotiator.Receive(MethodSelection(Socks5Method.NoAuthentication));
        negotiator.Receive(ConnectReply());

        var error = Assert.Throws<Socks5Exception>(() => negotiator.Receive([0x00]));
        Assert.Equal(Socks5ErrorCode.ProtocolViolation, error.Code);
    }

    // ---- Transient classification -------------------------------------------------------------

    [Theory]
    [InlineData(Socks5ReplyCode.HostUnreachable, true)]
    [InlineData(Socks5ReplyCode.NetworkUnreachable, true)]
    [InlineData(Socks5ReplyCode.TtlExpired, true)]
    [InlineData(Socks5ReplyCode.ConnectionNotAllowed, false)]
    [InlineData(Socks5ReplyCode.CommandNotSupported, false)]
    public void RejectionTransienceIsClassified(Socks5ReplyCode code, bool transient) =>
        Assert.Equal(transient, Socks5Exception.RequestRejected(code).IsTransient);

    [Fact]
    public void AuthenticationFailureIsNotTransient() =>
        Assert.False(Socks5Exception.AuthenticationFailed().IsTransient);
}
