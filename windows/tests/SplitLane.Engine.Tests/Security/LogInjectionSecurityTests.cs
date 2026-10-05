using System.Collections.Concurrent;
using SplitLane.Core.Logging;
using SplitLane.Core.Models;
using SplitLane.Engine.Interop;
using SplitLane.Engine.Ipc;

namespace SplitLane.Engine.Tests.Security;

/// <summary>
/// SL-SEC-018: text from outside cannot forge a log record or rewrite a console, legitimate Unicode is
/// left alone, and the activity list shows a user only their own session's connections.
/// </summary>
[Trait("Category", "Security")]
public sealed class LogInjectionSecurityTests
{
    [Theory]
    [InlineData("proxy said\r\n2026-10-06 [INFO] engine: all good", "\\u000D\\u000A")]
    [InlineData("host\nname", "\\u000A")]
    [InlineData("reason\u001b[2Jcleared", "\\u001B")]
    [InlineData("bell\u0007", "\\u0007")]
    [InlineData("line\u2028separator", "\\u2028")]
    [InlineData("evil\u202Eexe.txt", "\\u202E")]
    public void Control_characters_are_escaped_not_written(string input, string expected)
    {
        var sanitized = SplitLaneLog.Sanitize(input);

        Assert.Contains(expected, sanitized, StringComparison.Ordinal);
        Assert.DoesNotContain('\n', sanitized);
        Assert.DoesNotContain('\r', sanitized);
        Assert.DoesNotContain('\u001b', sanitized);
    }

    [Theory]
    [InlineData("Прокси отклонил учётные данные")]
    [InlineData("代理拒绝了凭据")]
    [InlineData("C:\\Program Files\\Ünïcødé\\app.exe")]
    [InlineData("emoji 🙂 ok")]
    public void Legitimate_unicode_is_left_alone(string input) =>
        Assert.Equal(input, SplitLaneLog.Sanitize(input));

    [Fact]
    public void Overlong_text_is_cut_and_says_so()
    {
        var sanitized = SplitLaneLog.Sanitize(new string('x', 100_000));

        Assert.True(sanitized.Length < SplitLaneLog.MaxMessageLength + 32);
        Assert.EndsWith("[truncated]", sanitized, StringComparison.Ordinal);
    }

    [Fact]
    public void What_reaches_a_sink_is_one_line()
    {
        var sink = new CapturingSink();
        SplitLaneLog.AddSink(sink);

        SplitLaneLog.Warning("relay\nforged", "upstream said: 407 Denied\r\n2026-10-06 [ERROR] fake record");

        Assert.Contains(sink.Lines, line => line.Category == "relay\\u000Aforged");
        Assert.DoesNotContain(sink.Lines, line => line.Message.Contains('\n') || line.Message.Contains('\r'));
    }

    [Fact]
    public void A_caller_sees_only_their_own_sessions_connections()
    {
        IReadOnlyList<ConnectionEvent> events =
        [
            Event("mine.example", session: 2),
            Event("theirs.example", session: 3),
            Event("unknown.example", session: null),
        ];

        var mine = ControlServer.ForSession(events, 2);

        Assert.Equal(["mine.example"], mine.Select(e => e.DestinationHost));
        Assert.Empty(ControlServer.ForSession(events, null));
    }

    [Fact]
    public void The_session_of_a_running_process_can_be_read()
    {
        Assert.Equal(
            (uint)System.Diagnostics.Process.GetCurrentProcess().SessionId,
            ProcessSessions.Of((uint)Environment.ProcessId));
    }

    private static ConnectionEvent Event(string host, uint? session) => new()
    {
        ExecutablePath = @"C:\Apps\app.exe",
        DestinationHost = host,
        SessionId = session,
    };

    private sealed class CapturingSink : ILogSink
    {
        public ConcurrentBag<(string Category, string Message)> Lines { get; } = [];

        public void Write(LogLevel level, string category, string message) => Lines.Add((category, message));
    }
}
