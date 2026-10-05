using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace SplitLane.Core.Logging;

/// <summary>Severity of a log record.</summary>
public enum LogLevel
{
    /// <summary>Hot-path detail, off unless explicitly enabled.</summary>
    Debug = 0,

    /// <summary>Normal lifecycle events.</summary>
    Info = 1,

    /// <summary>Something unexpected that did not stop the work.</summary>
    Warning = 2,

    /// <summary>Something that failed.</summary>
    Error = 3,
}

/// <summary>Where log records go.</summary>
public interface ILogSink
{
    /// <summary>Accepts one already-formatted record.</summary>
    void Write(LogLevel level, string category, string message);
}

/// <summary>
/// Structured logging with a hard rule: no secrets, no payloads, ever.
/// </summary>
/// <remarks>
/// <para>
/// The macOS project forbids <c>print()</c> in production paths and routes everything through OSLog.
/// The Windows equivalent is this: a single choke point that every component writes through, so that
/// "we never log a password" is enforced in one place rather than reviewed in fifty.
/// </para>
/// <para>
/// Destinations, ports, rule keys and byte <i>counts</i> are loggable. Credentials and relayed bytes
/// are not, and there is no overload here that takes a buffer.
/// </para>
/// </remarks>
public static class SplitLaneLog
{
    private static readonly List<ILogSink> Sinks = [];
    private static readonly Lock Gate = new();

    /// <summary>Records at or above this level are emitted.</summary>
    public static LogLevel MinimumLevel { get; set; } = LogLevel.Info;

    /// <summary>Adds a destination.</summary>
    public static void AddSink(ILogSink sink)
    {
        ArgumentNullException.ThrowIfNull(sink);
        lock (Gate)
        {
            Sinks.Add(sink);
        }
    }

    /// <summary>Removes every destination. Used by tests.</summary>
    public static void ClearSinks()
    {
        lock (Gate)
        {
            Sinks.Clear();
        }
    }

    /// <summary>Writes a debug record.</summary>
    public static void Debug(string category, string message) => Write(LogLevel.Debug, category, message);

    /// <summary>Writes an informational record.</summary>
    public static void Info(string category, string message) => Write(LogLevel.Info, category, message);

    /// <summary>Writes a warning.</summary>
    public static void Warning(string category, string message) => Write(LogLevel.Warning, category, message);

    /// <summary>Writes an error.</summary>
    public static void Error(string category, string message) => Write(LogLevel.Error, category, message);

    /// <summary>Writes an error with an exception, recording its type and message but not a payload.</summary>
    public static void Error(string category, string message, Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        Write(LogLevel.Error, category, $"{message} — {exception.GetType().Name}: {exception.Message}");
    }

    /// <summary>Longest message written. Anything longer is cut, and says so.</summary>
    public const int MaxMessageLength = 4096;

    /// <summary>
    /// Makes text safe to put on one log line (SL-SEC-018).
    /// </summary>
    /// <remarks>
    /// Messages carry text from outside: a proxy's reason phrase, a hostname, a process path, a rule
    /// name. A line break in any of them would start a forged record; an escape sequence would rewrite
    /// what a console shows; a bidirectional override would make a name read as something else. Every
    /// control character, line or paragraph separator and bidi control is written as <c>\uXXXX</c>.
    /// Ordinary letters in any script are left alone.
    /// </remarks>
    public static string Sanitize(string? text, int maxLength = MaxMessageLength)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        var clean = true;
        foreach (var character in text)
        {
            if (NeedsEscape(character))
            {
                clean = false;
                break;
            }
        }

        if (clean && text.Length <= maxLength)
        {
            return text;
        }

        var builder = new System.Text.StringBuilder(Math.Min(text.Length, maxLength) + 16);
        foreach (var character in text)
        {
            if (builder.Length >= maxLength)
            {
                builder.Append(" [truncated]");
                break;
            }

            if (NeedsEscape(character))
            {
                builder.Append("\\u").Append(((int)character).ToString("X4", CultureInfo.InvariantCulture));
            }
            else
            {
                builder.Append(character);
            }
        }

        return builder.ToString();
    }

    private static bool NeedsEscape(char character) =>
        char.IsControl(character) ||
        character is '\u2028' or '\u2029' or (>= '\u202A' and <= '\u202E') or (>= '\u2066' and <= '\u2069');

    private static void Write(LogLevel level, string category, string message)
    {
        if (level < MinimumLevel)
        {
            return;
        }

        // At the boundary, once, so no sink and no call site can forget (SL-SEC-018).
        category = Sanitize(category, 64);
        message = Sanitize(message);

        ILogSink[] snapshot;
        lock (Gate)
        {
            if (Sinks.Count == 0)
            {
                Trace.WriteLine($"[{level}] {category}: {message}");
                return;
            }

            snapshot = [.. Sinks];
        }

        foreach (var sink in snapshot)
        {
            try
            {
                sink.Write(level, category, message);
            }
            catch (Exception ex)
            {
                // A failing sink must never take down the component that was logging. There is
                // nowhere useful to report this except the debugger.
                Trace.WriteLine($"[log-sink-failure] {ex.GetType().Name}: {ex.Message}");
            }
        }
    }
}

/// <summary>A log sink that appends to a rolling file.</summary>
/// <remarks>
/// Deliberately tiny and dependency-free. The engine runs elevated, and pulling a logging framework
/// into an elevated process for the sake of a timestamped line is a poor trade.
/// </remarks>
public sealed class RollingFileLogSink : ILogSink, IDisposable
{
    private readonly string _path;
    private readonly long _maxBytes;
    private readonly Lock _gate = new();
    private bool _disposed;

    /// <summary>Opens (or creates) a log file.</summary>
    /// <param name="path">Full path of the log file.</param>
    /// <param name="maxBytes">Size at which the file is rolled to <c>.1</c>.</param>
    public RollingFileLogSink(string path, long maxBytes = 4 * 1024 * 1024)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = path;
        _maxBytes = maxBytes;

        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }
    }

    /// <inheritdoc />
    public void Write(LogLevel level, string category, string message)
    {
        if (_disposed)
        {
            return;
        }

        var line = new StringBuilder()
            .Append(DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss.fff zzz", CultureInfo.InvariantCulture))
            .Append(" [").Append(level.ToString().ToUpperInvariant()).Append("] ")
            .Append(category).Append(": ").Append(message)
            .AppendLine()
            .ToString();

        lock (_gate)
        {
            try
            {
                if (_maxBytes > 0 && File.Exists(_path) && new FileInfo(_path).Length > _maxBytes)
                {
                    var rolled = _path + ".1";
                    File.Delete(rolled);
                    File.Move(_path, rolled);
                }

                File.AppendAllText(_path, line, Encoding.UTF8);
            }
            catch (IOException)
            {
                // Losing a log line is strictly better than failing the operation that produced it.
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    /// <inheritdoc />
    public void Dispose() => _disposed = true;
}
