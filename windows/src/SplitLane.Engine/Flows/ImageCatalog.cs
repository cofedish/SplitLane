using System.Collections.Concurrent;
using System.Diagnostics;
using System.Threading.Channels;
using SplitLane.Core.Logging;
using SplitLane.Core.Rules;
using SplitLane.Platform;

namespace SplitLane.Engine.Flows;

/// <summary>One version of one executable file, and what has been established about it.</summary>
/// <remarks>
/// Shared by every process started from that file. Its evidence is replaced, never mutated, when
/// verification finishes, so a reader always sees one coherent answer.
/// </remarks>
public sealed class ImageRecord
{
    private ImageEvidence _evidence;
    private int _requested;

    internal ImageRecord(string path, FileStamp stamp)
    {
        Path = path;
        Stamp = stamp;
        _evidence = new ImageEvidence { ExecutablePath = path, FileSize = stamp.Size };
    }

    /// <summary>Normalised path of the file.</summary>
    public string Path { get; }

    /// <summary>Size, write time and file id when the record was made. A different stamp is a different file.</summary>
    internal FileStamp Stamp { get; }

    /// <summary>Everything known so far.</summary>
    public ImageEvidence Evidence
    {
        get => Volatile.Read(ref _evidence);
        internal set => Volatile.Write(ref _evidence, value);
    }

    /// <summary>How long verification took, once it has run. Diagnostic.</summary>
    public TimeSpan VerificationTime { get; internal set; }

    /// <summary>Adds to what has been asked for; true when this call is the one that should queue it.</summary>
    internal bool Request(EvidenceNeeds needs)
    {
        while (true)
        {
            var current = Volatile.Read(ref _requested);
            var next = current | (int)needs | Queued;
            if (Interlocked.CompareExchange(ref _requested, next, current) == current)
            {
                return (current & Queued) == 0;
            }
        }
    }

    /// <summary>Takes what has been asked for and marks the record idle.</summary>
    internal EvidenceNeeds Take() => (EvidenceNeeds)(Interlocked.Exchange(ref _requested, 0) & ~Queued);

    private const int Queued = 1 << 16;
}

/// <summary>
/// What the engine knows about every executable it has seen, and the worker that verifies them.
/// </summary>
/// <remarks>
/// <para>
/// The socket pump asks for evidence on every connection and must never wait for a disk, let alone a
/// signature check: that costs 1.5 s for a 320 MB executable, measured, and the pump is the one thread
/// every connection on the machine goes through. So the pump only ever reads what is cached, plus
/// the file's stamp once per new process, and verification happens here on background threads, once
/// per file version, only for files that claim to be a selected application.
/// </para>
/// <para>
/// A new process refreshes its image's stamp. That is what stops a verified answer outliving the file
/// it was about: a record is keyed on the path but valid only for the stamp - size, write time, file
/// id - it was made for, and a file replaced in place gets a new record and a new verification.
/// </para>
/// </remarks>
public sealed class ImageCatalog : IAsyncDisposable
{
    private const string LogCategory = "identity";

    private readonly ConcurrentDictionary<string, ImageRecord> _records = new(ExecutablePath.Comparer);
    private readonly Channel<ImageRecord> _queue = Channel.CreateUnbounded<ImageRecord>(
        new UnboundedChannelOptions { SingleWriter = false, SingleReader = false });
    private readonly CancellationTokenSource _stopping = new();
    private readonly Task[] _workers;
    private readonly int _maxEntries;
    private readonly Func<string, bool, ImageEvidence?> _inspect;
    private readonly Func<string, FileStamp> _stamp;
    private long _verifications;

    /// <summary>Builds a catalog that inspects real files.</summary>
    public ImageCatalog(int workers = 2, int maxEntries = 4096)
        : this(WindowsImageInspector.Read, StampOf, workers, maxEntries)
    {
    }

    /// <summary>Builds a catalog over explicit inspection functions. Used by tests.</summary>
    internal ImageCatalog(
        Func<string, bool, ImageEvidence?> inspect,
        Func<string, FileStamp> stamp,
        int workers = 2,
        int maxEntries = 4096)
    {
        ArgumentNullException.ThrowIfNull(inspect);
        ArgumentNullException.ThrowIfNull(stamp);
        ArgumentOutOfRangeException.ThrowIfLessThan(workers, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxEntries, 1);

        _inspect = inspect;
        _stamp = stamp;
        _maxEntries = maxEntries;

        // Two, so that one very large executable being hashed does not hold up a small one behind it.
        _workers = [.. Enumerable.Range(0, workers).Select(_ => Task.Run(WorkAsync))];
    }

    /// <summary>Raised on a worker thread when a record's evidence has been completed.</summary>
    public event Action<ImageRecord>? Verified;

    /// <summary>Cached records. Diagnostic.</summary>
    public int Count => _records.Count;

    /// <summary>Verifications performed. Diagnostic.</summary>
    public long Verifications => Interlocked.Read(ref _verifications);

    /// <summary>
    /// The record for a file as it is now: the cached one if the file has not changed, a new one if it
    /// has. Called once per new process.
    /// </summary>
    public ImageRecord Refresh(string executablePath)
    {
        var path = ExecutablePath.Normalize(executablePath);
        var stamp = path.Length == 0 ? default : _stamp(path);

        if (_records.TryGetValue(path, out var cached) && cached.Stamp == stamp)
        {
            return cached;
        }

        if (_records.Count >= _maxEntries)
        {
            // As in ProcessResolver: a wholesale clear rather than an LRU. Rebuilding costs a stamp per
            // live image, and verified answers are re-earned only for files that claim a rule.
            _records.Clear();
        }

        var record = new ImageRecord(path, stamp);
        _records[path] = record;
        return record;
    }

    /// <summary>
    /// The evidence to decide a flow on, reading the version resource first when some rule can only be
    /// claimed through a product name.
    /// </summary>
    /// <param name="record">The process's image.</param>
    /// <param name="packageFamilyName">The package family from the process token, or null.</param>
    /// <param name="needsProductName">Whether the snapshot has product-name rules.</param>
    public ImageEvidence EvidenceFor(ImageRecord record, string? packageFamilyName, bool needsProductName)
    {
        ArgumentNullException.ThrowIfNull(record);

        var evidence = record.Evidence;

        if (needsProductName && !evidence.HasVersionInfo && record.Path.Length > 0)
        {
            // A few milliseconds, once per file version, and only while a product rule exists. It is a
            // claim until the signature covering it is checked.
            var (product, _, _) = ImageFile.ReadVersion(record.Path);
            evidence = evidence with { ProductName = product, HasVersionInfo = true };
            record.Evidence = evidence;
        }

        return packageFamilyName is null ? evidence : evidence with { PackageFamilyName = packageFamilyName };
    }

    /// <summary>
    /// Asks for the expensive facts about a file. Returns immediately; <see cref="Verified"/> fires when
    /// they are in. Asking again while a request is queued adds to it rather than queuing twice.
    /// </summary>
    public void RequestVerification(ImageRecord record, EvidenceNeeds needs)
    {
        ArgumentNullException.ThrowIfNull(record);

        if (needs == EvidenceNeeds.None || record.Path.Length == 0)
        {
            return;
        }

        if (record.Request(needs))
        {
            _queue.Writer.TryWrite(record);
        }
    }

    /// <summary>
    /// Completes a record now, on the calling thread. For the diagnostic <c>--explain</c> mode, which
    /// has nothing better to do than wait.
    /// </summary>
    public ImageEvidence VerifyNow(ImageRecord record, EvidenceNeeds needs)
    {
        ArgumentNullException.ThrowIfNull(record);
        Complete(record, needs);
        return record.Evidence;
    }

    private async Task WorkAsync()
    {
        try
        {
            await foreach (var record in _queue.Reader.ReadAllAsync(_stopping.Token).ConfigureAwait(false))
            {
                var needs = record.Take();
                if (needs == EvidenceNeeds.None)
                {
                    continue;
                }

                try
                {
                    Complete(record, needs);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    // A verification that could not finish is a signature that does not verify. Leaving
                    // the evidence unanswered instead would leave every flow held for this image held
                    // for good - a UDP socket's datagrams dropped for as long as it lives.
                    SplitLaneLog.Error(LogCategory, $"verifying {ExecutablePath.FileName(record.Path)} failed", ex);
                    var current = record.Evidence;
                    record.Evidence = current with
                    {
                        Signature = current.HasSignatureVerdict ? current.Signature : SignatureStatus.Invalid,
                        Sha256 = current.Sha256 ?? (needs.HasFlag(EvidenceNeeds.Hash) ? string.Empty : null),
                    };
                }

                // Raised even when nothing new was computed: a flow held after an earlier verification
                // finished re-requests it, and this is what releases it.
                try
                {
                    Verified?.Invoke(record);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    SplitLaneLog.Error(LogCategory, $"deciding flows held for {ExecutablePath.FileName(record.Path)} failed", ex);
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private void Complete(ImageRecord record, EvidenceNeeds needs)
    {
        var current = record.Evidence;
        var wantsHash = needs.HasFlag(EvidenceNeeds.Hash) && current.Sha256 is null;
        var wantsSignature = needs.HasFlag(EvidenceNeeds.Signature) && !current.HasSignatureVerdict;

        if (!wantsHash && !wantsSignature)
        {
            return;
        }

        var watch = Stopwatch.StartNew();
        var read = _inspect(record.Path, wantsHash);
        watch.Stop();
        Interlocked.Increment(ref _verifications);

        // A file that cannot be opened cannot be vouched for. It is recorded as a signature that does
        // not verify, so a pinned rule refuses it and a claim on a family rule falls through to DIRECT
        // - the answer for a program that is not the selected one.
        //
        // A hash that was asked for and could not be computed is recorded as empty rather than left
        // null: it matches nothing, and it stops the flow asking for it again - otherwise a file that
        // cannot be read would be re-queued for as long as something kept connecting from it.
        var failedHash = wantsHash ? string.Empty : current.Sha256;
        var completed = read is null
            ? current with
            {
                Signature = current.HasSignatureVerdict ? current.Signature : SignatureStatus.Invalid,
                Sha256 = current.Sha256 ?? failedHash,
            }
            : read with
            {
                ExecutablePath = record.Path,
                PackageFamilyName = null,
                Sha256 = read.Sha256 ?? current.Sha256 ?? failedHash,
            };

        record.VerificationTime = watch.Elapsed;
        record.Evidence = completed;
    }

    private static FileStamp StampOf(string path) =>
        ImageFile.TryGetStamp(path, out var stamp) ? stamp : default;

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        _queue.Writer.TryComplete();
        await _stopping.CancelAsync().ConfigureAwait(false);

        try
        {
            await Task.WhenAll(_workers).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }

        _stopping.Dispose();
    }
}
