namespace SplitLane.Engine.Update;

/// <summary>Reports bytes successfully written without owning the protected staging stream.</summary>
internal sealed class DownloadProgressStream(Stream destination, Action<int> written) : Stream
{
    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => destination.CanWrite;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() => destination.Flush();
    public override Task FlushAsync(CancellationToken token) => destination.FlushAsync(token);
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count)
    {
        destination.Write(buffer, offset, count);
        written(count);
    }
    public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken token)
    {
        await destination.WriteAsync(buffer.AsMemory(offset, count), token).ConfigureAwait(false);
        written(count);
    }
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken token = default)
    {
        await destination.WriteAsync(buffer, token).ConfigureAwait(false);
        written(buffer.Length);
    }
}
