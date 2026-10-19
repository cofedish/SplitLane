using SplitLane.Engine.Update;

namespace SplitLane.Engine.Tests;

public sealed class DownloadProgressTests
{
    [Fact]
    public async Task CountsOnlyCompletedWritesAndDoesNotCloseStagingStream()
    {
        using var destination = new MemoryStream();
        var progress = new List<int>();
        using (var stream = new DownloadProgressStream(destination, progress.Add))
        {
            stream.Write(new byte[3], 0, 3);
            await stream.WriteAsync(new byte[5], 0, 5, CancellationToken.None);
            await stream.WriteAsync(new byte[7].AsMemory());
        }
        Assert.Equal(new[] { 3, 5, 7 }, progress);
        Assert.Equal(15, destination.Length);
        Assert.True(destination.CanWrite);
    }

    [Fact]
    public async Task FailedWriteDoesNotAdvanceReportedProgress()
    {
        using var destination = new MemoryStream(new byte[1], writable: false);
        var count = 0;
        using var stream = new DownloadProgressStream(destination, n => count += n);
        await Assert.ThrowsAsync<NotSupportedException>(async () => await stream.WriteAsync(new byte[3].AsMemory()));
        Assert.Equal(0, count);
    }

    [Fact]
    public async Task CancelledWriteDoesNotAdvanceReportedProgress()
    {
        using var destination = new MemoryStream();
        var count = 0;
        using var stream = new DownloadProgressStream(destination, n => count += n);
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await stream.WriteAsync(new byte[3].AsMemory(), cancelled.Token));
        Assert.Equal(0, count);
    }
}
