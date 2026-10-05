using SplitLane.Platform;

namespace SplitLane.Engine.Tests.Security;

/// <summary>
/// SL-SEC-013: the version strings read from an image are read while their buffer cannot move, and an
/// answer pointing outside the buffer is refused rather than dereferenced.
/// </summary>
[Trait("Category", "Security")]
[Collection(SerialSecurityTests.Name)]
public sealed class VersionResourceSecurityTests
{
    private static string SystemTool => Path.Combine(Environment.SystemDirectory, "notepad.exe");

    [Fact]
    public async Task Reading_a_version_resource_is_stable_under_garbage_collection()
    {
        var expected = ImageFile.ReadVersion(SystemTool);
        Assert.NotNull(expected.ProductName);

        using var stop = new CancellationTokenSource();

        // Allocation and compaction on another thread, so a buffer that was not pinned would move
        // between VerQueryValue and the read that follows it.
        var churn = Task.Run(() =>
        {
            while (!stop.IsCancellationRequested)
            {
                _ = new byte[16 * 1024];
                GC.Collect(0, GCCollectionMode.Forced, blocking: true, compacting: true);
            }
        });

        try
        {
            for (var i = 0; i < 200; i++)
            {
                Assert.Equal(expected, ImageFile.ReadVersion(SystemTool));
            }
        }
        finally
        {
            await stop.CancelAsync();
            await churn;
        }
    }

    [Theory]
    [InlineData(1000, 0, 4, true)]     // start of the block
    [InlineData(1000, 996, 4, true)]   // ends exactly at the end
    [InlineData(1000, 997, 4, false)]  // runs past the end
    [InlineData(1000, -4, 4, false)]   // before the block
    [InlineData(1000, 10, -1, false)]
    public void An_answer_outside_the_block_is_refused(int blockLength, long offset, long bytes, bool accepted)
    {
        var start = (nint)0x10000;
        Assert.Equal(accepted, ImageFile.TryLocate(blockLength, start, (nint)(start + offset), bytes, out _));
    }

    [Fact]
    public void A_null_answer_is_refused() =>
        Assert.False(ImageFile.TryLocate(100, (nint)0x10000, nint.Zero, 4, out _));
}

/// <summary>
/// Tests that stress the whole process (forced garbage collections) and must not run beside others,
/// whose timeouts they would otherwise eat into.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class SerialSecurityTests
{
    /// <summary>The collection's name.</summary>
    public const string Name = "Serial security tests";
}
