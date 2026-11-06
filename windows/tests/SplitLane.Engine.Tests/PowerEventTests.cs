using System.ServiceProcess;
using SplitLane.Engine.Runtime;

namespace SplitLane.Engine.Tests;

public sealed class PowerEventTests
{
    [Fact]
    public void AnInteractiveWakeRefreshesTransportOnlyOnce()
    {
        var resumes = 0;
        foreach (var status in new[] { PowerBroadcastStatus.Suspend, PowerBroadcastStatus.ResumeAutomatic, PowerBroadcastStatus.ResumeSuspend })
        {
            Assert.True(EngineWindowsService.DispatchPowerEvent(status, () => resumes++));
        }
        Assert.Equal(1, resumes);
    }

    [Theory]
    [InlineData(PowerBroadcastStatus.Suspend)]
    [InlineData(PowerBroadcastStatus.QuerySuspend)]
    [InlineData(PowerBroadcastStatus.ResumeSuspend)]
    [InlineData(PowerBroadcastStatus.PowerStatusChange)]
    [InlineData(PowerBroadcastStatus.BatteryLow)]
    public void OtherPowerNotificationsDoNotRestartRouting(PowerBroadcastStatus status)
    {
        Assert.True(EngineWindowsService.DispatchPowerEvent(status, () => throw new InvalidOperationException("Unexpected restart")));
    }
}
