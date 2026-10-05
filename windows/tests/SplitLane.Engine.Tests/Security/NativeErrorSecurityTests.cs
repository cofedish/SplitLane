using System.Reflection;
using System.Runtime.InteropServices;
using SplitLane.Engine.Interop;

namespace SplitLane.Engine.Tests.Security;

/// <summary>
/// SL-SEC-020: every WinDivert call whose failure the engine reports records its own error, so a
/// reported Win32 code is the call's and not a stale one.
/// </summary>
[Trait("Category", "Security")]
public sealed class NativeErrorSecurityTests
{
    [Theory]
    [InlineData("Open")]
    [InlineData("Close")]
    [InlineData("Shutdown")]
    [InlineData("Recv")]
    [InlineData("Send")]
    [InlineData("SetParam")]
    [InlineData("GetParam")]
    public void Failures_that_are_reported_carry_their_own_error(string method)
    {
        var declaration = typeof(WinDivertNative).GetMethod(method, BindingFlags.Static | BindingFlags.NonPublic);

        Assert.NotNull(declaration);
        var import = declaration.GetCustomAttribute<LibraryImportAttribute>();
        Assert.NotNull(import);
        Assert.True(import.SetLastError, $"{method} does not set the last error");
    }
}
