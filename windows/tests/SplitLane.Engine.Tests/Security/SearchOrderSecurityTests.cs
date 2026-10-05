using System.Reflection;
using System.Runtime.InteropServices;
using SplitLane.Engine.Divert;
using SplitLane.Engine.Interop;
using SplitLane.Engine.Update;

namespace SplitLane.Engine.Tests.Security;

/// <summary>
/// SL-SEC-015: the LocalSystem engine loads WinDivert from its own directory by absolute path, resolves
/// every other native library from System32 only, and starts msiexec by absolute path.
/// </summary>
[Trait("Category", "Security")]
public sealed class SearchOrderSecurityTests
{
    [Fact]
    public void WinDivert_is_loaded_from_beside_the_engine_by_absolute_path()
    {
        Assert.True(Path.IsPathFullyQualified(WinDivertNative.LibraryPath));
        Assert.Equal(
            Path.Combine(AppContext.BaseDirectory, "WinDivert.dll"),
            WinDivertNative.LibraryPath,
            ignoreCase: true);
    }

    [Fact]
    public void Other_native_libraries_resolve_from_System32_only()
    {
        var attribute = typeof(DivertPipeline).Assembly.GetCustomAttribute<DefaultDllImportSearchPathsAttribute>();

        Assert.NotNull(attribute);
        Assert.Equal(DllImportSearchPath.System32, attribute.Paths);
    }

    [Fact]
    public void The_library_probe_looks_only_where_the_engine_loads_from()
    {
        // WinDivert.dll is copied beside the test binaries; loading it does not touch the driver.
        Assert.Equal(File.Exists(WinDivertNative.LibraryPath), DivertHandle.IsLibraryAvailable());
    }

    [Fact]
    public void The_installer_is_started_from_System32_by_absolute_path()
    {
        Assert.True(Path.IsPathFullyQualified(MsiexecInstaller.MsiexecPath));
        Assert.StartsWith(Environment.SystemDirectory, MsiexecInstaller.MsiexecPath, StringComparison.OrdinalIgnoreCase);
    }
}
