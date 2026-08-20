using System.Windows;
using System.Windows.Threading;

namespace SplitLane.App;

/// <summary>Application entry point.</summary>
public partial class App : Application
{
    /// <inheritdoc />
    protected override void OnStartup(StartupEventArgs e)
    {
        // A crash in a UI handler must not vanish silently: the window would keep running in an
        // inconsistent state and the user would have no idea why a page stopped updating.
        DispatcherUnhandledException += OnDispatcherUnhandledException;

        base.OnStartup(e);
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show(
            $"{e.Exception.GetType().Name}: {e.Exception.Message}",
            "SplitLane encountered a problem",
            MessageBoxButton.OK,
            MessageBoxImage.Error);

        e.Handled = true;
    }
}
