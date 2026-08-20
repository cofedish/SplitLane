using System.Windows;
using System.Windows.Threading;
using SplitLane.App.Infrastructure;
using SplitLane.App.Services;
using SplitLane.App.Theme;

namespace SplitLane.App;

/// <summary>Application entry point.</summary>
public partial class App : Application
{
    /// <inheritdoc />
    protected override void OnStartup(StartupEventArgs e)
    {
        // One window per session. A second copy used to open stacked over the first, which looked
        // like the title bar had grown a duplicate set of window buttons - and, less visibly, gave
        // two windows their own view of one configuration to save over each other.
        if (!SingleInstance.TryClaim())
        {
            SingleInstance.ActivateExisting();
            Shutdown();
            return;
        }

        Exit += (_, _) => SingleInstance.Release();

        // Paint before any window exists, so nothing is ever shown in the wrong theme and then
        // corrected in front of the user.
        var preferences = UiSettings.Load();
        ThemeService.Apply(preferences.Theme);

        // Following Windows means following it afterwards too, not only at startup.
        SystemTheme.StartListening();
        SystemTheme.Changed += () =>
        {
            if (UiSettings.Load().Theme == AppTheme.System)
            {
                Dispatcher.Invoke(() => ThemeService.Apply(AppTheme.System));
            }
        };

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
