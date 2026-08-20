using System.ComponentModel;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;
using SplitLane.App.Infrastructure;
using SplitLane.App.ViewModels;

namespace SplitLane.App;

/// <summary>The application window.</summary>
public partial class MainWindow : Window
{
    private readonly MainViewModel _model = new();

    /// <summary>Builds the window.</summary>
    public MainWindow()
    {
        InitializeComponent();
        DataContext = _model;

        _model.PropertyChanged += OnModelPropertyChanged;

        Loaded += async (_, _) =>
        {
            PlayEntrance();
            await _model.StartAsync().ConfigureAwait(true);
        };

        Closed += (_, _) =>
        {
            _model.PropertyChanged -= OnModelPropertyChanged;
            _model.Stop();
        };

        StateChanged += (_, _) => UpdateMaximiseGlyph();
    }

    /// <inheritdoc />
    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);

        // The earliest point at which the window has an HWND, which every DWM call needs. Doing this
        // in the constructor is too early and silently does nothing.
        //
        // Acrylic rather than Mica. Mica samples the wallpaper and desaturates it heavily, which on
        // a dark desktop is indistinguishable from a plain dark window — the effect is technically
        // present and visually absent. Acrylic blurs whatever is actually behind the window, so the
        // glass reads as glass on any desktop.
        WindowEffects.Apply(this, Backdrop.Acrylic);
    }

    /// <summary>
    /// Routes the content host through its cross-fade instead of letting the binding swap instantly.
    /// </summary>
    /// <remarks>
    /// The host's <c>Content</c> is bound, so a plain binding update would replace the page with no
    /// transition at all. Intercepting the change here keeps the view model ignorant of animation.
    /// </remarks>
    private void OnModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.CurrentPage))
        {
            Pages.Transition(_model.CurrentPage);
        }
    }

    /// <summary>
    /// Fades the window in, so it does not simply appear.
    /// </summary>
    /// <remarks>
    /// Opacity only. A <c>Window</c> refuses a render transform —
    /// it throws on the next layout pass, not at the point of assignment, so the scale-up this used
    /// to do surfaced as an unrelated-looking error dialog seconds later. The content's own entrance
    /// drift lives in <see cref="PageHost"/>, where a transform is legal.
    /// </remarks>
    private void PlayEntrance()
    {
        var fade = new DoubleAnimation(0, 1, new Duration(TimeSpan.FromMilliseconds(280)))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
        };

        BeginAnimation(OpacityProperty, fade);
    }

    private void UpdateMaximiseGlyph() =>
        MaximiseGlyph.SetResourceReference(
            System.Windows.Shapes.Path.DataProperty,
            WindowState == WindowState.Maximized ? "IconRestore" : "IconMaximise");

    private void OnMinimise(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void OnMaximise(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void OnClose(object sender, RoutedEventArgs e) => Close();
}
