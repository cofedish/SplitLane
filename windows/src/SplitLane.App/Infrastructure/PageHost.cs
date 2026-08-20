using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace SplitLane.App.Infrastructure;

/// <summary>
/// A content control that cross-fades when its content changes.
/// </summary>
/// <remarks>
/// <para>
/// The page swap is the most-seen transition in the app, so it is worth doing properly. Content is
/// held for the length of an outgoing fade, then replaced and eased back in with a small upward
/// drift — enough motion to say "this is a different page" without the delay of a real slide.
/// </para>
/// <para>
/// Durations are short on purpose. Anything past about 200ms stops reading as responsiveness and
/// starts reading as lag, and this runs every time someone clicks the sidebar.
/// </para>
/// </remarks>
public sealed class PageHost : ContentControl
{
    private static readonly Duration OutDuration = new(TimeSpan.FromMilliseconds(110));
    private static readonly Duration InDuration = new(TimeSpan.FromMilliseconds(220));

    private readonly TranslateTransform _slide = new();
    private bool _animating;
    private object? _pending;

    /// <summary>Builds the host.</summary>
    public PageHost()
    {
        RenderTransform = _slide;
        RenderTransformOrigin = new Point(0.5, 0.5);
    }

    /// <inheritdoc />
    protected override void OnContentChanged(object oldContent, object newContent)
    {
        base.OnContentChanged(oldContent, newContent);

        if (oldContent is null || _animating)
        {
            // First assignment, or a change that arrived mid-transition. The latter is queued rather
            // than started, so rapid clicks through the sidebar cannot leave two fades fighting over
            // the same opacity.
            if (_animating)
            {
                _pending = newContent;
            }

            return;
        }

        BeginEnter();
    }

    /// <summary>Starts a transition to new content, fading the old out first.</summary>
    public void Transition(object? newContent)
    {
        if (_animating)
        {
            _pending = newContent;
            return;
        }

        if (Content is null)
        {
            Content = newContent;
            return;
        }

        _animating = true;

        var fadeOut = new DoubleAnimation(1, 0, OutDuration)
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn },
        };

        fadeOut.Completed += (_, _) =>
        {
            Content = newContent;
            _animating = false;
            BeginEnter();

            if (_pending is not null)
            {
                var queued = _pending;
                _pending = null;
                Transition(queued);
            }
        };

        BeginAnimation(OpacityProperty, fadeOut);
    }

    private void BeginEnter()
    {
        var fadeIn = new DoubleAnimation(0, 1, InDuration)
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
        };

        var drift = new DoubleAnimation(10, 0, InDuration)
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
        };

        BeginAnimation(OpacityProperty, fadeIn);
        _slide.BeginAnimation(TranslateTransform.YProperty, drift);
    }
}
