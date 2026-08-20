using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace SplitLane.App.Infrastructure;

/// <summary>
/// A content control that cross-fades when its page changes.
/// </summary>
/// <remarks>
/// <para>
/// The page swap is the most-seen transition in the app, so it is worth doing properly. The old page
/// fades out, the new one is put in place and laid out, and only then does it ease back in with a
/// small upward drift — enough motion to say "this is a different page" without the delay of a real
/// slide.
/// </para>
/// <para>
/// The order there is the whole point, and getting it wrong is what made this stutter. Assigning
/// content and starting its fade in the same breath means the first frames of the animation are
/// spent building and measuring a page that is already visible, so its elements visibly shuffle into
/// place while fading in. Layout is now forced while the page is still invisible: that frame costs
/// what it costs, and the animation that follows has nothing left to do but fade.
/// </para>
/// <para>
/// Built pages are kept. A page is a view over a view model that lives as long as the window, so
/// rebuilding its visual tree on every visit is work with no result — and it is precisely that work
/// which the eye reads as jank on the way back to a page it has already seen.
/// </para>
/// <para>
/// Durations are short on purpose. Anything past about 200ms stops reading as responsiveness and
/// starts reading as lag, and this runs every time someone clicks the sidebar.
/// </para>
/// </remarks>
public sealed class PageHost : ContentControl
{
    private static readonly Duration OutDuration = new(TimeSpan.FromMilliseconds(90));
    private static readonly Duration InDuration = new(TimeSpan.FromMilliseconds(200));

    private readonly TranslateTransform _slide = new();
    private readonly Dictionary<object, FrameworkElement> _pages = [];
    private bool _animating;
    private object? _pending;

    /// <summary>Builds the host.</summary>
    public PageHost()
    {
        RenderTransform = _slide;
        RenderTransformOrigin = new Point(0.5, 0.5);
    }

    /// <summary>Shows a page immediately, with no transition. For the first one.</summary>
    public void Show(object? page)
    {
        Content = page is null ? null : Realize(page);
        UpdateLayout();
    }

    /// <summary>Transitions to a page, fading the current one out first.</summary>
    public void Transition(object? page)
    {
        // A click that lands mid-transition is remembered rather than started. Two fades racing over
        // one opacity is how a rapid trip through the sidebar ends up on a half-visible page.
        if (_animating)
        {
            _pending = page;
            return;
        }

        if (Content is null)
        {
            Show(page);
            BeginEnter();
            return;
        }

        _animating = true;

        var fadeOut = new DoubleAnimation(1, 0, OutDuration)
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn },
        };

        fadeOut.Completed += (_, _) =>
        {
            // Swap and lay out while nothing is on screen. Opacity is still 0 here, so the cost of
            // realising a page that has never been shown is paid in a frame nobody sees.
            Content = page is null ? null : Realize(page);
            UpdateLayout();

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

    /// <summary>
    /// Turns a page view model into its view, building it once and keeping it thereafter.
    /// </summary>
    /// <remarks>
    /// The window declares an implicit <see cref="DataTemplate"/> per page type, and a content
    /// presenter would apply it afresh on every switch. Loading the template here instead, and
    /// handing the host a ready element, means going back to a page is a reparent rather than a
    /// rebuild.
    /// </remarks>
    private FrameworkElement Realize(object page)
    {
        if (_pages.TryGetValue(page, out var built))
        {
            return built;
        }

        var template = TryFindResource(new DataTemplateKey(page.GetType())) as DataTemplate;

        if (template?.LoadContent() is not FrameworkElement element)
        {
            // No template for this type. Rather than crash, show what a content presenter would have
            // shown - which for a view model is its type name, and is at least visibly wrong.
            var fallback = new ContentPresenter { Content = page };
            _pages[page] = fallback;
            return fallback;
        }

        element.DataContext = page;
        _pages[page] = element;
        return element;
    }

    private void BeginEnter()
    {
        var fadeIn = new DoubleAnimation(0, 1, InDuration)
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
        };

        var drift = new DoubleAnimation(8, 0, InDuration)
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
        };

        BeginAnimation(OpacityProperty, fadeIn);
        _slide.BeginAnimation(TranslateTransform.YProperty, drift);
    }
}
