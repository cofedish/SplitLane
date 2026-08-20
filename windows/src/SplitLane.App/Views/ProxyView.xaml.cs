using System.Windows.Controls;
using SplitLane.App.ViewModels;

namespace SplitLane.App.Views;

/// <summary>The Proxy page.</summary>
public partial class ProxyView : UserControl
{
    /// <summary>Builds the view.</summary>
    public ProxyView() => InitializeComponent();

    /// <summary>
    /// Copies the typed password into the view model.
    /// </summary>
    /// <remarks>
    /// <c>PasswordBox.Password</c> is deliberately not a dependency property, so it cannot be data
    /// bound — WPF refuses to let a password sit in the binding engine's caches. Pushing it across
    /// in the changed handler is the supported way, and it keeps the same property: the value moves
    /// straight to the credential store on save and is never held anywhere else.
    /// </remarks>
    private void OnPasswordChanged(object sender, System.Windows.RoutedEventArgs e)
    {
        if (DataContext is ProxyViewModel model && sender is System.Windows.Controls.PasswordBox box)
        {
            model.Password = box.Password;
        }
    }
}
