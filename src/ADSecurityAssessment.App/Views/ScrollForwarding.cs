using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace ADSecurityAssessment.App.Views;

/// <summary>
/// Evita o problema clássico de "scroll preso": quando o mouse está sobre uma lista interna (com ScrollViewer próprio) que não
/// pode mais rolar naquela direção, a roda do mouse passa a rolar o ScrollViewer externo.
/// Uso: <c>views:ScrollForwarding.Enabled="True"</c> no ScrollViewer externo.
/// </summary>
public static class ScrollForwarding
{
    public static readonly DependencyProperty EnabledProperty =
        DependencyProperty.RegisterAttached("Enabled", typeof(bool), typeof(ScrollForwarding), new PropertyMetadata(false, OnEnabledChanged));

    public static bool GetEnabled(DependencyObject d) => (bool)d.GetValue(EnabledProperty);
    public static void SetEnabled(DependencyObject d, bool value) => d.SetValue(EnabledProperty, value);

    private static void OnEnabledChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not ScrollViewer viewer) return;
        viewer.PreviewMouseWheel -= OnPreviewMouseWheel;
        if (e.NewValue is true) viewer.PreviewMouseWheel += OnPreviewMouseWheel;
    }

    private static void OnPreviewMouseWheel(object sender, MouseWheelEventArgs e)
    {
        if (e.Handled || sender is not ScrollViewer outer) return;
        var inner = FindInnerScrollViewer(e.OriginalSource as DependencyObject, outer);
        if (inner is null) return;

        var up = e.Delta > 0;
        var innerCanScroll = inner.ScrollableHeight > 0 && (up ? inner.VerticalOffset > 0 : inner.VerticalOffset < inner.ScrollableHeight);
        if (innerCanScroll) return;

        e.Handled = true;
        outer.ScrollToVerticalOffset(outer.VerticalOffset - e.Delta);
    }

    private static ScrollViewer? FindInnerScrollViewer(DependencyObject? start, ScrollViewer outer)
    {
        var current = start;
        while (current is not null && !ReferenceEquals(current, outer))
        {
            if (current is ScrollViewer sv) return sv;
            current = current is Visual or System.Windows.Media.Media3D.Visual3D
                ? VisualTreeHelper.GetParent(current)
                : LogicalTreeHelper.GetParent(current);
        }
        return null;
    }
}
