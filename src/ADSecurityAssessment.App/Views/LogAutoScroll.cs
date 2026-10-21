using System.Collections.Specialized;
using System.Windows;
using System.Windows.Controls;

namespace ADSecurityAssessment.App.Views;

/// <summary>Mantém um ListBox de log rolado até a última linha.</summary>
public static class LogAutoScroll
{
    public static readonly DependencyProperty EnabledProperty =
        DependencyProperty.RegisterAttached("Enabled", typeof(bool), typeof(LogAutoScroll), new PropertyMetadata(false, OnEnabledChanged));

    public static bool GetEnabled(DependencyObject d) => (bool)d.GetValue(EnabledProperty);
    public static void SetEnabled(DependencyObject d, bool value) => d.SetValue(EnabledProperty, value);

    private static void OnEnabledChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not ListBox list) return;
        ((INotifyCollectionChanged)list.Items).CollectionChanged -= OnChanged;
        list.Loaded -= OnLoaded;
        if (e.NewValue is not true) return;
        ((INotifyCollectionChanged)list.Items).CollectionChanged += OnChanged;
        list.Loaded += OnLoaded;

        void OnChanged(object? sender, NotifyCollectionChangedEventArgs args) => ScrollToEnd(list);
        void OnLoaded(object sender, RoutedEventArgs args) => ScrollToEnd(list);
    }

    private static void ScrollToEnd(ListBox list)
    {
        if (list.Items.Count == 0) return;
        list.Dispatcher.BeginInvoke(() =>
        {
            if (list.Items.Count > 0) list.ScrollIntoView(list.Items[^1]);
        });
    }
}
