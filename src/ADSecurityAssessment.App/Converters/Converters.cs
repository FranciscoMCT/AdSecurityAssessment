using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.App.Converters;

internal static class Palette
{
    private static SolidColorBrush Freeze(string hex)
    {
        var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        b.Freeze();
        return b;
    }

    // Cores fixas (legíveis nos dois temas) para que não fiquem "velhas" quando o tema é trocado.
    public static readonly Brush Critical = Freeze("#C50F1F");
    public static readonly Brush High = Freeze("#D4510A");
    public static readonly Brush Medium = Freeze("#8A6700");
    public static readonly Brush Low = Freeze("#0F6CBD");
    public static readonly Brush Info = Freeze("#5B6678");
    public static readonly Brush Ok = Freeze("#13795B");
    public static readonly Brush Warn = Freeze("#9A6700");
    public static readonly Brush Bad = Freeze("#C50F1F");
    public static readonly Brush Neutral = Freeze("#6B7587");

    public static Brush ForSeverity(string? name) => name switch
    {
        "Critical" => Critical,
        "High" => High,
        "Medium" => Medium,
        "Low" => Low,
        _ => Info
    };

    public static Brush ForTone(string? tone) => tone switch
    {
        "Ok" => Ok,
        "Warn" => Warn,
        "Bad" => Bad,
        _ => Neutral
    };
}

/// <summary>Severidade (enum ou texto) → cor do badge.</summary>
public sealed class SeverityBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        Palette.ForSeverity(value is Severity s ? s.ToString() : value?.ToString());
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>"Ok" / "Warn" / "Bad" / "Neutral" → cor.</summary>
public sealed class ToneBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => Palette.ForTone(value?.ToString());
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>bool → Visibility. <see cref="Invert"/> inverte.</summary>
public sealed class BoolToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var flag = value is bool b && b;
        return flag ^ Invert ? Visibility.Visible : Visibility.Collapsed;
    }
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>null / texto vazio → Collapsed (ou o inverso com <see cref="Invert"/>).</summary>
public sealed class NullToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var has = value is not null && !(value is string s && string.IsNullOrWhiteSpace(s));
        return has ^ Invert ? Visibility.Visible : Visibility.Collapsed;
    }
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Score 0..100 → arco (anel de progresso) de 120×120, raio 52.</summary>
public sealed class ScoreArcConverter : IValueConverter
{
    private const double Center = 60, Radius = 52;

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var score = value is double d ? d : 0;
        score = Math.Clamp(score, 0, 100);
        if (score <= 0) return Geometry.Empty;
        var angle = Math.Min(score / 100.0 * 360.0, 359.99);
        var rad = (angle - 90) * Math.PI / 180.0;
        var end = new Point(Center + Radius * Math.Cos(rad), Center + Radius * Math.Sin(rad));
        var geometry = new StreamGeometry();
        using (var ctx = geometry.Open())
        {
            ctx.BeginFigure(new Point(Center, Center - Radius), false, false);
            ctx.ArcTo(end, new Size(Radius, Radius), 0, angle > 180, SweepDirection.Clockwise, true, false);
        }
        geometry.Freeze();
        return geometry;
    }
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}
