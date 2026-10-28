using System.Windows;
using System.Windows.Threading;

namespace ADSecurityAssessment.HardeningApp;

public partial class App : Application
{
    public App()
    {
        DispatcherUnhandledException += OnUnhandled;
    }

    private static void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show("Erro inesperado: " + e.Exception.Message + "\n\nNenhuma alteração parcial é deixada pela ferramenta; consulte a pasta logs.",
            "AD Security Hardening", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
