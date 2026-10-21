using System.Windows;
using System.Windows.Controls;
using ADSecurityAssessment.App.ViewModels;

namespace ADSecurityAssessment.App.Views;

public partial class StartView : UserControl
{
    public StartView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => Wire();
        Wire();
    }

    /// <summary>
    /// A senha fica somente no PasswordBox (SecureString). O ViewModel recebe uma CÓPIA no momento da conexão, descarta-a ao final
    /// da execução e pede para limpar o campo. Nada é gravado em disco, log ou configuração.
    /// </summary>
    private void Wire()
    {
        if (DataContext is not MainViewModel vm) return;
        vm.PasswordProvider = () => PasswordInput.SecurePassword.Copy();
        vm.ClearPassword = () => PasswordInput.Clear();
    }
}
