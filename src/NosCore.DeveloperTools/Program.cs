using NosCore.DeveloperTools.Forms;
using NosCore.DeveloperTools.Remote;
using NosCore.DeveloperTools.Services;

namespace NosCore.DeveloperTools;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        DiagnosticLog.Info("=== NosCore.DeveloperTools starting ===");
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception ex)
            {
                DiagnosticLog.Error("AppDomain unhandled", ex);
            }
        };
        Application.ThreadException += (_, args) =>
        {
            DiagnosticLog.Error("WinForms ThreadException", args.Exception);
        };

        try
        {
            ApplicationConfiguration.Initialize();
            var settingsService = new SettingsService();
            var processService = new ProcessService();
            using var injection = new RemoteAttachmentService();
            var log = new PacketLogService();
            var validation = new PacketValidationService();
            using var mainForm = new MainForm(settingsService, processService, injection, log, validation);
            DiagnosticLog.Info("MainForm constructed, Application.Run()");
            Application.Run(mainForm);
            DiagnosticLog.Info("Application.Run() returned normally");
        }
        catch (Exception ex)
        {
            DiagnosticLog.Error("Top-level startup", ex);
            throw;
        }
    }
}
