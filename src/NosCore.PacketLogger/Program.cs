using NosCore.PacketLogger.Forms;
using NosCore.PacketLogger.Remote;
using NosCore.PacketLogger.Services;

namespace NosCore.PacketLogger;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        DiagnosticLog.Info("=== NosCore.PacketLogger starting ===");
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
            using var mainForm = new MainForm(settingsService, processService, injection, log);
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
