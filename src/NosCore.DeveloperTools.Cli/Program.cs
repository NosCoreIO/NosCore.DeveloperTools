using System.Runtime.InteropServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace NosCore.DeveloperTools.Cli;

internal static class Program
{
    private const int DefaultPort = 8787;

    // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
    private static readonly IntPtr PerMonitorAwareV2 = -4;

    [DllImport("user32.dll")]
    private static extern bool SetProcessDpiAwarenessContext(IntPtr context);

    [STAThread]
    private static async Task<int> Main(string[] args)
    {
        // The client is DPI-aware: window rects and captured pixels are
        // physical. Match it, or clicks aimed from a screenshot miss on a
        // scaled display.
        try { SetProcessDpiAwarenessContext(PerMonitorAwareV2); } catch { }

        if (args.Contains("--mcp"))
        {
            return await RunMcpAsync(args);
        }

        return await RunHttpAsync(args);
    }

    /// <summary>
    /// MCP stdio server. Exposes the client-control tools to an MCP host
    /// (e.g. Claude Code). One process = one persistent <see cref="ClientDriver"/>,
    /// so the hook session and launched client survive across tool calls.
    /// Must be started elevated (injection needs it) — run the MCP host
    /// itself as admin so this child inherits elevation without a UAC prompt.
    /// </summary>
    private static async Task<int> RunMcpAsync(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(args);
        // stdout is the MCP transport — every log line MUST go to stderr.
        builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);
        builder.Services.AddSingleton<ClientDriver>();
        builder.Services.AddMcpServer()
            .WithStdioServerTransport()
            .WithToolsFromAssembly();
        await builder.Build().RunAsync();
        return 0;
    }

    private static async Task<int> RunHttpAsync(string[] args)
    {
        var port = ParsePort(args) ?? DefaultPort;
        await using var driver = new ClientDriver();
        var server = new ControlServer(driver, port);

        Console.WriteLine($"NosCore client driver listening on http://127.0.0.1:{port}");
        Console.WriteLine("  (run with --mcp to expose the same control as an MCP stdio server instead)");

        try
        {
            await server.RunAsync();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Driver stopped: {ex.Message}");
            return 1;
        }

        return 0;
    }

    private static int? ParsePort(string[] args)
    {
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i] is "--port" or "-p" && int.TryParse(args[i + 1], out var port)) return port;
        }

        return null;
    }
}
