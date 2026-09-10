namespace NosCore.DeveloperTools.Cli;

internal static class Program
{
    private const int DefaultPort = 8787;

    [STAThread]
    private static async Task<int> Main(string[] args)
    {
        var port = ParsePort(args) ?? DefaultPort;

        await using var driver = new ClientDriver();
        var server = new ControlServer(driver, port);

        Console.WriteLine($"NosCore client driver listening on http://127.0.0.1:{port}");
        Console.WriteLine("  POST /launch   {password}            auth + start the patched client");
        Console.WriteLine("  POST /attach   {pid?}                inject the hook, open the pipe");
        Console.WriteLine("  GET  /diag                           resolved signatures, tick count, in-world");
        Console.WriteLine("  GET  /pos                            live character id and coordinates");
        Console.WriteLine("  POST /walk     {x, y}                move via the client's own routine");
        Console.WriteLine("  POST /inject   {payload, direction}  raw packet injection");
        Console.WriteLine("  GET  /packets?since=N&contains=      captured traffic");
        Console.WriteLine("  GET  /log?since=N                    hook status lines");
        Console.WriteLine("  GET  /quit                           stop the driver");

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
