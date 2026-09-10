using System.Runtime.InteropServices;

namespace NosCore.DeveloperTools.Cli;

/// <summary>
/// Real mouse input for the client.
///
/// Posting WM_LBUTTONDOWN to the window does nothing here: the client
/// reads the mouse below the window-message layer, so a synthetic
/// message is simply never seen. Driving the actual system cursor is,
/// as far as the game is concerned, indistinguishable from a person.
///
/// This has to run at the client's integrity level, which the elevated
/// driver satisfies; from a normal process the injected input is
/// discarded by UIPI.
/// </summary>
internal static class Input
{
    private const uint MouseEventLeftDown = 0x0002;
    private const uint MouseEventLeftUp = 0x0004;

    [StructLayout(LayoutKind.Sequential)]
    private struct Point
    {
        public int X;
        public int Y;
    }

    [DllImport("user32.dll")]
    private static extern bool ClientToScreen(IntPtr window, ref Point point);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr window);

    [DllImport("user32.dll")]
    private static extern bool SetCursorPos(int x, int y);

    [DllImport("user32.dll")]
    private static extern bool GetCursorPos(out Point point);

    [DllImport("user32.dll")]
    private static extern void mouse_event(uint flags, int dx, int dy, uint data, IntPtr extraInfo);

    public static string Click(IntPtr window, int clientX, int clientY, bool restoreCursor = true)
    {
        if (window == IntPtr.Zero) throw new InvalidOperationException("No client window.");

        var point = new Point { X = clientX, Y = clientY };
        if (!ClientToScreen(window, ref point))
        {
            throw new InvalidOperationException("ClientToScreen failed.");
        }

        GetCursorPos(out var previous);

        SetForegroundWindow(window);
        Thread.Sleep(150);
        SetCursorPos(point.X, point.Y);
        // The client tracks hover state, and a click that arrives in the
        // same tick as the move can land before the control is highlighted.
        Thread.Sleep(150);

        mouse_event(MouseEventLeftDown, 0, 0, 0, IntPtr.Zero);
        Thread.Sleep(80);
        mouse_event(MouseEventLeftUp, 0, 0, 0, IntPtr.Zero);

        if (restoreCursor)
        {
            Thread.Sleep(150);
            SetCursorPos(previous.X, previous.Y);
        }

        return $"clicked client {clientX},{clientY} (screen {point.X},{point.Y})";
    }
}
