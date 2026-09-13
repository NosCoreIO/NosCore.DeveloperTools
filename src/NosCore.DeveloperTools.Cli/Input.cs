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

    [DllImport("user32.dll")]
    private static extern bool SetWindowPos(IntPtr window, IntPtr after, int x, int y, int cx, int cy, uint flags);

    private const uint SwpNoSize = 0x0001;
    private const uint SwpNoMove = 0x0002;
    private const uint SwpNoZOrder = 0x0004;
    private const uint SwpShowWindow = 0x0040;

    private static readonly IntPtr HwndTopmost = -1;
    private static readonly IntPtr HwndNoTopmost = -2;

    public static string Click(IntPtr window, int clientX, int clientY, bool restoreCursor = true)
    {
        if (window == IntPtr.Zero) throw new InvalidOperationException("No client window.");

        var point = new Point { X = clientX, Y = clientY };
        if (!ClientToScreen(window, ref point))
        {
            throw new InvalidOperationException("ClientToScreen failed.");
        }

        // The game window is taller than the desktop and sits at a positive
        // offset, so lower controls map to screen coordinates past the
        // bottom edge. SetCursorPos clamps to the desktop, which silently
        // puts the click on whatever else is there — so pull the window to
        // the origin and recompute rather than clicking the wrong thing.
        var screen = System.Windows.Forms.SystemInformation.VirtualScreen;
        if (!screen.Contains(point.X, point.Y))
        {
            SetWindowPos(window, IntPtr.Zero, 0, 0, 0, 0, SwpNoSize | SwpNoZOrder);
            Thread.Sleep(250);

            point = new Point { X = clientX, Y = clientY };
            if (!ClientToScreen(window, ref point))
            {
                throw new InvalidOperationException("ClientToScreen failed after move.");
            }

            if (!screen.Contains(point.X, point.Y))
            {
                throw new InvalidOperationException(
                    $"Client point {clientX},{clientY} is off-screen at {point.X},{point.Y} even at the origin.");
            }
        }

        GetCursorPos(out var previous);

        // SetForegroundWindow alone is not enough: Windows refuses
        // foreground changes requested by a process that does not own it,
        // so the client stayed behind whatever was maximised and the click
        // — which goes to whatever is topmost at that point — landed on
        // the wrong application entirely. Forcing topmost is not subject
        // to that restriction.
        SetWindowPos(window, HwndTopmost, 0, 0, 0, 0, SwpNoMove | SwpNoSize | SwpShowWindow);
        SetForegroundWindow(window);
        Thread.Sleep(200);
        SetCursorPos(point.X, point.Y);
        // The client tracks hover state, and a click that arrives in the
        // same tick as the move can land before the control is highlighted.
        Thread.Sleep(150);

        mouse_event(MouseEventLeftDown, 0, 0, 0, IntPtr.Zero);
        Thread.Sleep(80);
        mouse_event(MouseEventLeftUp, 0, 0, 0, IntPtr.Zero);

        // Drop back out of topmost so the client does not sit permanently
        // over everything else on the desktop.
        SetWindowPos(window, HwndNoTopmost, 0, 0, 0, 0, SwpNoMove | SwpNoSize);

        if (restoreCursor)
        {
            Thread.Sleep(150);
            SetCursorPos(previous.X, previous.Y);
        }

        return $"clicked client {clientX},{clientY} (screen {point.X},{point.Y})";
    }
}
