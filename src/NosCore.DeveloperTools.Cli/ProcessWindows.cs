using System.Runtime.InteropServices;
using System.Text;

namespace NosCore.DeveloperTools.Cli;

/// <summary>
/// Finds the client's actual game window from outside the process.
///
/// Process.MainWindowHandle is not usable here: the client owns several
/// top-level windows and the one it reports is a zero-size helper that
/// exists almost immediately at startup. Treating that as "the client is
/// ready" meant injecting into a process that had barely initialised,
/// which killed it.
/// </summary>
internal static class ProcessWindows
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr FindWindowExW(IntPtr parent, IntPtr after, string? className, string? windowName);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);

    [DllImport("user32.dll")]
    private static extern bool GetWindowRect(IntPtr window, out Rect rect);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowTextW(IntPtr window, StringBuilder text, int count);

    [StructLayout(LayoutKind.Sequential)]
    private struct Rect
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    /// <summary>
    /// The largest captioned top-level window the process owns, or zero
    /// while it has none big enough to be the game window yet.
    /// </summary>
    public static IntPtr FindGameWindow(int processId, int minWidth = 640, int minHeight = 480)
    {
        var best = IntPtr.Zero;
        var bestArea = 0;

        var window = IntPtr.Zero;
        while ((window = FindWindowExW(IntPtr.Zero, window, null, null)) != IntPtr.Zero)
        {
            GetWindowThreadProcessId(window, out var owner);
            if (owner != (uint)processId) continue;

            var text = new StringBuilder(256);
            if (GetWindowTextW(window, text, text.Capacity) == 0) continue;

            GetWindowRect(window, out var rect);
            var width = rect.Right - rect.Left;
            var height = rect.Bottom - rect.Top;
            if (width < minWidth || height < minHeight) continue;

            var area = width * height;
            if (area <= bestArea) continue;

            bestArea = area;
            best = window;
        }

        return best;
    }
}
