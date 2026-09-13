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
    private static extern int GetClassNameW(IntPtr window, StringBuilder className, int count);

    private const string NosTaleWindowClass = "TNosTaleMainF";

    [StructLayout(LayoutKind.Sequential)]
    private struct Rect
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    /// <summary>
    /// The process's game window, matched by class, or zero while it has
    /// not created one yet. Size is only a fallback — the caption is never
    /// read, because that sends WM_GETTEXT and blocks on a busy client.
    /// </summary>
    public static IntPtr FindGameWindow(int processId, int minWidth = 640, int minHeight = 480)
    {
        var fallback = IntPtr.Zero;
        var fallbackArea = 0;
        var className = new StringBuilder(64);

        var window = IntPtr.Zero;
        while ((window = FindWindowExW(IntPtr.Zero, window, null, null)) != IntPtr.Zero)
        {
            GetWindowThreadProcessId(window, out var owner);
            if (owner != (uint)processId) continue;

            className.Clear();
            if (GetClassNameW(window, className, className.Capacity) > 0
                && className.ToString() == NosTaleWindowClass)
            {
                return window;
            }

            GetWindowRect(window, out var rect);
            var width = rect.Right - rect.Left;
            var height = rect.Bottom - rect.Top;
            if (width < minWidth || height < minHeight) continue;

            var area = width * height;
            if (area <= fallbackArea) continue;

            fallbackArea = area;
            fallback = window;
        }

        return fallback;
    }
}
