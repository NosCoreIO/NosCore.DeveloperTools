using System.Runtime.InteropServices;
using System.Text;

namespace NosCore.DeveloperTools.Hook;

/// <summary>
/// Window and input control for the client, performed from inside it.
///
/// Doing this from the outside does not work: the client inherits the
/// launcher's elevation, so a normal-integrity process is refused by
/// UIPI — ShowWindow and SetWindowPos silently do nothing and posted
/// input is dropped. Running in-process sidesteps that entirely, since
/// a process is always allowed to drive its own windows.
/// </summary>
internal static class ClientWindow
{
    private const int SwRestore = 9;
    private const int SwShow = 5;
    private const uint WmLButtonDown = 0x0201;
    private const uint WmLButtonUp = 0x0202;
    private const uint WmMouseMove = 0x0200;
    private const int MkLButton = 0x0001;

    [StructLayout(LayoutKind.Sequential)]
    private struct Rect
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr FindWindowExW(IntPtr parent, IntPtr after, string? className, string? windowName);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr window);

    [DllImport("user32.dll")]
    private static extern bool IsIconic(IntPtr window);

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr window, int command);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr window);

    [DllImport("user32.dll")]
    private static extern bool GetWindowRect(IntPtr window, out Rect rect);

    [DllImport("user32.dll")]
    private static extern bool GetClientRect(IntPtr window, out Rect rect);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowTextW(IntPtr window, StringBuilder text, int count);

    [DllImport("user32.dll")]
    private static extern bool PostMessageW(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);

    /// <summary>
    /// Walks the top-level window list with FindWindowEx rather than
    /// EnumWindows: the latter needs a managed callback marshalled back
    /// into native code, which does not survive NativeAOT here and made
    /// the scan return nothing at all.
    ///
    /// Prefers the largest captioned window, since the client also owns
    /// zero-size helper windows that would otherwise win.
    /// </summary>
    public static IntPtr Find()
    {
        var pid = (uint)Environment.ProcessId;
        var best = IntPtr.Zero;
        var bestArea = -1;

        var window = IntPtr.Zero;
        while ((window = FindWindowExW(IntPtr.Zero, window, null, null)) != IntPtr.Zero)
        {
            GetWindowThreadProcessId(window, out var owner);
            if (owner != pid) continue;

            var text = new StringBuilder(256);
            if (GetWindowTextW(window, text, text.Capacity) == 0) continue;

            GetWindowRect(window, out var rect);
            var area = Math.Max(0, rect.Right - rect.Left) * Math.Max(0, rect.Bottom - rect.Top);
            if (area <= bestArea) continue;

            bestArea = area;
            best = window;
        }

        return best;
    }

    /// <summary>Every top-level window this process owns, for diagnosis.</summary>
    public static string List()
    {
        var pid = (uint)Environment.ProcessId;
        var found = new List<string>();

        var window = IntPtr.Zero;
        while ((window = FindWindowExW(IntPtr.Zero, window, null, null)) != IntPtr.Zero)
        {
            GetWindowThreadProcessId(window, out var owner);
            if (owner != pid) continue;

            var text = new StringBuilder(256);
            GetWindowTextW(window, text, text.Capacity);
            GetWindowRect(window, out var rect);
            found.Add($"0x{window.ToInt64():X}:'{text}':{rect.Right - rect.Left}x{rect.Bottom - rect.Top}" +
                $":visible={IsWindowVisible(window)}:iconic={IsIconic(window)}");
        }

        return found.Count == 0 ? "none" : string.Join(" ", found);
    }

    public static string Show()
    {
        var window = Find();
        if (window == IntPtr.Zero) return "no-window";

        if (IsIconic(window))
        {
            ShowWindow(window, SwRestore);
        }

        ShowWindow(window, SwShow);
        SetForegroundWindow(window);
        return Describe(window);
    }

    public static string Describe()
    {
        var window = Find();
        return window == IntPtr.Zero ? "no-window" : Describe(window);
    }

    private static string Describe(IntPtr window)
    {
        GetWindowRect(window, out var rect);
        GetClientRect(window, out var client);
        var title = new StringBuilder(256);
        GetWindowTextW(window, title, title.Capacity);

        return $"hwnd=0x{window.ToInt64():X} title='{title}' " +
            $"rect={rect.Left},{rect.Top},{rect.Right},{rect.Bottom} " +
            $"client={client.Right - client.Left}x{client.Bottom - client.Top} " +
            $"iconic={IsIconic(window)}";
    }

    /// <summary>
    /// Post a left click at a point in client coordinates. Posted rather
    /// than sent so the click lands on the client's own message loop
    /// instead of re-entering it from our thread.
    /// </summary>
    public static string Click(int x, int y)
    {
        var window = Find();
        if (window == IntPtr.Zero) return "no-window";

        var point = (IntPtr)((y << 16) | (x & 0xFFFF));
        PostMessageW(window, WmMouseMove, IntPtr.Zero, point);
        PostMessageW(window, WmLButtonDown, (IntPtr)MkLButton, point);
        PostMessageW(window, WmLButtonUp, IntPtr.Zero, point);
        return $"clicked {x},{y}";
    }
}
