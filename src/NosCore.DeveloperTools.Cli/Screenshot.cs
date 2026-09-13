using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;

namespace NosCore.DeveloperTools.Cli;

/// <summary>
/// Captures the client window on its own.
///
/// Screen-scraping the desktop is not good enough here: the game window
/// is usually behind an editor, and it is larger than the desktop, so a
/// screen grab returns whatever happens to be on top plus a cropped
/// game. <see cref="Mode.Window"/> asks the window to render itself
/// instead, which ignores z-order and off-screen area entirely.
///
/// The driver is elevated to match the client, so it may read the
/// window; a normal-integrity process would be refused.
/// </summary>
internal static class Screenshot
{
    private const uint PwRenderFullContent = 0x00000002;

    public enum Mode
    {
        /// <summary>Ask the window to paint itself; survives occlusion.</summary>
        Window,

        /// <summary>Grab the desktop where the window sits. Needed when a
        /// window renders through an overlay that PrintWindow misses.</summary>
        Screen,
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Rect
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [DllImport("user32.dll")]
    private static extern bool GetWindowRect(IntPtr window, out Rect rect);

    [DllImport("user32.dll")]
    private static extern bool PrintWindow(IntPtr window, IntPtr deviceContext, uint flags);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr window);

    [DllImport("user32.dll")]
    private static extern bool SetWindowPos(IntPtr window, IntPtr after, int x, int y, int cx, int cy, uint flags);

    private const uint SwpNoSize = 0x0001;
    private const uint SwpNoZOrder = 0x0004;
    private const uint SwpShowWindow = 0x0040;

    public static string Capture(IntPtr window, Mode mode, string path)
    {
        if (window == IntPtr.Zero) throw new InvalidOperationException("No client window.");
        if (!GetWindowRect(window, out var rect)) throw new InvalidOperationException("GetWindowRect failed.");

        var width = rect.Right - rect.Left;
        var height = rect.Bottom - rect.Top;
        if (width <= 0 || height <= 0)
        {
            throw new InvalidOperationException($"Client window has no area ({width}x{height}).");
        }

        Directory.CreateDirectory(Path.GetDirectoryName(path) ?? ".");

        using var bitmap = new Bitmap(width, height, PixelFormat.Format32bppArgb);
        using (var graphics = Graphics.FromImage(bitmap))
        {
            if (mode == Mode.Window)
            {
                var dc = graphics.GetHdc();
                try
                {
                    if (!PrintWindow(window, dc, PwRenderFullContent))
                    {
                        throw new InvalidOperationException("PrintWindow failed.");
                    }
                }
                finally
                {
                    graphics.ReleaseHdc(dc);
                }
            }
            else
            {
                // The game window is larger than the desktop and sits at a
                // negative-bottom offset, so a screen grab of its rect would
                // be part desktop. Pull it to the origin and raise it first.
                SetWindowPos(window, IntPtr.Zero, 0, 0, 0, 0, SwpNoSize | SwpNoZOrder | SwpShowWindow);
                SetForegroundWindow(window);
                Thread.Sleep(600);
                GetWindowRect(window, out var moved);
                graphics.CopyFromScreen(moved.Left, moved.Top, 0, 0, bitmap.Size);
            }
        }

        bitmap.Save(path, ImageFormat.Png);
        return path;
    }

    /// <summary>
    /// True when the capture came back essentially uniform — the usual
    /// sign that a hardware-accelerated surface did not render into the
    /// device context, and that the screen mode should be tried instead.
    /// </summary>
    public static bool LooksBlank(string path)
    {
        using var bitmap = new Bitmap(path);

        // Skip the title bar: it always paints, so including it would make
        // an otherwise-black capture look like it had content.
        var top = Math.Min(bitmap.Height - 1, 48);
        var first = bitmap.GetPixel(0, top);

        for (var y = top; y < bitmap.Height; y += Math.Max(1, bitmap.Height / 40))
        {
            for (var x = 0; x < bitmap.Width; x += Math.Max(1, bitmap.Width / 40))
            {
                var pixel = bitmap.GetPixel(x, y);
                if (Math.Abs(pixel.R - first.R) > 8
                    || Math.Abs(pixel.G - first.G) > 8
                    || Math.Abs(pixel.B - first.B) > 8)
                {
                    return false;
                }
            }
        }

        return true;
    }
}
