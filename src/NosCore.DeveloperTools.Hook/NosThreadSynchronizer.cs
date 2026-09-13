using System.Collections.Concurrent;

namespace NosCore.DeveloperTools.Hook;

/// <summary>
/// Marshals work onto the client's own thread.
///
/// The client keeps its game state — scene graph, entity list, the
/// player's position — under no synchronisation at all, because only
/// one thread was ever meant to touch it. Our pipe reader is a
/// different thread, so calling a client routine straight from a pipe
/// command races the frame loop and corrupts that state.
///
/// The periodic detour calls <see cref="Tick"/> once per frame from the
/// right thread; commands queue work here and block until it has run
/// there.
/// </summary>
internal static class NosThreadSynchronizer
{
    private const int MaxWorkPerTick = 8;
    private const int DefaultTimeoutMs = 3000;

    private static readonly ConcurrentQueue<Action> Pending = new();
    private static long _ticks;
    private static volatile bool _installed;

    [ThreadStatic]
    private static bool _insideTick;

    public static long Ticks => Interlocked.Read(ref _ticks);

    /// <summary>
    /// True once the periodic detour is installed and has actually
    /// fired. Both halves matter: a signature can match a function that
    /// is never called, and queueing onto a tick that never comes would
    /// hang every command until it times out.
    /// </summary>
    public static bool IsRunning => _installed && Interlocked.Read(ref _ticks) > 0;

    public static void MarkInstalled() => _installed = true;

    public static void Tick()
    {
        Interlocked.Increment(ref _ticks);

        _insideTick = true;
        try
        {
            for (var i = 0; i < MaxWorkPerTick; i++)
            {
                if (!Pending.TryDequeue(out var work)) return;
                try
                {
                    work();
                }
                catch
                {
                    // Never throw out of the frame loop — the client would die.
                }
            }
        }
        finally
        {
            _insideTick = false;
        }
    }

    /// <summary>
    /// Run <paramref name="work"/> on the client thread and wait for it.
    /// False means it never ran: either no tick is available, or the
    /// client stopped ticking (minimised, frozen, shutting down).
    /// </summary>
    public static bool Invoke(Action work, int timeoutMs = DefaultTimeoutMs)
    {
        // Already on the client thread: queueing would wait for a tick
        // that cannot start until we return.
        if (_insideTick)
        {
            try
            {
                work();
            }
            catch
            {
            }

            return true;
        }

        if (!IsRunning) return false;

        var done = new ManualResetEventSlim(false);
        Pending.Enqueue(() =>
        {
            try
            {
                work();
            }
            finally
            {
                try { done.Set(); } catch { }
            }
        });

        var completed = done.Wait(timeoutMs);
        if (completed)
        {
            done.Dispose();
        }

        // On timeout the item stays queued and will Set() a later tick,
        // so the event is deliberately left undisposed rather than
        // racing a disposal against the client thread.
        return completed;
    }
}
