namespace NosCore.DeveloperTools.Hook;

internal enum ConnectResult
{
    Ok,
    NoConnectFunction,
    NoContext,
    NoClientThread,
}

/// <summary>
/// Opens the world connection the way the channel button does.
///
/// Until that button is pressed the client has no world socket at all,
/// so none of the in-game control works — which made logging in the one
/// step that still needed synthetic mouse clicks, with all the fragility
/// that carries.
///
/// The routine takes the connection object in EAX, and that object is
/// reached through the client's own UI state rather than a static slot.
/// Rather than chase the pointer chain, the routine is detoured purely
/// to record EAX the first time the client connects normally; from then
/// on the same object can be reused to reconnect without touching the
/// UI.
/// </summary>
internal static unsafe class WorldConnection
{
    public static IntPtr ConnectAddress { get; private set; }

    private static IntPtr _connectInvoker;
    private static IntPtr _trampoline;

    private static volatile IntPtr _context;
    private static int _observed;

    public static IntPtr Context => _context;

    public static int Observed => System.Threading.Volatile.Read(ref _observed);

    public static bool Install()
    {
        var address = PatternScanner.ScanMainModule(Signatures.WorldConnect);
        if (address == IntPtr.Zero) return false;

        ConnectAddress = address;
        _connectInvoker = ClientInvoker.BuildRegisterInvoker3(address);

        // Displace 5 bytes, not the default 6. The prologue is
        // push ebx / push esi / push edi / mov edi,ecx — exactly five —
        // and the next instruction is the two-byte mov esi,edx. Taking
        // six would cut that in half, leaving an orphaned operand byte
        // that the trampoline returns into; the routine then fails and
        // the client retries it forever.
        delegate* unmanaged[Stdcall]<IntPtr, IntPtr, void> hook = &OnConnect;
        _trampoline = Detour.Install(address, (IntPtr)hook, prologueSize: 5, arg: Detour.HookArg.EaxThenEdx);
        return _trampoline != IntPtr.Zero;
    }

    [System.Runtime.InteropServices.UnmanagedCallersOnly(
        CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvStdcall) })]
    private static void OnConnect(IntPtr eax, IntPtr edx)
    {
        _context = eax;
        var seen = System.Threading.Interlocked.Increment(ref _observed);

        try
        {
            // Announce only the first few. If a detour ever corrupts this
            // routine the client retries it thousands of times a second,
            // and logging each one buries everything else.
            if (seen <= 3)
            {
                var host = DelphiString.Read(edx);
                PipeServer.Announce($"world connect observed: object=0x{eax.ToInt64():X} host={host}");
            }
        }
        catch
        {
            // Never throw out of a hook — the target would crash.
        }
    }

    public static ConnectResult Connect(string host, int port)
    {
        if (ConnectAddress == IntPtr.Zero || _connectInvoker == IntPtr.Zero) return ConnectResult.NoConnectFunction;

        var context = _context;
        if (context == IntPtr.Zero) return ConnectResult.NoContext;

        var hostString = ClientInvoker.AllocAnsiString(host);
        var invoker = _connectInvoker;

        var invoked = NosThreadSynchronizer.Invoke(() =>
        {
            var connect = (delegate* unmanaged[Cdecl]<IntPtr, IntPtr, int, void>)invoker;
            connect(context, hostString, port);
        });

        return invoked ? ConnectResult.Ok : ConnectResult.NoClientThread;
    }
}
