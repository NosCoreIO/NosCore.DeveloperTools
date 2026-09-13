using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace NosCore.DeveloperTools.Hook;

internal enum PacketDirection : byte
{
    Status = 0,
    Send = (byte)'S',
    Receive = (byte)'R',
}

internal enum PacketConnection : byte
{
    World = (byte)'W',
    Login = (byte)'L',
}

internal readonly record struct CapturedPacket(PacketDirection Direction, PacketConnection Connection, string Payload);

internal static unsafe class Hooks
{
    private const int QueueCap = 4096;

    public static readonly ConcurrentQueue<CapturedPacket> Queue = new();

    /// <summary>
    /// Command replies, kept apart from captured traffic. In-world the
    /// packet queue runs thousands of entries deep, and a reply sharing
    /// it arrived tens of seconds after the command that asked for it.
    /// </summary>
    public static readonly ConcurrentQueue<string> Replies = new();
    public static int QueueDropped;
    public static InstallResult LastInstall;

    private static IntPtr _sendTrampoline;
    private static IntPtr _recvTrampoline;
    private static IntPtr _loginRecvTrampoline;
    private static IntPtr _periodicTrampoline;

    // Invoker thunks for re-entering the client's own send/recv functions
    // (Delphi register convention). Cached after scanning.
    private static IntPtr _worldSendInvoker;
    private static IntPtr _worldRecvInvoker;
    // Last-seen EAX (Delphi "self" context) from each hook firing —
    // needed as the first arg when we re-invoke the client's function.
    private static volatile IntPtr _worldSendContext;
    private static volatile IntPtr _worldRecvContext;

    /// <summary>
    /// Which detours to install, from <c>_NC_HOOKS</c> in the client's
    /// environment (comma-separated: send, recv, login-recv, periodic).
    /// Unset means all of them. A detour that destabilises the client
    /// can only be identified by leaving it out, and the launcher owns
    /// the client's environment, so this is the one setting available
    /// before any code runs.
    /// </summary>
    private static bool Enabled(string name)
    {
        var configured = Environment.GetEnvironmentVariable("_NC_HOOKS");
        if (string.IsNullOrWhiteSpace(configured)) return true;

        foreach (var part in configured.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            if (part.Trim().Equals(name, StringComparison.OrdinalIgnoreCase)) return true;
        }

        return false;
    }

    public static InstallResult Install()
    {
        var result = new InstallResult();

        // Must precede every detour: trampolines bake in the stub address.
        RuntimeBootstrap.Initialize();
        result.BootstrapStatus = RuntimeBootstrap.Status;

        var sendAddr = Enabled("send") ? PatternScanner.ScanMainModule(Signatures.Send) : IntPtr.Zero;
        var recvAddr = Enabled("recv") ? PatternScanner.ScanMainModule(Signatures.Recv) : IntPtr.Zero;
        var loginRecvAddr = Enabled("login-recv") ? PatternScanner.ScanMainModule(Signatures.LoginRecv) : IntPtr.Zero;

        result.SendAddress = sendAddr;
        result.RecvAddress = recvAddr;
        result.LoginRecvAddress = loginRecvAddr;

        if (sendAddr != IntPtr.Zero)
        {
            delegate* unmanaged[Stdcall]<IntPtr, IntPtr, void> sendHook = &HookedSend;
            _sendTrampoline = Detour.Install(sendAddr, (IntPtr)sendHook, arg: Detour.HookArg.EaxThenEdx);
            result.SendHooked = _sendTrampoline != IntPtr.Zero;
            _worldSendInvoker = ClientInvoker.BuildRegisterInvoker(sendAddr);
        }

        if (recvAddr != IntPtr.Zero)
        {
            delegate* unmanaged[Stdcall]<IntPtr, IntPtr, void> recvHook = &HookedRecv;
            _recvTrampoline = Detour.Install(recvAddr, (IntPtr)recvHook, arg: Detour.HookArg.EaxThenEdx);
            result.RecvHooked = _recvTrampoline != IntPtr.Zero;
            _worldRecvInvoker = ClientInvoker.BuildRegisterInvoker(recvAddr);
        }

        if (loginRecvAddr != IntPtr.Zero)
        {
            // Mid-function hook: 9 bytes of straight-line lea/push/lea/mov to
            // displace. Trampoline pushes EBP; managed hook dereferences
            // [EBP-0x08] to get the full cleartext packet pointer.
            delegate* unmanaged[Stdcall]<IntPtr, void> loginRecvHook = &HookedLoginRecv;
            _loginRecvTrampoline = Detour.Install(loginRecvAddr, (IntPtr)loginRecvHook,
                prologueSize: 9, arg: Detour.HookArg.Ebp);
            result.LoginRecvHooked = _loginRecvTrampoline != IntPtr.Zero;
        }

        var periodicAddr = Enabled("periodic") ? PatternScanner.ScanMainModule(Signatures.Periodic) : IntPtr.Zero;
        result.PeriodicAddress = periodicAddr;
        if (periodicAddr != IntPtr.Zero)
        {
            delegate* unmanaged[Stdcall]<void> periodicHook = &HookedPeriodic;
            _periodicTrampoline = Detour.Install(periodicAddr, (IntPtr)periodicHook,
                prologueSize: Signatures.PeriodicPrologueSize, arg: Detour.HookArg.None);
            result.PeriodicHooked = _periodicTrampoline != IntPtr.Zero;
            if (result.PeriodicHooked)
            {
                NosThreadSynchronizer.MarkInstalled();
            }
        }

        if (Enabled("connect"))
        {
            result.ConnectHooked = WorldConnection.Install();
            result.ConnectAddress = WorldConnection.ConnectAddress;
        }

        PlayerManager.Resolve();
        result.PlayerManagerStaticAddress = PlayerManager.StaticAddress;
        result.WalkAddress = PlayerManager.WalkAddress;

        LastInstall = result;
        return result;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static void HookedPeriodic() => NosThreadSynchronizer.Tick();

    public static WalkResult Walk(ushort x, ushort y, (int Un0, int Un1)? extraArgs) =>
        PlayerManager.Walk(x, y, extraArgs);

    /// <summary>
    /// Reads the character's position on the client thread where
    /// possible, so a position sampled mid-move can't be a torn read of
    /// coordinates the frame loop is writing.
    /// </summary>
    public static bool TryGetPosition(out int id, out ushort x, out ushort y)
    {
        var readId = 0;
        ushort readX = 0;
        ushort readY = 0;
        var read = false;

        if (NosThreadSynchronizer.Invoke(() => read = PlayerManager.TryGetPosition(out readId, out readX, out readY)))
        {
            id = readId;
            x = readX;
            y = readY;
            return read;
        }

        return PlayerManager.TryGetPosition(out id, out x, out y);
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static void HookedSend(IntPtr eax, IntPtr edx)
    {
        _worldSendContext = eax;
        Capture(PacketDirection.Send, PacketConnection.World, edx);
    }

    private static volatile string? _lastPublishedNosMallUrl;
    private static int _nosMallPollerStarted;

    /// <summary>
    /// Start a background thread that periodically scans the heap for the
    /// NosMall URL. First time the formatted URL shows up (user opens
    /// NosMall in-game), it publishes a NOSMALLURL line over the pipe.
    /// No-ops after install if called again.
    /// </summary>
    public static void StartNosMallPoller()
    {
        if (Interlocked.Exchange(ref _nosMallPollerStarted, 1) != 0) return;
        var thread = new Thread(NosMallPollLoop) { IsBackground = true, Name = "NosMallPoll" };
        thread.Start();
    }

    public static void TriggerNosMallRescan() => ThreadPool.QueueUserWorkItem(_ => PublishNosMallUrlIfNew());

    private static void NosMallPollLoop()
    {
        while (true)
        {
            try
            {
                PublishNosMallUrlIfNew();
            }
            catch
            {
                // Never throw out of the poller — the target would crash.
            }
            Thread.Sleep(2000);
        }
    }

    private static void PublishNosMallUrlIfNew()
    {
        var url = HeapScanner.FindNosMallUrl();
        if (string.IsNullOrEmpty(url)) return;
        if (url == _lastPublishedNosMallUrl) return;
        _lastPublishedNosMallUrl = url;
        Queue.Enqueue(new CapturedPacket(PacketDirection.Status, PacketConnection.World, "NOSMALLURL " + url));
    }

    /// <summary>
    /// Attempt to inject <paramref name="packet"/> as if the client
    /// itself were sending it. Requires that a real world-send has
    /// already fired at least once so we've captured a valid Delphi
    /// "self" context. Returns true on success.
    /// </summary>
    public static bool InjectWorldSend(string packet) =>
        InjectViaInvoker(packet, _worldSendInvoker, _worldSendContext);

    public static bool InjectWorldRecv(string packet) =>
        InjectViaInvoker(packet, _worldRecvInvoker, _worldRecvContext);

    private static bool InjectViaInvoker(string packet, IntPtr invokerPtr, IntPtr ctx)
    {
        if (string.IsNullOrEmpty(packet)) return false;
        if (invokerPtr == IntPtr.Zero || ctx == IntPtr.Zero) return false;

        try
        {
            var ansi = ClientInvoker.AllocAnsiString(packet);

            // Prefer the client's own thread. The direct call is kept as a
            // fallback so injection still works if the periodic signature
            // drifts — it races the frame loop, which is survivable for
            // send/recv but is why movement never takes this path.
            if (NosThreadSynchronizer.Invoke(() => CallInvoker(invokerPtr, ctx, ansi)))
            {
                return true;
            }

            CallInvoker(invokerPtr, ctx, ansi);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void CallInvoker(IntPtr invokerPtr, IntPtr ctx, IntPtr ansi)
    {
        var invoker = (delegate* unmanaged[Cdecl]<IntPtr, IntPtr, void>)invokerPtr;
        invoker(ctx, ansi);
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static void HookedRecv(IntPtr eax, IntPtr edx)
    {
        _worldRecvContext = eax;
        Capture(PacketDirection.Receive, PacketConnection.World, edx);
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static void HookedLoginRecv(IntPtr ebp)
    {
        if (ebp == IntPtr.Zero) return;
        var packetPtr = *(IntPtr*)(ebp - 8);
        Capture(PacketDirection.Receive, PacketConnection.Login, packetPtr);
    }

    private static void Capture(PacketDirection direction, PacketConnection connection, IntPtr packetPtr)
    {
        try
        {
            var text = DelphiString.Read(packetPtr);
            if (string.IsNullOrEmpty(text)) return;
            if (Queue.Count >= QueueCap)
            {
                Interlocked.Increment(ref QueueDropped);
                return;
            }
            Queue.Enqueue(new CapturedPacket(direction, connection, text));
        }
        catch
        {
            // Never throw out of a hook — the target would crash.
        }
    }
}

internal struct InstallResult
{
    public IntPtr ConnectAddress;
    public bool ConnectHooked;
    public string? BootstrapStatus;
    public IntPtr PeriodicAddress;
    public IntPtr PlayerManagerStaticAddress;
    public IntPtr WalkAddress;
    public bool PeriodicHooked;
    public IntPtr SendAddress;
    public IntPtr RecvAddress;
    public IntPtr LoginRecvAddress;
    public bool SendHooked;
    public bool RecvHooked;
    public bool LoginRecvHooked;
}
