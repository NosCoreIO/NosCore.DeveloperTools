using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace NosCore.PacketLogger.Hook;

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
    public static int QueueDropped;

    private static IntPtr _sendTrampoline;
    private static IntPtr _recvTrampoline;
    private static IntPtr _loginRecvTrampoline;

    // Invoker thunks for re-entering the client's own send/recv functions
    // (Delphi register convention). Cached after scanning.
    private static IntPtr _worldSendInvoker;
    private static IntPtr _worldRecvInvoker;
    // Last-seen EAX (Delphi "self" context) from each hook firing —
    // needed as the first arg when we re-invoke the client's function.
    private static volatile IntPtr _worldSendContext;
    private static volatile IntPtr _worldRecvContext;

    public static InstallResult Install()
    {
        var result = new InstallResult();

        var sendAddr = PatternScanner.ScanMainModule(Signatures.Send);
        var recvAddr = PatternScanner.ScanMainModule(Signatures.Recv);
        var loginRecvAddr = PatternScanner.ScanMainModule(Signatures.LoginRecv);

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

        return result;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static void HookedSend(IntPtr eax, IntPtr edx)
    {
        _worldSendContext = eax;
        Capture(PacketDirection.Send, PacketConnection.World, edx);
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
            var invoker = (delegate* unmanaged[Cdecl]<IntPtr, IntPtr, void>)invokerPtr;
            invoker(ctx, ansi);
            return true;
        }
        catch
        {
            return false;
        }
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
    public IntPtr SendAddress;
    public IntPtr RecvAddress;
    public IntPtr LoginRecvAddress;
    public bool SendHooked;
    public bool RecvHooked;
    public bool LoginRecvHooked;
}
