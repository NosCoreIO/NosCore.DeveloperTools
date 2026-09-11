using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace NosCore.DeveloperTools.Hook;

/// <summary>
/// Attaches an arbitrary client thread to this NativeAOT image before a
/// detour enters managed code.
///
/// Every hook body is a reverse P/Invoke, and AOT's prologue expects a
/// per-thread context in this module's static TLS slot. The loader only
/// populates that slot for threads created after the DLL is loaded — and
/// we inject into a running client, so every thread that matters already
/// existed. A detour that fires on such a thread reads an empty slot and
/// takes the client down with it.
///
/// Two detours were needed to see it: alone, each happened to fire only
/// on threads that were fine; together, one of them reached a thread that
/// was not, roughly twenty seconds in.
///
/// The stub below performs, in hand-written x86, what
/// <c>DLL_THREAD_ATTACH</c> would have done: allocate this thread's TLS
/// block, seed it from the image's template, publish it in the TEB, then
/// run the image's TLS callbacks and entry point. It returns 1 when the
/// thread is safe to enter and 0 when it is not, and the trampoline
/// skips the managed hook entirely on 0 — dropping a packet is always
/// better than killing the client.
/// </summary>
internal static unsafe class RuntimeBootstrap
{
    private const uint TebThreadLocalStoragePointer = 0x2C;
    private const uint HeapZeroMemory = 0x08;
    private const uint DllThreadAttach = 2;
    private const int MaxCallbacks = 8;

    private const uint GetModuleHandleFromAddress = 0x00000004;
    private const uint GetModuleHandleUnchangedRefcount = 0x00000002;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetModuleHandleExW(uint flags, IntPtr address, out IntPtr module);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern IntPtr GetModuleHandleA(string moduleName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern IntPtr GetProcAddress(IntPtr module, string functionName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint type, uint protect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(IntPtr address, UIntPtr size, uint newProtect, out uint oldProtect);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern bool FlushInstructionCache(IntPtr process, IntPtr address, UIntPtr size);

    public static IntPtr Stub { get; private set; }

    public static string Status { get; private set; } = "not-initialised";

    /// <summary>Anchor used only to locate this image's base address.</summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static int Anchor() => 0;

    public static void Initialize()
    {
        if (Stub != IntPtr.Zero) return;

        // The stub re-runs the image's TLS callbacks and DLL_THREAD_ATTACH
        // by hand. That is right when the image was manual-mapped and the
        // loader never did it, but we arrive via LoadLibrary, where the
        // loader does it for every thread created after the load — so on
        // those threads this would attach a second time. Kept switchable
        // until that is proven harmless here.
        if (Environment.GetEnvironmentVariable("_NC_BOOTSTRAP") == "0")
        {
            Status = "disabled";
            return;
        }

        try
        {
            Status = Build();
        }
        catch (Exception ex)
        {
            Status = $"failed: {ex.Message}";
        }
    }

    private static string Build()
    {
        delegate*<int> anchor = &Anchor;
        if (!GetModuleHandleExW(
                GetModuleHandleFromAddress | GetModuleHandleUnchangedRefcount, (IntPtr)anchor, out var module)
            || module == IntPtr.Zero)
        {
            return "no-module-handle";
        }

        var image = (byte*)module;
        if (*(ushort*)image != 0x5A4D) return "not-a-pe";

        var nt = image + *(int*)(image + 0x3C);
        if (*(uint*)nt != 0x00004550) return "bad-nt-header";

        var optional = nt + 0x18;
        if (*(ushort*)optional != 0x010B) return "not-pe32";

        var entryPointRva = *(uint*)(optional + 0x10);

        // DataDirectory[9] is IMAGE_DIRECTORY_ENTRY_TLS; PE32 puts the
        // directory array at OptionalHeader + 0x60.
        var tlsDirectory = (uint*)(optional + 0x60 + (9 * 8));
        if (tlsDirectory[0] == 0) return "no-tls-directory";

        var tls = (uint*)(image + tlsDirectory[0]);
        var rawDataStart = tls[0];
        var rawDataEnd = tls[1];
        var addressOfIndex = tls[2];
        var addressOfCallbacks = tls[3];
        var zeroFillSize = tls[4];

        if (addressOfIndex == 0) return "no-tls-index";
        var staticTlsIndex = *(uint*)addressOfIndex;
        var rawDataSize = rawDataEnd > rawDataStart ? rawDataEnd - rawDataStart : 0;

        var callbacks = stackalloc uint[MaxCallbacks];
        var callbackCount = 0u;
        if (addressOfCallbacks != 0)
        {
            var entry = (uint*)addressOfCallbacks;
            while (callbackCount < MaxCallbacks && entry[callbackCount] != 0)
            {
                callbacks[callbackCount] = entry[callbackCount];
                callbackCount++;
            }
        }

        var kernel32 = GetModuleHandleA("kernel32.dll");
        if (kernel32 == IntPtr.Zero) return "no-kernel32";
        var getProcessHeap = GetProcAddress(kernel32, "GetProcessHeap");
        var heapAlloc = GetProcAddress(kernel32, "HeapAlloc");
        if (getProcessHeap == IntPtr.Zero || heapAlloc == IntPtr.Zero) return "no-heap-exports";

        var code = Emit(
            (uint)module, entryPointRva, staticTlsIndex, addressOfIndex, rawDataStart, rawDataSize, zeroFillSize,
            callbacks, callbackCount, (uint)getProcessHeap, (uint)heapAlloc);

        var stub = VirtualAlloc(IntPtr.Zero, (UIntPtr)(uint)code.Length, 0x1000 | 0x2000, 0x04);
        if (stub == IntPtr.Zero) return "stub-alloc-failed";

        Marshal.Copy(code, 0, stub, code.Length);
        if (!VirtualProtect(stub, (UIntPtr)(uint)code.Length, 0x20, out _)) return "stub-protect-failed";
        FlushInstructionCache(GetCurrentProcess(), stub, (UIntPtr)(uint)code.Length);

        Stub = stub;
        return $"ok tls-index={staticTlsIndex} callbacks={callbackCount} raw={rawDataSize} zero={zeroFillSize}";
    }

    private static byte[] Emit(
        uint imageBase, uint entryPointRva, uint staticTlsIndex, uint indexValueAddr, uint rawDataAddr,
        uint rawDataSize, uint zeroFillSize, uint* callbacks, uint callbackCount, uint getProcessHeap, uint heapAlloc)
    {
        var code = new List<byte>(256);

        void U32(uint value) => code.AddRange(BitConverter.GetBytes(value));
        void MovEax(uint value) { code.Add(0xB8); U32(value); }
        void MovEcx(uint value) { code.Add(0xB9); U32(value); }
        void MovEsi(uint value) { code.Add(0xBE); U32(value); }
        void Push(uint value) { code.Add(0x68); U32(value); }
        void CallEax() { code.Add(0xFF); code.Add(0xD0); }
        void AddEax(byte value) { code.Add(0x83); code.Add(0xC0); code.Add(value); }

        int JzNear() { code.Add(0x0F); code.Add(0x84); var at = code.Count; U32(0); return at; }
        int JnzNear() { code.Add(0x0F); code.Add(0x85); var at = code.Count; U32(0); return at; }
        void Patch(int at, int target)
        {
            var bytes = BitConverter.GetBytes(target - (at + 4));
            for (var i = 0; i < bytes.Length; i++) code[at + i] = bytes[i];
        }

        code.Add(0x53);
        code.Add(0x56);
        code.Add(0x57);

        var staticSlotOffset = staticTlsIndex * 4;
        var blockSize = Math.Max(rawDataSize + zeroFillSize, 4u);

        code.Add(0xC7); code.Add(0x05); U32(indexValueAddr); U32(staticTlsIndex);
        code.Add(0x64); code.Add(0x8B); code.Add(0x35); U32(TebThreadLocalStoragePointer);
        code.Add(0x85); code.Add(0xF6);
        var noInitialTlsArray = JzNear();
        code.Add(0x8B); code.Add(0x96); U32(staticSlotOffset);
        code.Add(0x85); code.Add(0xD2);
        var alreadyAttached = JnzNear();

        Patch(noInitialTlsArray, code.Count);
        MovEax(getProcessHeap);
        CallEax();
        Push(blockSize + 4);
        Push(HeapZeroMemory);
        code.Add(0x50);
        MovEax(heapAlloc);
        CallEax();
        code.Add(0x85); code.Add(0xC0);
        var failAlloc = JzNear();
        // ntdll frees the TLS block by its allocation base, so keep it in
        // the first dword and hand out the memory after it.
        code.Add(0x89); code.Add(0x00);
        AddEax(4);
        code.Add(0x8B); code.Add(0xD0);

        if (rawDataSize != 0)
        {
            code.Add(0x8B); code.Add(0xFA);
            MovEsi(rawDataAddr);
            MovEcx(rawDataSize);
            code.Add(0xFC);
            code.Add(0xF3); code.Add(0xA4);
        }

        code.Add(0x64); code.Add(0x8B); code.Add(0x35); U32(TebThreadLocalStoragePointer);
        code.Add(0x85); code.Add(0xF6);
        var hasTlsArray = JnzNear();
        MovEax(getProcessHeap);
        CallEax();
        Push(8 + ((staticTlsIndex + 1) * 4));
        Push(HeapZeroMemory);
        code.Add(0x50);
        MovEax(heapAlloc);
        CallEax();
        code.Add(0x85); code.Add(0xC0);
        var failTlsArrayAlloc = JzNear();
        code.Add(0xC7); code.Add(0x00); U32(staticTlsIndex + 1);
        AddEax(8);
        code.Add(0x8B); code.Add(0xF0);
        code.Add(0x64); code.Add(0x89); code.Add(0x35); U32(TebThreadLocalStoragePointer);

        Patch(hasTlsArray, code.Count);
        code.Add(0x89); code.Add(0x96); U32(staticSlotOffset);
        code.Add(0x8D); code.Add(0x72); code.Add(0x08);
        code.Add(0xC7); code.Add(0x46); code.Add(0x30); U32(0xFFFFFFFF);

        for (var i = 0; i < callbackCount; i++)
        {
            Push(0);
            Push(DllThreadAttach);
            Push(imageBase);
            MovEax(callbacks[i]);
            CallEax();
        }

        if (entryPointRva != 0)
        {
            Push(0);
            Push(DllThreadAttach);
            Push(imageBase);
            MovEax(imageBase + entryPointRva);
            CallEax();
        }

        // Deliberately do NOT rewrite the TLS slot here: the callbacks above
        // stored AOT's own per-thread context in it, and that is exactly what
        // the reverse P/Invoke prologue looks for on every later hook fire.
        Patch(alreadyAttached, code.Count);
        MovEax(1);
        code.Add(0x5F);
        code.Add(0x5E);
        code.Add(0x5B);
        code.Add(0xC3);

        var fail = code.Count;
        Patch(failAlloc, fail);
        Patch(failTlsArrayAlloc, fail);
        code.Add(0x33); code.Add(0xC0);
        code.Add(0x5F);
        code.Add(0x5E);
        code.Add(0x5B);
        code.Add(0xC3);

        return code.ToArray();
    }
}
