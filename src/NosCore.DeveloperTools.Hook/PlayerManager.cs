namespace NosCore.DeveloperTools.Hook;

internal enum WalkResult
{
    Ok,
    NoWalkFunction,
    NoPlayerManager,
    NotInWorld,
    NoCharacterLoaded,
    NoClientThread,
}

/// <summary>
/// Reads the local character's live state and drives its movement
/// through the client's own walk routine.
///
/// Injecting a <c>walk</c> packet instead would move the character
/// server-side only: the client keeps rendering the old position and
/// every subsequent packet it originates carries stale coordinates.
/// Calling the client's routine updates local state, animates, and lets
/// the client build the outgoing packet itself — including the checksum
/// byte, which we therefore never have to reproduce.
/// </summary>
internal static unsafe class PlayerManager
{
    private const int PlayerObjectOffset = 0x20;
    private const int PlayerIdOffset = 0x24;
    private const int ObjectIdOffset = 0x08;
    private const int ObjectXOffset = 0x0C;
    private const int ObjectYOffset = 0x0E;

    /// <summary>
    /// The manager exists as soon as the client reaches its game scene,
    /// several seconds before a character is loaded into it — at that
    /// point the player slot is null and the id reads -1. Movement
    /// dereferences the player, so a non-null manager is not enough to
    /// make the call safe.
    /// </summary>
    public static bool TryGetPlayer(out IntPtr player, out int playerId)
    {
        player = IntPtr.Zero;
        playerId = -1;

        if (!TryGetManager(out var manager)) return false;
        if (!SafeMemory.TryReadIntPtr(manager + PlayerObjectOffset, out var candidate)) return false;
        if (candidate == IntPtr.Zero) return false;
        if (!SafeMemory.TryReadInt32(manager + PlayerIdOffset, out playerId)) return false;
        if (playerId == -1) return false;

        player = candidate;
        return true;
    }

    public static IntPtr StaticAddress { get; private set; }

    public static IntPtr WalkAddress { get; private set; }

    private static IntPtr _walkInvoker2;
    private static IntPtr _walkInvoker4;

    public static void Resolve()
    {
        var managerSite = PatternScanner.ScanMainModule(Signatures.PlayerManager);
        if (managerSite != IntPtr.Zero &&
            SafeMemory.TryReadIntPtr(managerSite + Signatures.PlayerManagerStaticOperandOffset, out var slot))
        {
            StaticAddress = slot;
        }

        var walk = PatternScanner.ScanMainModule(Signatures.PlayerWalk);
        if (walk == IntPtr.Zero) return;

        WalkAddress = walk;
        _walkInvoker2 = ClientInvoker.BuildRegisterInvoker(walk);
        _walkInvoker4 = ClientInvoker.BuildRegisterInvoker4(walk);
    }

    /// <summary>
    /// The manager slot is populated when the character enters the
    /// world and nulled on the way out, so a null here means "not
    /// in-world yet", not "signature wrong".
    /// </summary>
    public static bool TryGetManager(out IntPtr manager)
    {
        manager = IntPtr.Zero;
        if (StaticAddress == IntPtr.Zero) return false;
        if (!SafeMemory.TryReadIntPtr(StaticAddress, out var resolved)) return false;
        if (resolved == IntPtr.Zero) return false;

        manager = resolved;
        return true;
    }

    public static bool TryGetPosition(out int id, out ushort x, out ushort y)
    {
        id = 0;
        x = 0;
        y = 0;

        if (!TryGetPlayer(out var playerObject, out _)) return false;

        return SafeMemory.TryReadInt32(playerObject + ObjectIdOffset, out id)
            && SafeMemory.TryReadUInt16(playerObject + ObjectXOffset, out x)
            && SafeMemory.TryReadUInt16(playerObject + ObjectYOffset, out y);
    }

    /// <summary>
    /// Hex dump of client memory, for working out a struct layout when a
    /// borrowed offset does not match this build.
    /// </summary>
    public static string Peek(IntPtr address, int length)
    {
        length = Math.Clamp(length, 1, 512);
        if (!SafeMemory.IsReadable(address, length)) return "unreadable";

        var bytes = (byte*)address;
        var text = new System.Text.StringBuilder(length * 2);
        for (var i = 0; i < length; i++)
        {
            text.Append(bytes[i].ToString("X2"));
        }

        return text.ToString();
    }

    /// <summary>
    /// Walks the manager's fields looking for a pointer that leads to
    /// something shaped like a map object — a non-zero id and a
    /// coordinate pair inside map bounds. Reports every candidate rather
    /// than picking one, since several offsets can look plausible and
    /// only a comparison against the server's view settles it.
    /// </summary>
    public static string ScanForPlayerObject()
    {
        if (!TryGetManager(out var manager)) return "not-in-world";

        var found = new List<string>();
        for (var offset = 0; offset <= 0x100; offset += 4)
        {
            if (!SafeMemory.TryReadIntPtr(manager + offset, out var candidate)) continue;
            if (candidate == IntPtr.Zero) continue;
            if (!SafeMemory.TryReadInt32(candidate + ObjectIdOffset, out var id)) continue;
            if (!SafeMemory.TryReadUInt16(candidate + ObjectXOffset, out var x)) continue;
            if (!SafeMemory.TryReadUInt16(candidate + ObjectYOffset, out var y)) continue;
            if (id == 0 || x == 0 || y == 0 || x > 300 || y > 300) continue;

            found.Add($"+0x{offset:X2}=>0x{candidate.ToInt64():X}:id={id},x={x},y={y}");
        }

        return found.Count == 0 ? "no-candidates" : string.Join(" ", found);
    }

    /// <summary>
    /// Walk to a map cell. <paramref name="extraArgs"/> selects the call
    /// shape: null uses the two-register form (manager, position), which
    /// is what the client's own call sites appear to use; supplying a
    /// pair passes them as the third register and one stack argument so
    /// the four-argument form can be tried against a live client without
    /// rebuilding the DLL.
    /// </summary>
    public static WalkResult Walk(ushort x, ushort y, (int Un0, int Un1)? extraArgs)
    {
        if (WalkAddress == IntPtr.Zero || _walkInvoker2 == IntPtr.Zero) return WalkResult.NoWalkFunction;
        if (StaticAddress == IntPtr.Zero) return WalkResult.NoPlayerManager;
        if (!TryGetManager(out var manager)) return WalkResult.NotInWorld;
        if (!TryGetPlayer(out _, out _)) return WalkResult.NoCharacterLoaded;

        var position = (y << 16) | x;

        var invoked = NosThreadSynchronizer.Invoke(() =>
        {
            if (extraArgs is { } extra)
            {
                var walk4 = (delegate* unmanaged[Cdecl]<IntPtr, int, int, int, void>)_walkInvoker4;
                walk4(manager, position, extra.Un0, extra.Un1);
            }
            else
            {
                var walk2 = (delegate* unmanaged[Cdecl]<IntPtr, int, void>)_walkInvoker2;
                walk2(manager, position);
            }
        });

        return invoked ? WalkResult.Ok : WalkResult.NoClientThread;
    }
}
