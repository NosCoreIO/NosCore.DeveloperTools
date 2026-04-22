namespace NosCore.PacketLogger.Hook;

/// <summary>
/// NosTale client byte-pattern signatures. '?' = wildcard byte.
/// See <c>docs/finding-hooks.md</c> for the recipe used to derive them.
/// </summary>
internal static class Signatures
{
    // Send: world cleartext SendPacket.
    //   push ebx; push esi; mov esi, edx; mov ebx, eax; jmp short +4
    // EDX on entry holds a pointer to the packet string (NostaleStringA
    // buffer at offset 0x08, i.e. past the refcount + length header).
    public const string Send = "53 56 8B F2 8B D8 EB 04";

    // Recv: world cleartext RecvPacket handler.
    //   push ebp; mov ebp,esp; add esp,-10; push ebx; push esi; push edi;
    //   xor ecx,ecx; mov [ebp-0C],ecx; mov [ebp-10],ecx; mov [ebp-04],edx;
    //   mov ebx,eax; mov eax,[ebp-04]
    // EDX points to the NostaleStringA packet buffer.
    public const string Recv = "55 8B EC 83 C4 F0 53 56 57 33 C9 89 4D F4 89 4D F0 89 55 FC 8B D8 8B 45 FC";

    // Login cleartext: mid-function hook inside the login recv dispatcher,
    // positioned right after the `cmp [ebp-8], 0 / jz exit` that follows
    // the decrypt call. At this point the dispatcher's EBP is intact and
    // [EBP-0x08] points to the full cleartext NsTeST packet — before the
    // dispatcher's inline tokenizer starts consuming it one token at a
    // time. Unlike the world recv, there's no single function that takes
    // the whole cleartext packet in EDX; the dispatcher parses it inline,
    // so we reach in via the dispatcher's own local.
    //
    //   lea eax, [ebp-0x0C]    ; 8D 45 F4
    //   push eax               ; 50
    //   lea edx, [ebp-0x08]    ; 8D 55 F8
    //   mov cl, 0x20           ; B1 20
    //   mov eax, [ebp-0x08]    ; 8B 45 F8
    //
    // We displace 9 bytes (through `mov cl, 0x20`) — clean instruction
    // boundary, no relative branches to relocate. Hook pushes EBP so the
    // managed side can dereference [EBP-0x08] itself.
    public const string LoginRecv =
        "8D 45 F4 50 8D 55 F8 B1 20 8B 45 F8";
}
