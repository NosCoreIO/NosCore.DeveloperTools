namespace NosCore.DeveloperTools.Hook;

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

    // Periodic: a function the client calls every frame from its main
    // thread. We hook it purely as a scheduling tick — the detour body
    // drains work queued by our pipe thread so client functions always
    // execute on the thread that owns the game state.
    //
    //   push ebp               ; 55
    //   mov ebp, esp           ; 8B EC
    //   push ebx               ; 53
    //   push esi               ; 56
    //   add esp, <imm8>        ; 83 C4 ??
    //
    // Only the first 5 bytes are displaced: `add esp, imm8` is 3 bytes,
    // so a 6-byte detour would split it and the trampoline would return
    // into the middle of an instruction.
    public const string Periodic = "55 8B EC 53 56 83 C4";

    public const int PeriodicPrologueSize = 5;

    // PlayerManager: locates a code site that loads the manager's static
    // slot, rather than the slot itself — the slot holds no distinctive
    // bytes to scan for.
    //
    //   xor ecx, ecx           ; 33 C9
    //   mov edx, [ebp-0x04]    ; 8B 55 FC
    //   mov eax, [<static>]    ; A1 ?? ?? ?? ??
    //   call <...>             ; E8 ?? ?? ?? ??
    //
    // The A1 opcode sits at match+5, so its imm32 operand — the static
    // address — is at match+6. That slot in turn holds the live manager
    // pointer, which is null until the character is in-world.
    public const string PlayerManager = "33 C9 8B 55 FC A1 ?? ?? ?? ?? E8 ?? ?? ?? ??";

    public const int PlayerManagerStaticOperandOffset = 6;

    // Walk: the client's own movement routine. Calling it (rather than
    // emitting a `walk` packet ourselves) makes the client update its
    // local position, run its animation, and compute the packet's
    // checksum itself — so what reaches the server is byte-identical to
    // a real player's movement.
    //
    //   push ebp               ; 55
    //   mov ebp, esp           ; 8B EC
    //   add esp, -0x14         ; 83 C4 EC
    //   push ebx               ; 53
    //   push esi               ; 56
    //   push edi               ; 57
    //   mov [ebp-0x06], cx     ; 66 89 4D FA
    //
    // Delphi register convention: EAX = manager, EDX = packed position
    // ((y << 16) | x). Never detoured, only called.
    public const string PlayerWalk = "55 8B EC 83 C4 EC 53 56 57 66 89 4D FA";

    // WorldConnect: opens the connection to a world server. This is the
    // step behind the channel button on the selection screen — the client
    // does not open its world socket until then, which is why nothing can
    // be driven in-game before someone clicks.
    //
    //   push ebx / esi / edi        ; 53 56 57
    //   mov  edi, ecx               ; 8B F9   port
    //   mov  esi, edx               ; 8B F2   host string
    //   mov  ebx, eax               ; 8B D8   connection object
    //   mov  eax, esi               ; 8B C6
    //   call <string helper>        ; E8 ?? ?? ?? ??
    //   push eax                    ; 50
    //   call <resolve host>         ; E8 ?? ?? ?? ??
    //
    // Delphi register convention: EAX = connection object, EDX = host as
    // a Delphi AnsiString, ECX = port. Found by breaking on ws2_32
    // connect and walking the call stack back into the client; the worker
    // it tail-calls writes CX straight into the sockaddr as the port,
    // which is what pins the argument order down.
    public const string WorldConnect =
        "53 56 57 8B F9 8B F2 8B D8 8B C6 E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ??";
}
