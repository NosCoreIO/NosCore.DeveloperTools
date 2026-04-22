# Finding hook points in the NosTale client

This doc explains how we find the spots in `NosCore.exe` where we intercept cleartext packets. We currently hook three of them — world send, world recv, login recv — and they all go through the same trampoline machinery. What differs is *where* the trampoline reads the packet pointer from (a register for world, a stack local for login).

We use **x32dbg** with the [Wasdubya x64dbg MCP](https://github.com/Wasdubya/x64dbgMCP) plugin so an LLM session can read registers, set breakpoints, and disassemble on command. You can follow the same steps by hand in x32dbg's UI — the MCP is just faster.

---

## Quick primer

A few concepts that come up repeatedly:

- **NosTale is 32-bit (x86), written in Delphi.** ImageBase is `0x400000`, no ASLR, so every address in this doc is stable across launches of the same client build.
- **Packet strings are Delphi `AnsiString`.** When the game code holds one it holds a pointer `P` to the payload bytes; the length lives 4 bytes *before* the payload (`*(int*)(P-4)`). That's all our [`DelphiString.Read`](../src/NosCore.PacketLogger.Hook/DelphiString.cs) needs.
- **Delphi's fastcall convention:** first three arguments go in `ECX`, `EDX`, `EAX` (in that order). Any remaining args are pushed on the stack. When the client has a per-packet cleartext handler, the packet string pointer consistently arrives in `EDX`.
- **An inline detour is a 5-byte `JMP rel32` (opcode `E9 xx xx xx xx`)** we patch into the target. The displaced bytes get copied into a trampoline and re-executed, then the trampoline jumps back into the function past our patch.

---

## Two flavours of cleartext hook point

### Flavour A — per-packet handler (world)

For the world connection, the dispatcher hands each decrypted packet to a dedicated handler function. That handler receives the packet as a Delphi AnsiString in `EDX`. We detour the function's prologue, copy EDX to the managed hook, done. This is the clean case.

Fingerprint: in the first ~20 bytes of the function you'll see `mov [ebp-x], edx`. That's the handler saving the packet pointer. Hook candidate confirmed.

### Flavour B — no handler, inline parse (login)

For the login connection, the dispatcher decrypts the packet and then *parses it inline* — there's no single function that gets called with the whole cleartext packet. The cleartext exists only for a few instructions in the dispatcher's own stack frame, at `[ebp-0x08]`, before the inline tokenizer starts consuming it token-by-token.

So we can't use Flavour A for login. Instead we place a detour at a mid-function address where:
1. `EBP` still belongs to the dispatcher
2. `[ebp-0x08]` still points to the full cleartext
3. The bytes we displace are straight-line instructions we can copy to the trampoline

Fingerprint: look for the instruction just after `cmp [ebp-0x08], 0 / jz exit` (the dispatcher's null-check on the decrypted string). The next `lea eax, [ebp-x] / push eax / …` sequence is where we land.

---

## Current addresses in `NosCore.exe` (Entwell build)

| Hook | Address | Flavour | Source of packet pointer |
|---|---|---|---|
| World send | `0x4EB00C` | A | EDX on entry |
| World recv | `0x4DB5C0` | A | EDX on entry |
| Login recv | `0x4EB5CC` | B | `*(IntPtr*)(EBP-0x08)` |

World send/recv were derived the same way as login recv — see the recipe below. The "dead ends" section at the bottom lists the approaches we walked through before landing on the current mid-function hook.

The single [`Detour.Install`](../src/NosCore.PacketLogger.Hook/Detour.cs) entry point handles both flavours via the `HookArg` enum: `HookArg.Edx` for flavour A, `HookArg.Ebp` for flavour B (in which case the managed hook dereferences the local itself).

---

## Instruction-boundary caveat

The trampoline re-executes whatever bytes it displaced. If you cut through the middle of a multi-byte instruction, the CPU decodes garbage when the trampoline runs those bytes. **Pick a prologue size that lands on an instruction boundary**, and avoid displacing any relative branch (rel32 would misaim after being moved).

- World send/recv: 6 bytes (default).
- Login recv: 9 bytes (covers `lea/push/lea/mov cl,0x20` — no relative branches, clean boundary).

If a future target doesn't cut clean at 6, pass `prologueSize` to `Detour.Install` with the smallest value ≥5 that lands on a boundary.

---

## Recipe: finding the cleartext hook for a new phase

For a new client phase (lobby, character select, in-game subsystem) that uses its own send/recv.

### 1. Launch under the debugger

```
# from the MCP:
init "C:\Program Files (x86)\Nostale\NosCore.exe", EntwellNostaleClient
```

Then `erun` until the target screen is visible.

### 2. Break on every winsock entry point

```
bp ws2_32.recv
bp ws2_32.WSARecv
bp ws2_32.recvfrom
bp ws2_32.WSARecvFrom
bp ws2_32.send
bp ws2_32.WSASend
```

Delphi's Indy layer may land on any of these. Covering all six avoids one missed bp derailing the session.

### 3. Find the connection object

Trigger the action. When a winsock breakpoint fires, pull the call stack. The first `NosCore.exe` return address walking up from `ws2_32.*` is the client's socket pump. Read its `EBX` — that's the connection's `this` pointer.

Every Delphi `TClientCore` instance in NosTale has the same layout:

```
+0x0000  VMT pointer           // class identity (TClientCore)
+0x011C  recv buffer (8 KB raw — still encrypted)
+0x4320  recv buffer length
+0x4338  send "drain" tick — virtual function pointer
+0x4340  recv dispatcher — virtual function pointer
```

### 4. Locate the recv dispatcher

```
MemoryRead(ebx + 0x4340, 4)    →  e.g. 0x004EB540 for login
```

### 5. Figure out which flavour you're in

Disassemble the dispatcher. Somewhere after a `call <decrypt>` you'll see either:

- **Flavour A:** a tight loop calling a single function with `EDX = [ebp-x]` (the decrypted string). That call target is a per-packet handler — your hook point.
- **Flavour B:** no such single-function dispatch — instead the dispatcher consumes the cleartext inline with string-tokenization calls, string compares against hardcoded constants ("fail", "failc", …), and scattered parsing loops.

If Flavour A: confirm the candidate prologue has `mov [ebp-x], edx` near the top and take a signature.

If Flavour B: find the *first* instruction immediately after `cmp [ebp-0x08], 0 / jz exit`. That's your landing point. The bytes after it need to be straight-line (no relative branches) for at least 5 bytes — in practice the compiler emits a run of `lea/push/mov` here, which is ideal.

### 6. Take a signature and wire it up

Pull enough bytes to be unique (usually 12–25 with no wildcards). Add to [`Signatures.cs`](../src/NosCore.PacketLogger.Hook/Signatures.cs) and install via `Detour.Install(addr, &Hook, prologueSize, arg)`:

- Flavour A: `arg: HookArg.Edx`, managed hook takes `IntPtr packetPtr` and calls `Capture`.
- Flavour B: `arg: HookArg.Ebp`, managed hook takes `IntPtr ebp` and calls `Capture(direction, *(IntPtr*)(ebp - offset))`.

---

## Dead ends (so you don't re-walk them)

If you're iterating on the login hook or a similar phase, these are the mistakes we already made. Each one wasted an hour or so.

**Hooking the dispatcher at `+0x4340` directly.** Gets you encrypted bytes. The dispatcher hasn't decrypted yet at its prologue. Would work if you decrypted in managed code (`cleartext[i] = encrypted[i] - 0x0F`, `0xFF` as end-of-packet marker), but that duplicates the client and the lesson generalises poorly to future phases whose crypto may differ.

**Hooking the dispatcher's prologue with the default 6-byte detour.** Login's dispatcher begins `55 8B EC 51 B9 06 00 00 00` — `mov ecx, 6` spans bytes 4–8. A 6-byte detour splits the immediate. The trampoline re-executes `B9 06 <next 3 bytes of JMP>` as `mov ecx, <garbage>` and the dispatcher runs with a broken loop counter. Symptom: cleartext packets *are* captured, but the client UI renders blank because the dispatcher's own inline parsing breaks. If you land on a prologue whose byte 6 isn't clean, bump `prologueSize` to the next boundary.

**Wrapping the decrypt call at `0x4EB5BD` with a CALL-based trampoline.** The client's decrypt function takes *stack* arguments (two dwords the dispatcher pushes before the call) which it reads via `[ebp+0x08]` / `[ebp+0x0C]`. If your trampoline CALLs decrypt, the extra return address your CALL pushes shifts those offsets by 4. Decrypt reads wrong values, produces an empty cleartext, the dispatcher takes the `jz exit` branch, UI renders blank. Works if you replace `E8` with `E9` (JMP instead of CALL) so no extra frame is pushed, but then the shape of the wrap trampoline is very specific to this one call site and not reusable. We retired this approach in favour of the mid-function hook above.

**Hooking the `call 0x004DBEA0` inside the dispatcher's server-list loop.** That function receives one *token* (space-separated) per call — specifically the server-list entries at the tail of `NsTeST`. You'll see entries like `127.0.0.1:1337:...` and `-1:-1:-1:...` arrive, but never the header (`NsTeST 0 admin 1 4 -99 …`) because the dispatcher parses the header inline before the tokenisation loop starts. There's no "whole cleartext packet" function for login — hence Flavour B.

---

## Generalising

The core lesson is that cleartext lives either (a) in a register at a handler's function entry, or (b) in a local inside the dispatcher's own frame for a few instructions. One of those two will be true for any new phase. Don't reach for `[conn+0x11C]` and a C# decrypt — you missed something one level up.

The VMT pointer at `[conn + 0x0000]` tells you the class owning this connection (we saw `0x4DAA6C` for `TClientCore`). Useful as a sanity check that you're looking at what you think you are.
