# NosCore.DeveloperTools #

<p align="center">
  <img width="250px" src="https://github.com/NosCoreIO/NosCore.Packets/blob/15.0.1/icon.png?raw=true"/>
</p>

[![.NET](https://github.com/NosCoreIO/NosCore.DeveloperTools/actions/workflows/dotnet.yml/badge.svg?branch=master)](https://github.com/NosCoreIO/NosCore.DeveloperTools/actions/workflows/dotnet.yml)

Early-stage (`0.0.1`) developer tools for NosTale / NosCore. WinForms on .NET 10, runs as 32-bit to match the NosTale client, parses packets with [NosCore.Packets](https://github.com/NosCoreIO/NosCore.Packets). Ships as a single self-contained `.exe`.

## Warning! ##
We are not responsible of any damages caused by bad usage of our source. Please before asking questions or installing this source read this readme and also do a research, google is your friend. If you mess up when installing our source because you didnt follow it, we will laugh at you. A lot.

## Legal ##
This is an independent and unofficial tool for educational use ONLY. Using the Project might be against the TOS of any NosTale server you connect to. Use at your own risk.

## Tools ##

### Packet Logger
- `File → Select process` (Ctrl+P): UAC-elevated launch, process selector with substring filter, remembers the last-used name, hides same-name child processes.
- Attach opens a `PROCESS_ALL_ACCESS`-equivalent handle on the target and injects a NativeAOT-compiled hook DLL via `CreateRemoteThread + LoadLibraryW`.
- Hook DLL scans the target's main module for NosTale send/recv byte-pattern signatures, installs 6-byte inline detours (entry-point for world, mid-function for login), and forwards captured packets over a named pipe to the UI.
- Per-direction capture toggles, blacklist/whitelist filters (filtered packets are dropped at intake), Ctrl+A / Ctrl+C / right-click copy with and without tags, Clear button.
- Custom packet inject — send / receive synthetic packets through the client's own send/recv functions using a Delphi register-convention invoker thunk + a hand-rolled Delphi AnsiString.

### Client Creator
Point it at a copy of `NostaleClientX.exe`, pick a new server address and output filename, hit **Patch**. The output binary gets three edits:

1. **Server address** — the client stores the login server as a Delphi constant AnsiString in its `.rdata`. We auto-detect the slot by shape (refcount-`-1` header + IP-looking payload, no text search), overwrite the payload, and rewrite the length prefix at offset `-4`.
2. **Allow no-arg launches** — the entry point calls `ParamCount`, decrements, and `JL`s to the exit path on a negative result. That gate aborts double-click launches. We NOP the 6-byte `JL rel32` so execution flows into the arg dispatcher regardless of argc.
3. **Default to Entwell mode** — the arg dispatcher compares `argv[1]` against `"gf"` / `"gftest"` / `"EntwellNostaleClient"` (in that order) and `JNZ`s to exit when none match. We NOP that last `JNZ`, so any non-`gf` / non-`gftest` launch (including empty) falls into the Entwell standalone body. The `gf` / `gftest` branches are untouched — passing `gf <N>` still routes through GF mode as the real Gameforge launcher would trigger.

## ⚠️ Windows Defender

The remote-thread injection path triggers Defender's generic MSIL heuristic
`Trojan:MSIL/TurtleLoader` — false positive matching any .NET assembly that
P/Invokes `CreateRemoteThread + VirtualAllocEx + WriteProcessMemory + LoadLibraryW`
(i.e. the exact shape of a legitimate injector). Until the binary is EV-signed,
you need to exclude the install folder:

```powershell
# Run once as admin
Add-MpPreference -ExclusionPath 'C:\path\to\where\you\put\NosCore.DeveloperTools.exe'
```

Same story for the project directory if you're building from source:
`Add-MpPreference -ExclusionPath 'C:\dev\NosCore.DeveloperTools'`.

## How the hook side differs from other NosTale packet loggers

The usual pattern is to inject a managed .NET DLL into the client and — because NosTale is Delphi (no CLR in-process) — ship a native shim (typically `nethost.dll` + CoreCLR hosting code, sometimes C++/CLI) to start the runtime before the managed code can run. That brings a native dependency and a framework-runtime requirement on the target machine.

We publish the hook DLL with [`PublishAot`](src/NosCore.DeveloperTools.Hook/NosCore.DeveloperTools.Hook.csproj) instead. The C# code compiles straight to native x86 machine code — no CLR, no JIT, no runtime install — and drops to ~620 KB. The bootstrap is just `CreateRemoteThread(target, LoadLibraryW, hookDllPath)`; `DllMain` runs native code immediately, an exported init function is called right after to spawn the worker thread, and we're live. Zero lines of C++ in the repo.

## Signatures

Byte-pattern signatures for the send/recv entry points live in [src/NosCore.DeveloperTools.Hook/Signatures.cs](src/NosCore.DeveloperTools.Hook/Signatures.cs). Client patches drift prologue bytes over time; when a signature stops matching, re-reverse the prologue (x32dbg → hardware breakpoint on a known packet string → step back to the caller's prologue) and bump the constants.

For a walkthrough of the exact recipe we used (via x32dbg + the x64dbg MCP, tracing from `ws2_32.*` into the connection object's virtual handler slots), see [docs/finding-hooks.md](docs/finding-hooks.md). Re-run that process any time a client patch invalidates an existing signature or you need to instrument a new phase of the client (character select, a subsystem, etc.).

## Build ##

Requires .NET 10 SDK.

```
dotnet build
```

Produce a self-contained single `.exe`:

```
dotnet publish src/NosCore.DeveloperTools -c Release -r win-x86 --self-contained -p:PublishSingleFile=true -o ./publish
```

Output: `./publish/NosCore.DeveloperTools.exe`.

## Contributing ##

Discord: [NosCore community](https://discord.gg/Eu3ETSw).

Disclaimer: this is a community project not for commercial use. The result is to learn and program together for prove the study.

Contribution is only possible with Visual Studio 2026 or an equivalent IDE.

## You like our work? ##
<a href='https://github.com/sponsors/0Lucifer0' target='_blank'><img height='46' src='https://i.gyazo.com/47b2ca2eb6e1ce38d02b04c410e1c82a.png' alt='Sponsor me!'/></a>
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/A3562BQV)
<a href='https://www.patreon.com/bePatron?u=6503887' target='_blank'><img height='46' src='https://c5.patreon.com/external/logo/become_a_patron_button@2x.png' alt='Become a Patron!'/></a>
