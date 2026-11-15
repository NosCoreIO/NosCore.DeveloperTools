<p align="center">
  <img width="200" alt="NosCore" src="icon.png"/>
</p>

<h1 align="center">NosCore.DeveloperTools</h1>

<p align="center">
  <a href="https://github.com/NosCoreIO/NosCore.DeveloperTools/actions/workflows/dotnet.yml"><img alt="Build" src="https://github.com/NosCoreIO/NosCore.DeveloperTools/actions/workflows/dotnet.yml/badge.svg?branch=master"/></a>
  <a href="https://discord.gg/Eu3ETSw"><img alt="Discord" src="https://img.shields.io/badge/Discord-join-5865F2?style=flat-square&logo=discord&logoColor=white"/></a>
  <a href="LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/license-MIT-blue?style=flat-square"/></a>
</p>

Developer tools for NosTale and NosCore: a packet logger that hooks a running client, and a client creator that
points a copy of the client at your own server. WinForms on .NET 11, 32-bit to match the client, packets parsed with
[NosCore.Packets](https://github.com/NosCoreIO/NosCore.Packets). Ships as a single self-contained `.exe`; still at
`0.0.1`.

## Tools

### Packet Logger
- `File → Select process` (Ctrl+P): UAC-elevated launch, process selector with substring filter, remembers the last-used name, hides same-name child processes.
- Attach opens a `PROCESS_ALL_ACCESS`-equivalent handle on the target and injects a NativeAOT-compiled hook DLL via `CreateRemoteThread + LoadLibraryW`.
- Hook DLL scans the target's main module for NosTale send/recv byte-pattern signatures, installs 6-byte inline detours (entry-point for world, mid-function for login), and forwards captured packets over a named pipe to the UI.
- Per-direction capture toggles, blacklist/whitelist filters (filtered packets are dropped at intake), Ctrl+A / Ctrl+C / right-click copy with and without tags, Clear button.
- Custom packet inject — send / receive synthetic packets through the client's own send/recv functions using a Delphi register-convention invoker thunk + a hand-rolled Delphi AnsiString.

### Client Creator
Point it at a copy of `NostaleClientX.exe`, pick a new server address and output filename, hit **Patch**. The output binary gets three edits:

1. **Server address** — the client stores the login server as a Delphi constant AnsiString in its `.rdata`. We auto-detect the slot by shape (refcount-`-1` header + IP-looking payload, no text search), overwrite the payload, and rewrite the length prefix at offset `-4`.
2. **Double-click opens the password login** — the entry point calls `ParamCount`, decrements, and `JL`s to the exit path on a negative result. We retarget that `JL` to the body every login mode shares, so a launch without arguments reaches it with the Steam and GF flags still zero, which is the `EntwellNostaleClient` password login. Launches with an argument never take the jump, so `gf <N>` (what the Auth tab's **Sign in & launch** passes) still goes through the auth-code login.
3. **Gameforge wrapper stub** — the `gf_wrapper.dll` import is renamed to `noscore_gf.dll`, which is written next to the patched exe and hands the client the `_NC_AUTH_CODE` from the Auth tab.

## Windows Defender

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

## Building

Requires .NET 11 SDK.

```
dotnet build
```

Produce a self-contained single `.exe`:

```
dotnet publish src/NosCore.DeveloperTools -c Release -r win-x86 --self-contained -p:PublishSingleFile=true -o ./publish
```

Output: `./publish/NosCore.DeveloperTools.exe`.

## Contributing

Questions, ideas and pull requests are welcome; most of the discussion happens on [Discord](https://discord.gg/Eu3ETSw).
It targets Windows only, since it works on the NosTale client's process. Any editor that handles .NET 11 works.
In Visual Studio, [Roslynator](https://github.com/dotnet/roslynator) and
[ReSharper](https://www.jetbrains.com/resharper/) help keep to the code style.

## Supporting NosCore

NosCore is a spare-time open source project. Sponsoring buys time spent on the emulator and the packages around it,
and gives the **Supporter** role on Discord.

<p>
  <a href="https://github.com/sponsors/0Lucifer0"><img alt="Sponsor on GitHub" src="https://img.shields.io/badge/GitHub-sponsor-EA4AAA?style=for-the-badge&logo=githubsponsors&logoColor=white"/></a>
  <a href="https://ko-fi.com/A3562BQV"><img alt="Support on Ko-fi" src="https://img.shields.io/badge/Ko--fi-support-FF5E5B?style=for-the-badge&logo=kofi&logoColor=white"/></a>
  <a href="https://www.patreon.com/bePatron?u=6503887"><img alt="Become a patron" src="https://img.shields.io/badge/Patreon-become_a_patron-F96854?style=for-the-badge&logo=patreon&logoColor=white"/></a>
</p>

Thanks to [Navicat](https://www.navicat.com) for supporting the project.

<a href="https://www.navicat.com"><img height="60" alt="Navicat" src="https://user-images.githubusercontent.com/35202750/207230064-dcf23adc-9e96-4481-9a53-cd212f5bd60e.png"/></a>

## Legal

NosCore is an independent, unofficial project for educational use. It is not affiliated with, authorized, maintained,
sponsored or endorsed by Gameforge or any of its affiliates; NosTale is a trademark of Gameforge. Using it may be
against the terms of service of NosTale servers.

Released under the [MIT License](LICENSE).
