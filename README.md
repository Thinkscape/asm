# Agents Secrets Manager (asm)

macOS menu-bar manager (Rust core + SwiftUI shell), the `asm` CLI for agent machines, a patched iron-proxy, and an agent skill.

|Path|What|
|---|---|
|`crates/asm-proto`|Wire types and shared rules|
|`crates/asm-core`|Manager core (macOS), UniFFI exports|
|`crates/asm-cli`|`asm` CLI|
|`app/`|SwiftUI app|
|`third_party/iron-proxy`|iron-proxy v0.56.0 subtree + asm patch|
|`skill/asm`|Agent skill|

Build: `just setup` once, then `just dist`. Tests: `just test`.

Install the CLI: `just install-cli` (this Mac, `~/.local/bin/asm`) or
`just install-cli-remote <ssh-host>` (Linux host, `~/.local/bin/asm`, arch picked automatically).
Then `asm pair <manager-host>` on that machine.
