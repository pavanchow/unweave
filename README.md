<img src="docs/logo.svg" alt="Unweave logo" width="96">

# Unweave: an EVM bytecode disassembler in Rust

Unweave is an EVM bytecode disassembler written in Rust that reconstructs intent and flags
dangerous opcodes inline: delegatecall, callcode, selfdestruct, external call, create2, and
tx.origin auth, each with a severity and a one-line explanation. Most disassemblers list
mnemonics and leave you to supply the EVM security knowledge; Unweave names the security
meaning, so a smart-contract auditor or agent gets correct disassembly with the risky
opcodes, basic blocks, and recovered function selectors marked out.

**[Live demo](https://pavanchow.github.io/unweave/)** · MIT licensed · written in Rust

## Try it

```
cargo run -- disasm 0x600160005560016000f4          # disassemble hex
cargo run -- disasm ./contract.hex --flags-only     # only the dangerous opcodes
cargo run -- disasm 0x...f4 --json                  # structured output
```

```
0009: DELEGATECALL
        ! [critical] delegatecall: runs external code in THIS contract's context and storage. The classic proxy/upgrade takeover and storage-collision vector.
```

## How it differs

evmdis and ethersplay give you a correct opcode listing, and you supply the EVM security
knowledge. Panoramix and heimdall decompile to pseudo-Solidity, powerful but heavy.
Unweave is the fast middle: correct disassembly with the security-relevant opcodes
(delegatecall, callcode, selfdestruct, external call, create2, tx.origin auth) flagged
inline with severity and a one-line explanation.

## HTTP API and console

```
cargo run -- serve --port 8080
```

Open the URL, paste bytecode, and see the disassembly with dangerous opcodes flagged. Or
POST directly: `curl -s localhost:8080/disasm -H 'content-type: application/json' -d '{"hex":"0x...f4"}'`.

## MCP server (agent-native)

```
cargo run -- mcp
claude mcp add unweave -- /path/to/unweave mcp
```

Tool `unweave_disasm` takes `{hex}` and returns instructions, basic blocks, recovered
function selectors, and flagged opcodes, so an agent auditing a contract can ask "does
this bytecode delegatecall".

## Stack

Rust. A full EVM opcode table, PUSH-immediate decoding, and a danger table that maps
security-relevant opcodes to a severity and explanation. See [DESIGN.md](DESIGN.md).

## Status

v0.2: disassembler, full opcode table, danger flags, basic-block splitting, function-
selector recovery, CLI (text/JSON/flags-only), HTTP API, paste-bytecode console, and MCP
server. Next: light stack tracking to resolve delegatecall/call targets.

## License

MIT licensed. By Pavan Nallamothu.
