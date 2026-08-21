# Unweave

**An EVM bytecode disassembler that reconstructs intent and flags dangerous opcodes.**
Most disassemblers list mnemonics. Unweave names the security meaning: a `DELEGATECALL`
is flagged as "runs external code in this contract's storage, the classic proxy-takeover
vector." Built for smart-contract auditors and agents. By Pavan Nallamothu.

## Try it

```
cargo run -- disasm 0x600160005560016000f4          # disassemble hex
cargo run -- disasm ./contract.hex --flags-only     # only the dangerous opcodes
cargo run -- disasm 0x...f4 --json                  # structured output
```

```
0006: DELEGATECALL
        ! [critical] delegatecall: runs external code in THIS contract's context and storage.
```

## How it differs

evmdis and ethersplay give you a correct opcode listing, and you supply the EVM security
knowledge. Panoramix and heimdall decompile to pseudo-Solidity, powerful but heavy.
Unweave is the fast middle: correct disassembly with the security-relevant opcodes
(delegatecall, callcode, selfdestruct, external call, create2, tx.origin auth) flagged
inline with severity and a one-line explanation.

## Stack

Rust. A full EVM opcode table, PUSH-immediate decoding, and a danger table that maps
security-relevant opcodes to a severity and explanation. See [DESIGN.md](DESIGN.md).

## Status

v0.1: disassembler, opcode table, danger flags, CLI (text/JSON/flags-only). Next: basic
blocks and the function dispatcher, then an HTTP API, a paste-bytecode console, and an
MCP server.
