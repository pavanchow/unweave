# Unweave, design

Unweave is an EVM bytecode disassembler that reconstructs intent and flags dangerous
opcodes. Most disassemblers list mnemonics. Unweave names the security meaning: a
`DELEGATECALL` is not just "0xf4", it is "runs external code in this contract's storage,
the classic proxy takeover vector."

Same idea as Oracle and Lint-Owl: the output explains and flags, it does not just dump.

## Prior art, and where Unweave differs

- **evmdis, ethersplay, evm disasm** produce opcode listings. Correct, but you still
  read every line and know EVM security yourself.
- **Panoramix, heimdall** decompile to pseudo-Solidity. Powerful, heavy, and not always
  right; overkill when you want to spot a dangerous primitive fast.

Unweave sits between: a fast, correct disassembly where the security-relevant opcodes
(delegatecall, callcode, selfdestruct, external call, create2, tx.origin auth) are
flagged inline with a one-line explanation and severity. Built for an auditor scanning
a contract, and for an agent (MCP) asking "does this bytecode delegatecall".

## Model (v0.1)

- Full opcode table, PUSH1..PUSH32 immediates decoded, DUP/SWAP/LOG families, unknown
  bytes labeled rather than dropped, truncated trailing PUSH handled safely.
- A danger table mapping the security-relevant opcodes to (severity, explanation).
- Text, JSON, and flags-only output.

## Roadmap

### v0.1
1. Opcode table, disassembler, danger flags, CLI (this slice).

### Next
2. Basic blocks: split at JUMPDEST/JUMP/JUMPI so control flow is visible.
3. The 4-byte function dispatcher: recover function selectors and route to their code.
4. Light stack tracking to resolve the target of `DELEGATECALL`/`CALL` (which address,
   which selector) instead of just flagging the opcode.
5. HTTP API + a paste-bytecode UI, then an MCP server (`unweave_disasm`), like the others.
