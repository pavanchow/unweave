//! Unweave: an EVM bytecode disassembler that reconstructs intent and flags
//! dangerous opcodes. Most tools list mnemonics. This one names the security
//! meaning: delegatecall, selfdestruct, unchecked external calls, tx.origin auth.

use serde::Serialize;

pub mod mcp;
pub mod server;

/// One decoded instruction.
#[derive(Debug, Clone, Serialize)]
pub struct Ins {
    pub pc: usize,
    pub op: u8,
    pub name: String,
    /// PUSH immediate bytes, hex-encoded, if any.
    pub operand: Option<String>,
    /// A security note if this opcode is worth flagging.
    pub flag: Option<Flag>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Flag {
    pub severity: String,
    pub note: String,
}

/// Opcode mnemonic and the number of immediate bytes it consumes (PUSH1..32).
fn opcode(op: u8) -> (String, usize) {
    // PUSH1..PUSH32
    if (0x60..=0x7f).contains(&op) {
        return (format!("PUSH{}", op - 0x5f), (op - 0x5f) as usize);
    }
    if (0x80..=0x8f).contains(&op) {
        return (format!("DUP{}", op - 0x7f), 0);
    }
    if (0x90..=0x9f).contains(&op) {
        return (format!("SWAP{}", op - 0x8f), 0);
    }
    if (0xa0..=0xa4).contains(&op) {
        return (format!("LOG{}", op - 0xa0), 0);
    }
    let name = match op {
        0x00 => "STOP", 0x01 => "ADD", 0x02 => "MUL", 0x03 => "SUB", 0x04 => "DIV",
        0x05 => "SDIV", 0x06 => "MOD", 0x07 => "SMOD", 0x08 => "ADDMOD", 0x09 => "MULMOD",
        0x0a => "EXP", 0x0b => "SIGNEXTEND",
        0x10 => "LT", 0x11 => "GT", 0x12 => "SLT", 0x13 => "SGT", 0x14 => "EQ",
        0x15 => "ISZERO", 0x16 => "AND", 0x17 => "OR", 0x18 => "XOR", 0x19 => "NOT",
        0x1a => "BYTE", 0x1b => "SHL", 0x1c => "SHR", 0x1d => "SAR",
        0x20 => "KECCAK256",
        0x30 => "ADDRESS", 0x31 => "BALANCE", 0x32 => "ORIGIN", 0x33 => "CALLER",
        0x34 => "CALLVALUE", 0x35 => "CALLDATALOAD", 0x36 => "CALLDATASIZE",
        0x37 => "CALLDATACOPY", 0x38 => "CODESIZE", 0x39 => "CODECOPY", 0x3a => "GASPRICE",
        0x3b => "EXTCODESIZE", 0x3c => "EXTCODECOPY", 0x3d => "RETURNDATASIZE",
        0x3e => "RETURNDATACOPY", 0x3f => "EXTCODEHASH",
        0x40 => "BLOCKHASH", 0x41 => "COINBASE", 0x42 => "TIMESTAMP", 0x43 => "NUMBER",
        0x44 => "PREVRANDAO", 0x45 => "GASLIMIT", 0x46 => "CHAINID", 0x47 => "SELFBALANCE",
        0x48 => "BASEFEE",
        0x50 => "POP", 0x51 => "MLOAD", 0x52 => "MSTORE", 0x53 => "MSTORE8", 0x54 => "SLOAD",
        0x55 => "SSTORE", 0x56 => "JUMP", 0x57 => "JUMPI", 0x58 => "PC", 0x59 => "MSIZE",
        0x5a => "GAS", 0x5b => "JUMPDEST", 0x5f => "PUSH0",
        0xf0 => "CREATE", 0xf1 => "CALL", 0xf2 => "CALLCODE", 0xf3 => "RETURN",
        0xf4 => "DELEGATECALL", 0xf5 => "CREATE2", 0xfa => "STATICCALL", 0xfd => "REVERT",
        0xfe => "INVALID", 0xff => "SELFDESTRUCT",
        _ => "UNKNOWN",
    };
    if name == "UNKNOWN" {
        (format!("UNKNOWN_0x{op:02x}"), 0)
    } else {
        (name.to_string(), 0)
    }
}

/// The security meaning of an opcode, if it is worth flagging.
fn danger(op: u8) -> Option<Flag> {
    let (sev, note): (&str, &str) = match op {
        0xf4 => ("critical", "delegatecall: runs external code in THIS contract's context and storage. The classic proxy/upgrade takeover and storage-collision vector."),
        0xf2 => ("critical", "callcode: legacy delegatecall variant, runs external code with this contract's storage."),
        0xff => ("high", "selfdestruct: destroys the contract and force-sends its balance. Bricks proxies and breaks invariants."),
        0xf1 => ("medium", "call: external call with value/gas to an arbitrary address. Check reentrancy and the return value."),
        0xf5 => ("low", "create2: deploys to a deterministic, precomputable address. Watch for address-reuse tricks."),
        0x32 => ("medium", "tx.origin: using ORIGIN for authorization is a known phishing/bypass vector; prefer CALLER."),
        _ => return None,
    };
    Some(Flag { severity: sev.into(), note: note.into() })
}

/// Disassemble EVM bytecode into instructions, handling PUSH immediates.
pub fn disasm(code: &[u8]) -> Vec<Ins> {
    let mut out = Vec::new();
    let mut pc = 0;
    while pc < code.len() {
        let op = code[pc];
        let (name, plen) = opcode(op);
        let operand = if plen > 0 {
            let end = (pc + 1 + plen).min(code.len());
            Some(hex(&code[pc + 1..end]))
        } else {
            None
        };
        out.push(Ins { pc, op, name, operand, flag: danger(op) });
        pc += 1 + plen;
    }
    out
}

/// Parse a hex string (optional `0x`, whitespace ignored) into bytes.
pub fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if cleaned.len() % 2 != 0 {
        return Err("hex has an odd number of digits".into());
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).map_err(|_| format!("bad hex at byte {}", i / 2)))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Render the disassembly as readable text, marking flagged opcodes.
pub fn render(ins: &[Ins]) -> String {
    let mut out = String::new();
    for i in ins {
        let operand = i.operand.as_deref().map(|o| format!(" 0x{o}")).unwrap_or_default();
        out.push_str(&format!("{:04x}: {}{}\n", i.pc, i.name, operand));
        if let Some(f) = &i.flag {
            out.push_str(&format!("        ! [{}] {}\n", f.severity, f.note));
        }
    }
    out
}

fn is_terminator(name: &str) -> bool {
    matches!(
        name,
        "JUMP" | "JUMPI" | "STOP" | "RETURN" | "REVERT" | "SELFDESTRUCT" | "INVALID"
    )
}

/// Split the instruction stream into basic blocks. Leaders are pc 0, every
/// JUMPDEST, and the instruction after any terminator. Returns (start_pc, end_pc).
pub fn basic_blocks(ins: &[Ins]) -> Vec<(usize, usize)> {
    use std::collections::BTreeSet;
    let mut leaders: BTreeSet<usize> = BTreeSet::new();
    leaders.insert(0);
    for (i, w) in ins.iter().enumerate() {
        if w.name == "JUMPDEST" {
            leaders.insert(i);
        }
        if is_terminator(&w.name) && i + 1 < ins.len() {
            leaders.insert(i + 1);
        }
    }
    let ls: Vec<usize> = leaders.into_iter().collect();
    let mut blocks = Vec::new();
    for (idx, &l) in ls.iter().enumerate() {
        let end_idx = if idx + 1 < ls.len() { ls[idx + 1] } else { ins.len() };
        let start_pc = ins[l].pc;
        let end_pc = ins.get(end_idx).map(|i| i.pc).unwrap_or_else(|| {
            ins.last().map(|i| i.pc + 1 + i.operand.as_ref().map_or(0, |o| o.len() / 2)).unwrap_or(0)
        });
        blocks.push((start_pc, end_pc));
    }
    blocks
}

/// Recover function selectors from the standard solc dispatcher pattern
/// (`PUSH4 <selector> ... EQ ... PUSH<dest> JUMPI`). Heuristic, so it can miss
/// non-standard dispatchers; it reports (selector hex, jump destination pc).
pub fn selectors(ins: &[Ins]) -> Vec<(String, Option<u64>)> {
    let mut out: Vec<(String, Option<u64>)> = Vec::new();
    for (i, w) in ins.iter().enumerate() {
        if w.name != "PUSH4" {
            continue;
        }
        let sel = match &w.operand {
            Some(s) if s.len() == 8 => s.clone(),
            _ => continue,
        };
        let mut has_eq = false;
        let mut dest: Option<u64> = None;
        for k in (i + 1)..(i + 8).min(ins.len()) {
            let nk = &ins[k];
            if nk.name == "EQ" {
                has_eq = true;
            }
            if nk.name.starts_with("PUSH") && nk.name != "PUSH4" {
                if let Some(o) = &nk.operand {
                    dest = u64::from_str_radix(o, 16).ok();
                }
            }
            if nk.name == "JUMPI" && has_eq {
                if !out.iter().any(|(s, _)| *s == sel) {
                    out.push((sel.clone(), dest));
                }
                break;
            }
        }
    }
    out
}

/// Full analysis as JSON: instructions, basic blocks, recovered selectors, flags.
pub fn disasm_json(code: &[u8]) -> serde_json::Value {
    let ins = disasm(code);
    let flagged: Vec<&Ins> = ins.iter().filter(|i| i.flag.is_some()).collect();
    let blocks = basic_blocks(&ins);
    let sels = selectors(&ins);
    serde_json::json!({
        "byte_len": code.len(),
        "instruction_count": ins.len(),
        "block_count": blocks.len(),
        "blocks": blocks.iter().map(|(s, e)| serde_json::json!({ "start_pc": s, "end_pc": e })).collect::<Vec<_>>(),
        "selectors": sels.iter().map(|(s, d)| serde_json::json!({ "selector": format!("0x{s}"), "dest_pc": d })).collect::<Vec<_>>(),
        "instructions": ins,
        "flagged_count": flagged.len(),
        "flags": flagged.iter().map(|i| serde_json::json!({
            "pc": i.pc, "op": i.name,
            "severity": i.flag.as_ref().unwrap().severity,
            "note": i.flag.as_ref().unwrap().note,
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_push_and_immediate() {
        // 0x6002600101 = PUSH1 0x02, PUSH1 0x01, ADD
        let code = parse_hex("6002600101").unwrap();
        let ins = disasm(&code);
        assert_eq!(ins.len(), 3);
        assert_eq!(ins[0].name, "PUSH1");
        assert_eq!(ins[0].operand.as_deref(), Some("02"));
        assert_eq!(ins[1].name, "PUSH1");
        assert_eq!(ins[2].name, "ADD");
    }

    #[test]
    fn flags_delegatecall() {
        let code = parse_hex("f4").unwrap();
        let ins = disasm(&code);
        assert_eq!(ins[0].name, "DELEGATECALL");
        assert_eq!(ins[0].flag.as_ref().unwrap().severity, "critical");
    }

    #[test]
    fn flags_selfdestruct_and_origin() {
        let ins = disasm(&parse_hex("ff32").unwrap());
        assert_eq!(ins[0].name, "SELFDESTRUCT");
        assert_eq!(ins[1].name, "ORIGIN");
        assert!(ins[1].flag.is_some());
    }

    #[test]
    fn push_at_end_is_truncated_not_panicking() {
        // PUSH32 with no following bytes.
        let ins = disasm(&parse_hex("7f").unwrap());
        assert_eq!(ins[0].name, "PUSH32");
        assert_eq!(ins[0].operand.as_deref(), Some(""));
    }

    #[test]
    fn unknown_opcode_is_labeled() {
        let ins = disasm(&[0x0c]);
        assert!(ins[0].name.starts_with("UNKNOWN_0x0c"));
    }

    #[test]
    fn parse_hex_handles_prefix_and_odd() {
        assert!(parse_hex("0x6001").is_ok());
        assert!(parse_hex("601").is_err());
    }

    #[test]
    fn recovers_function_selector() {
        // DUP1 PUSH4 12345678 EQ PUSH2 0010 JUMPI
        let ins = disasm(&parse_hex("8063123456781461001057").unwrap());
        let sels = selectors(&ins);
        assert_eq!(sels.len(), 1);
        assert_eq!(sels[0].0, "12345678");
        assert_eq!(sels[0].1, Some(0x10));
    }

    #[test]
    fn splits_basic_blocks_at_jumpdest() {
        // PUSH1 00 JUMP JUMPDEST STOP  => leaders at 0, after JUMP, and JUMPDEST
        let ins = disasm(&parse_hex("6000565b00").unwrap());
        let blocks = basic_blocks(&ins);
        assert!(blocks.len() >= 2);
    }
}
