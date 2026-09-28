//! Public-API integration tests for unweave, the EVM bytecode disassembler.
//! Drives the crate the way a dependent would, through the crate-root exports:
//! parse_hex -> disasm -> {render, basic_blocks, selectors, disasm_json}.

use unweave::{basic_blocks, disasm, disasm_json, parse_hex, render, selectors};

// ---- full happy-path pipeline ---------------------------------------------

#[test]
fn parse_disasm_render_round_trip() {
    // 0x6002600101 = PUSH1 0x02 ; PUSH1 0x01 ; ADD
    let code = parse_hex("0x60 02 60 01 01").unwrap(); // whitespace tolerated
    let ins = disasm(&code);
    assert_eq!(ins.len(), 3);
    assert_eq!(ins[0].name, "PUSH1");
    assert_eq!(ins[0].operand.as_deref(), Some("02"));
    assert_eq!(ins[1].operand.as_deref(), Some("01"));
    assert_eq!(ins[2].name, "ADD");
    assert!(ins[2].operand.is_none());

    let text = render(&ins);
    assert!(text.contains("0000: PUSH1 0x02"));
    assert!(text.contains("0004: ADD"));
}

#[test]
fn disasm_is_deterministic() {
    let code = parse_hex("6002600101f4").unwrap();
    // Ins has no PartialEq; the rendered form is the stable observable output.
    assert_eq!(render(&disasm(&code)), render(&disasm(&code)));
    assert_eq!(disasm_json(&code), disasm_json(&code));
}

// ---- authoritative selector vectors (real solc dispatcher) ----------------

#[test]
fn recovers_real_erc20_selectors_through_public_api() {
    // A minimal solc-style dispatcher comparing calldata against two real
    // ERC20 selectors: transfer(address,uint256)=0xa9059cbb, then
    // balanceOf(address)=0x70a08231. Shape per selector:
    //   DUP1 PUSH4 <sel> EQ PUSH2 <dest> JUMPI
    // prefixed once by CALLDATALOAD so the heuristic treats it as a dispatcher.
    let bytecode = "35\
        8063a9059cbb1461002a57\
        806370a082311461004057";
    let ins = disasm(&parse_hex(bytecode).unwrap());
    let sels = selectors(&ins);
    assert_eq!(sels.len(), 2);
    assert_eq!(sels[0], ("a9059cbb".to_string(), Some(0x2a)));
    assert_eq!(sels[1], ("70a08231".to_string(), Some(0x40)));

    // The same selectors show up in the JSON view, 0x-prefixed.
    let v = disasm_json(&parse_hex(bytecode).unwrap());
    assert_eq!(v["selectors"][0]["selector"], "0xa9059cbb");
    assert_eq!(v["selectors"][1]["dest_pc"], 0x40);
}

#[test]
fn selector_recovery_requires_calldata_context() {
    // Identical PUSH4..EQ..JUMPI shape but no CALLDATALOAD: an incidental
    // constant compare, not a dispatcher.
    let ins = disasm(&parse_hex("600063a9059cbb14600a57").unwrap());
    assert!(selectors(&ins).is_empty());
}

// ---- danger flags: the crate's whole reason for existing -------------------

#[test]
fn dangerous_opcodes_are_flagged_with_expected_severity() {
    // op byte -> (mnemonic, severity)
    let cases: &[(&str, &str, &str)] = &[
        ("f4", "DELEGATECALL", "critical"),
        ("f2", "CALLCODE", "critical"),
        ("ff", "SELFDESTRUCT", "high"),
        ("f1", "CALL", "medium"),
        ("32", "ORIGIN", "medium"),
        ("f5", "CREATE2", "low"),
        ("5d", "TSTORE", "low"),
    ];
    for (hexop, mnemonic, sev) in cases {
        let ins = disasm(&parse_hex(hexop).unwrap());
        assert_eq!(ins[0].name, *mnemonic);
        let flag = ins[0]
            .flag
            .as_ref()
            .unwrap_or_else(|| panic!("{mnemonic} not flagged"));
        assert_eq!(flag.severity, *sev, "{mnemonic}");
        assert!(!flag.note.is_empty());
    }
}

#[test]
fn benign_opcodes_are_not_flagged_and_json_counts_match() {
    // ADD MUL SUB: arithmetic, nothing to warn about.
    let code = parse_hex("010203f4").unwrap(); // 3 benign + delegatecall
    let ins = disasm(&code);
    assert!(ins[0].flag.is_none());
    assert!(ins[1].flag.is_none());
    assert!(ins[2].flag.is_none());
    let v = disasm_json(&code);
    assert_eq!(v["instruction_count"], 4);
    assert_eq!(v["flagged_count"], 1); // only the DELEGATECALL
    assert_eq!(v["flags"][0]["severity"], "critical");
}

// ---- opcode decoding breadth ----------------------------------------------

#[test]
fn decodes_push_dup_swap_log_and_cancun_families() {
    // PUSH0(5f) DUP1(80) SWAP1(90) LOG0(a0) TLOAD(5c) MCOPY(5e) BLOBBASEFEE(4a)
    let ins = disasm(&parse_hex("5f8090a05c5e4a").unwrap());
    let names: Vec<&str> = ins.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(names, ["PUSH0", "DUP1", "SWAP1", "LOG0", "TLOAD", "MCOPY", "BLOBBASEFEE"]);
}

#[test]
fn unknown_opcode_labeled_and_trailing_push_truncated_without_panic() {
    let ins = disasm(&parse_hex("0c").unwrap()); // 0x0c is undefined
    assert!(ins[0].name.starts_with("UNKNOWN_0x0c"));

    // PUSH32 (0x7f) with no immediate bytes must not panic; operand is empty.
    let ins = disasm(&parse_hex("7f").unwrap());
    assert_eq!(ins[0].name, "PUSH32");
    assert_eq!(ins[0].operand.as_deref(), Some(""));
}

// ---- parse_hex: input validation error paths ------------------------------

#[test]
fn parse_hex_accepts_valid_forms() {
    assert_eq!(parse_hex("").unwrap(), Vec::<u8>::new());
    assert_eq!(parse_hex("0x6001").unwrap(), vec![0x60, 0x01]);
    assert_eq!(parse_hex("0X6001").unwrap(), vec![0x60, 0x01]);
    assert_eq!(parse_hex("60 01\n02").unwrap(), vec![0x60, 0x01, 0x02]);
}

#[test]
fn parse_hex_rejects_bad_input() {
    assert!(matches!(parse_hex("601"), Err(_))); // odd length
    assert!(matches!(parse_hex("60zz"), Err(_))); // non-hex digits
    assert!(matches!(parse_hex("€€"), Err(_))); // non-ascii, no panic
    assert!(matches!(parse_hex("0x0x6001"), Err(_))); // only one prefix stripped

    // Oversize inputs are rejected by the size guards.
    let over_clean = "5b".repeat(2_000_001); // >4M hex chars after cleaning
    assert_eq!(parse_hex(&over_clean), Err("bytecode exceeds 2MB limit".to_string()));
    let over_raw = "a".repeat(6_000_000); // >5M raw chars, rejected pre-clean
    assert_eq!(parse_hex(&over_raw), Err("bytecode exceeds 2MB limit".to_string()));
}

// ---- control-flow recovery and empty-input safety --------------------------

#[test]
fn basic_blocks_split_at_jumpdest_and_after_terminators() {
    // PUSH1 00 JUMP JUMPDEST STOP => leaders at pc0, after JUMP, and the JUMPDEST
    let ins = disasm(&parse_hex("6000565b00").unwrap());
    let blocks = basic_blocks(&ins);
    assert!(blocks.len() >= 2, "expected multiple blocks, got {blocks:?}");
    assert_eq!(blocks[0].0, 0); // first block starts at pc 0
}

#[test]
fn empty_bytecode_is_safe_across_the_whole_surface() {
    let code = parse_hex("").unwrap();
    assert!(disasm(&code).is_empty());
    assert!(basic_blocks(&disasm(&code)).is_empty());
    assert!(selectors(&disasm(&code)).is_empty());
    assert_eq!(render(&disasm(&code)), "");
    let v = disasm_json(&code);
    assert_eq!(v["instruction_count"], 0);
    assert_eq!(v["block_count"], 0);
    assert_eq!(v["flagged_count"], 0);
}
