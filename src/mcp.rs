//! MCP server so an agent can disassemble EVM bytecode and get flagged opcodes.
//! JSON-RPC 2.0 over stdio (newline-delimited).

use anyhow::Result;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

enum Reply {
    Ok(Value),
    Err(i64, String),
    Silent,
}

pub fn serve_mcp() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let id = req.get("id").cloned();
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        let reply = handle(method, req.get("params"));
        let envelope = match reply {
            Reply::Silent => continue,
            Reply::Ok(result) => match id {
                Some(id) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
                None => continue,
            },
            Reply::Err(code, msg) => match id {
                Some(id) => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": msg } }),
                None => continue,
            },
        };
        writeln!(stdout, "{envelope}")?;
        stdout.flush()?;
    }
    Ok(())
}

fn handle(method: &str, params: Option<&Value>) -> Reply {
    match method {
        "initialize" => Reply::Ok(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "unweave", "version": env!("CARGO_PKG_VERSION") }
        })),
        "notifications/initialized" => Reply::Silent,
        "ping" => Reply::Ok(json!({})),
        "tools/list" => Reply::Ok(json!({ "tools": [
            {
                "name": "unweave_disasm",
                "description": "Disassemble EVM bytecode (hex) and return instructions, basic blocks, recovered function selectors, and flagged dangerous opcodes (delegatecall, selfdestruct, external call, create2, tx.origin auth) with severity and explanation.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "hex": { "type": "string", "description": "EVM bytecode as hex (0x optional)." } },
                    "required": ["hex"]
                }
            }
        ] })),
        "tools/call" => {
            let params = params.cloned().unwrap_or(json!({}));
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            if name != "unweave_disasm" {
                return Reply::Ok(json!({
                    "content": [{ "type": "text", "text": format!("unknown tool: {name}") }],
                    "isError": true
                }));
            }
            let hex = params
                .get("arguments")
                .and_then(|a| a.get("hex"))
                .and_then(Value::as_str)
                .unwrap_or("");
            match crate::parse_hex(hex) {
                Ok(code) => Reply::Ok(json!({
                    "content": [{ "type": "text", "text": serde_json::to_string_pretty(&crate::disasm_json(&code)).unwrap_or_default() }],
                    "isError": false
                })),
                Err(e) => Reply::Ok(json!({
                    "content": [{ "type": "text", "text": e }],
                    "isError": true
                })),
            }
        }
        _ => Reply::Err(-32601, format!("method not found: {method}")),
    }
}
