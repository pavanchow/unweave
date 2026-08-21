use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "unweave",
    version,
    about = "An EVM bytecode disassembler that reconstructs intent and flags dangerous opcodes"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Disassemble EVM bytecode (a hex string, or a path to a file of hex).
    Disasm {
        /// Hex bytecode, or a file containing it.
        input: String,
        #[arg(long)]
        json: bool,
        /// Show only the flagged (security-relevant) opcodes.
        #[arg(long)]
        flags_only: bool,
    },
}

fn load(input: &str) -> Result<Vec<u8>> {
    let text = if std::path::Path::new(input).is_file() {
        std::fs::read_to_string(input)?
    } else {
        input.to_string()
    };
    unweave::parse_hex(&text).map_err(|e| anyhow!(e))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Disasm { input, json, flags_only } => {
            let code = load(&input)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&unweave::disasm_json(&code))?);
                return Ok(());
            }
            let ins = unweave::disasm(&code);
            if flags_only {
                let flagged: Vec<_> = ins.into_iter().filter(|i| i.flag.is_some()).collect();
                if flagged.is_empty() {
                    println!("no dangerous opcodes found in {} bytes", code.len());
                } else {
                    println!("{}", unweave::render(&flagged));
                }
            } else {
                print!("{}", unweave::render(&ins));
                let n = unweave::disasm(&code).iter().filter(|i| i.flag.is_some()).count();
                eprintln!("\n{n} flagged opcode(s)");
            }
        }
    }
    Ok(())
}
