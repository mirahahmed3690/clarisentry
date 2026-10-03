//! clarisentry — a static analyzer for Clarity (Stacks) smart contracts.
//!
//! Clarity is under-tooled compared with Solidity/Rust: no open-source,
//! CLI-native security linter in wide use. clarisentry flags Clarity-specific
//! vulnerability classes (missing caller checks, as-contract sender confusion,
//! panic-abort) with file:line, severity, and a fix.

mod finding;
mod report;
mod rules;
mod sexpr;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use finding::{Finding, Severity};
use rules::Context;
use walkdir::WalkDir;

#[derive(Parser)]
#[command(
    name = "clarisentry",
    version,
    about = "Static analyzer for Clarity (Stacks) smart contracts"
)]
struct Cli {
    /// A .clar file or a directory to scan.
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Emit findings as JSON.
    #[arg(long)]
    json: bool,
    /// List available rules and exit.
    #[arg(long)]
    list: bool,
    /// Exit 1 if a finding at this severity or above is present (high|medium|low|info).
    #[arg(long, default_value = "high")]
    fail_on: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if cli.list {
        for r in rules::all_rules() {
            println!("{:<26} {}", r.id(), r.description());
        }
        return ExitCode::SUCCESS;
    }

    let files = collect_clar(&cli.path);
    if files.is_empty() {
        eprintln!("No .clar files found under {}", cli.path.display());
        return ExitCode::SUCCESS;
    }

    let registry = rules::all_rules();
    let mut findings: Vec<Finding> = Vec::new();

    for file in &files {
        let src = match std::fs::read_to_string(file) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("warning: could not read {}: {e}", file.display());
                continue;
            }
        };
        let forms = sexpr::parse(&src);
        let path_str = file.display().to_string();
        let ctx = Context {
            path: &path_str,
            forms: &forms,
        };
        for rule in &registry {
            rule.check(&ctx, &mut findings);
        }
    }

    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then((a.severity as u8).cmp(&(b.severity as u8)))
    });

    if cli.json {
        if report::print_json(&findings).is_err() {
            return ExitCode::FAILURE;
        }
    } else {
        report::print_table(&findings);
        report::print_summary(&findings);
    }

    let threshold = parse_severity(&cli.fail_on) as u8;
    if findings.iter().any(|f| (f.severity as u8) <= threshold) {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn collect_clar(root: &Path) -> Vec<PathBuf> {
    if root.is_file() {
        return if is_clar(root) {
            vec![root.to_path_buf()]
        } else {
            vec![]
        };
    }
    WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| {
            e.path()
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n != "node_modules" && n != ".git" && n != "target")
                .unwrap_or(true)
        })
        .filter_map(|e| e.ok())
        .map(|e| e.into_path())
        .filter(|p| is_clar(p))
        .collect()
}

fn is_clar(p: &Path) -> bool {
    p.extension().map(|e| e == "clar").unwrap_or(false)
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        "info" => Severity::Info,
        _ => Severity::High,
    }
}
