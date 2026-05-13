// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

use std::process::{Command, ExitCode, Stdio};

fn git_output(args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

// Runs a git command, inheriting stdout/stderr, returning whether it succeeded.
fn git_run(args: &[&str]) -> bool {
    Command::new("git")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn print_usage() {
    eprintln!("Usage: cherry-pick-upstream [--remote=<name>] [--branch=<name>]");
    eprintln!();
    eprintln!("  --remote=<name>   Upstream remote name (default: upstream)");
    eprintln!("  --branch=<name>   Upstream branch name (default: master)");
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut remote = "upstream".to_string();
    let mut branch = "master".to_string();

    for arg in &args {
        if let Some(val) = arg.strip_prefix("--remote=") {
            remote = val.to_string();
        } else if let Some(val) = arg.strip_prefix("--branch=") {
            branch = val.to_string();
        } else if arg == "--help" || arg == "-h" {
            print_usage();
            return ExitCode::SUCCESS;
        } else {
            eprintln!("Unknown argument: {arg}");
            print_usage();
            return ExitCode::FAILURE;
        }
    }

    let status = git_output(&["status", "--porcelain"]).unwrap_or_default();
    if !status.is_empty() {
        eprintln!("Working tree is not clean. Commit or stash changes first.");
        return ExitCode::FAILURE;
    }

    println!("Fetching {remote}/{branch}...");
    if !git_run(&["fetch", &remote, &branch]) {
        eprintln!("Failed to fetch {remote}/{branch}.");
        return ExitCode::FAILURE;
    }

    let upstream_ref = format!("{remote}/{branch}");

    let merge_base = match git_output(&["merge-base", "HEAD", &upstream_ref]) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Failed to find common ancestor: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("Common ancestor: {merge_base}");

    // Collect merge commits (merged PRs) from merge base to upstream HEAD, oldest first.
    let range = format!("{merge_base}..{upstream_ref}");
    let log = match git_output(&["log", "--merges", "--oneline", "--reverse", &range]) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("Failed to list upstream commits: {e}");
            return ExitCode::FAILURE;
        }
    };

    if log.is_empty() {
        println!("Already up to date with {upstream_ref}.");
        return ExitCode::SUCCESS;
    }

    let commits: Vec<&str> = log.lines().collect();
    println!("Found {} merge commits to cherry-pick.\n", commits.len());

    let mut succeeded = 0usize;
    let mut conflicts: Vec<String> = Vec::new();

    for line in &commits {
        let hash = match line.split_whitespace().next() {
            Some(h) => h,
            None => continue,
        };
        let subject: String = line
            .trim_start_matches(hash)
            .trim()
            .chars()
            .take(72)
            .collect();

        print!("{hash}  {subject} ... ");

        // -m 1: treat parent 1 (mainline) as the base when cherry-picking a merge commit.
        // -x:   append "cherry picked from commit <hash>" to the message.
        if git_run(&["cherry-pick", "-m", "1", "-x", hash]) {
            println!("ok");
            succeeded += 1;
        } else {
            println!("CONFLICT");
            conflicts.push(hash.to_string());
            git_run(&["cherry-pick", "--abort"]);
        }
    }

    println!();
    println!(
        "Done: {} applied, {} conflicted.",
        succeeded,
        conflicts.len()
    );

    if !conflicts.is_empty() {
        println!();
        println!("Conflicting commits (skipped):");
        for hash in &conflicts {
            println!("  {hash}");
        }
    }

    ExitCode::SUCCESS
}
