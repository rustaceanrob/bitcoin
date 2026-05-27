use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const ROW_WIDTH: usize = 129;
const RUNS: usize = 3;
const DEFAULT_BASE: &str = "master";
const DEFAULT_BUILD: &str = "build";
const DEFAULT_FILTER: &str = ".*";

struct CommitInfo {
    short: String,
    subject: String,
}

#[derive(Clone)]
struct BenchResult {
    name: String,
    ns_per_op: f64,
    err_pct: f64,
    instructions: Option<f64>,
    cycles: Option<f64>,
    unstable: bool,
}

fn print_help(prog: &str) {
    println!(
        "Usage: {prog} [OPTIONS]

Build bench_bitcoin at <base> and HEAD, run benchmarks, print a delta table.

Options:
  --filter <PATTERN>  Substring filter             (default: {DEFAULT_FILTER})
  --base <REF>        Base git ref                 (default: {DEFAULT_BASE})
  --build <DIR>       Build directory (repo-relative) (default: {DEFAULT_BUILD})
  --runs <N>          Runs per commit; keeps min   (default: {RUNS})
  -h, --help          Print this help"
    );
}

fn default_jobs() -> String {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .to_string()
}

fn git_output(args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .args(args)
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_owned());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn find_repo_root() -> Result<PathBuf, String> {
    git_output(&["rev-parse", "--show-toplevel"]).map(PathBuf::from)
}

fn resolve_base(base: &str) -> Result<String, String> {
    if let Ok(sha) = git_output(&["rev-parse", "--verify", base]) {
        return Ok(sha);
    }
    git_output(&["rev-parse", "--verify", &format!("origin/{base}")])
}

fn commit_subject(sha: &str) -> String {
    git_output(&["log", "-1", "--format=%s", sha]).unwrap_or_default()
}

fn short_sha(sha: &str) -> &str {
    &sha[..8]
}

fn cmake_configure(source: &Path, build: &Path) -> Result<(), String> {
    let status = Command::new("cmake")
        .arg("-B")
        .arg(build)
        .arg("-S")
        .arg(source)
        .arg("-DCMAKE_BUILD_TYPE=Release")
        .arg("-DBUILD_BENCH=ON")
        .arg("-DENABLE_WALLET=OFF")
        .arg("-DBUILD_TESTS=OFF")
        .arg("-DBUILD_UTIL=OFF")
        .arg("-DBUILD_TX=OFF")
        .arg("-DBUILD_DAEMON=OFF")
        .arg("-DBUILD_CLI=OFF")
        .arg("-DBUILD_GUI=OFF")
        .status()
        .map_err(|e| format!("cmake configure: {e}"))?;
    if !status.success() {
        return Err("cmake configure failed".to_owned());
    }
    Ok(())
}

fn cmake_build(build: &Path) -> Result<(), String> {
    let status = Command::new("cmake")
        .arg("--build")
        .arg(build)
        .arg("-j")
        .arg(default_jobs())
        .arg("--target")
        .arg("bench_bitcoin")
        .status()
        .map_err(|e| format!("cmake build: {e}"))?;
    if !status.success() {
        return Err("cmake build failed".to_owned());
    }
    Ok(())
}

fn parse_bench_stdout(output: &str) -> Vec<BenchResult> {
    let mut results = Vec::new();
    let mut err_col: usize = 3;
    let mut ins_col: Option<usize> = None;
    let mut cyc_col: Option<usize> = None;

    for line in output.lines() {
        if !line.starts_with('|') {
            continue;
        }
        let cols: Vec<&str> = line.split('|').map(str::trim).collect();
        if line.contains("---") {
            continue;
        }
        if line.contains(" benchmark") {
            err_col = cols.iter().position(|c| *c == "err%").unwrap_or(3);
            ins_col = cols.iter().position(|c| c.starts_with("ins/"));
            cyc_col = cols.iter().position(|c| c.starts_with("cyc/"));
            continue;
        }
        let Some(ns_per_op) = cols
            .get(1)
            .and_then(|s| s.replace(',', "").trim().parse::<f64>().ok())
        else {
            continue;
        };
        let err_pct = cols
            .get(err_col)
            .and_then(|s| s.trim_end_matches('%').trim().parse::<f64>().ok())
            .unwrap_or(0.0);
        let instructions =
            ins_col.and_then(|i| cols.get(i)?.replace(',', "").trim().parse::<f64>().ok());
        let cycles = cyc_col.and_then(|i| cols.get(i)?.replace(',', "").trim().parse::<f64>().ok());
        let raw = match cols.iter().rev().find(|c| c.contains('`')) {
            Some(s) => s.trim_matches('`').trim(),
            None => continue,
        };
        if raw.is_empty() {
            continue;
        }
        let unstable = raw.contains(" (Unstable");
        let name = raw.trim().trim_matches('`').trim().to_owned();
        results.push(BenchResult {
            name,
            ns_per_op,
            err_pct,
            instructions,
            cycles,
            unstable,
        });
    }
    results
}

fn run_bench(bin: &Path, filter: &str) -> Result<Vec<BenchResult>, String> {
    let pattern = format!(".*{filter}.*");
    let out = Command::new(bin)
        .arg(format!("-filter={pattern}"))
        .output()
        .map_err(|e| format!("bench_bitcoin: {e}"))?;
    if !out.status.success() {
        return Err("bench_bitcoin exited with non-zero status".to_owned());
    }
    Ok(parse_bench_stdout(&String::from_utf8_lossy(&out.stdout)))
}

fn merge_runs(runs: Vec<Vec<BenchResult>>) -> Vec<BenchResult> {
    let mut best: HashMap<String, BenchResult> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for r in runs.into_iter().flatten() {
        let entry = best.entry(r.name.clone()).or_insert_with(|| {
            order.push(r.name.clone());
            r.clone()
        });
        if r.ns_per_op < entry.ns_per_op {
            *entry = r;
        }
    }
    order.into_iter().filter_map(|n| best.remove(&n)).collect()
}

fn fmt_val(ns: f64) -> String {
    if ns.abs() >= 1_000_000.0 {
        format!("{:>12.3}M", ns / 1_000_000.0)
    } else if ns.abs() >= 1_000.0 {
        format!("{:>12.3}K", ns / 1_000.0)
    } else {
        format!("{:>12.3} ", ns)
    }
}

fn fmt_delta(delta: f64) -> String {
    let sign = if delta >= 0.0 { '+' } else { '-' };
    let a = delta.abs();
    let inner = if a >= 1_000_000.0 {
        format!("{sign}{:.3}M", a / 1_000_000.0)
    } else if a >= 1_000.0 {
        format!("{sign}{:.3}K", a / 1_000.0)
    } else {
        format!("{sign}{:.3}", a)
    };
    format!("{:>12}", inner)
}

fn print_table(
    base_info: &CommitInfo,
    head_info: &CommitInfo,
    base_results: &[BenchResult],
    head_results: &[BenchResult],
) {
    println!("\n{:^width$}", "BENCHMARK COMPARISON", width = ROW_WIDTH);
    println!("{}", "=".repeat(ROW_WIDTH));
    println!("  base : {}  {}", base_info.short, base_info.subject);
    println!("  head : {}  {}", head_info.short, head_info.subject);
    println!("{}", "=".repeat(ROW_WIDTH));
    println!(
        "  {:<36} | {:>13} | {:>13} | {:>8} | {:>6} | {:>6} | {:>12} | {:>12}",
        "benchmark", "base (ns)", "head (ns)", "Δ time%", "b.err%", "h.err%", "Δ ins", "Δ cyc"
    );
    println!("  {}", "─".repeat(ROW_WIDTH - 2));

    let head_map: HashMap<&str, &BenchResult> =
        head_results.iter().map(|r| (r.name.as_str(), r)).collect();

    for base_r in base_results {
        if base_r.unstable {
            continue;
        }
        let name = if base_r.name.len() > 36 {
            format!(
                "{}…{}",
                &base_r.name[..17],
                &base_r.name[base_r.name.len() - 18..]
            )
        } else {
            base_r.name.clone()
        };
        let Some(head_r) = head_map.get(base_r.name.as_str()) else {
            continue;
        };
        let pct = if base_r.ns_per_op != 0.0 {
            (head_r.ns_per_op - base_r.ns_per_op) / base_r.ns_per_op * 100.0
        } else {
            0.0
        };
        let ins_delta = base_r
            .instructions
            .zip(head_r.instructions)
            .map(|(b, h)| h - b);
        let cyc_delta = base_r.cycles.zip(head_r.cycles).map(|(b, h)| h - b);
        let pct_s = format!("{:>8}", format!("{pct:+.2}%"));
        let b_err = format!("{:>5.1}%", base_r.err_pct);
        let h_err = format!("{:>5.1}%", head_r.err_pct);
        let ins_s = ins_delta.map_or_else(|| format!("{:>12}", "N/A"), fmt_delta);
        let cyc_s = cyc_delta.map_or_else(|| format!("{:>12}", "N/A"), fmt_delta);
        println!(
            "  {:<36} | {} | {} | {} | {} | {} | {} | {}",
            name,
            fmt_val(base_r.ns_per_op),
            fmt_val(head_r.ns_per_op),
            pct_s,
            b_err,
            h_err,
            ins_s,
            cyc_s,
        );
    }

    println!("{}", "=".repeat(ROW_WIDTH));
}

fn build_and_run(
    repo: &Path,
    build: &Path,
    label: &str,
    sha: &str,
    filter: &str,
    runs: usize,
) -> Result<Vec<BenchResult>, String> {
    println!("\n  [{label}] checking out {}", short_sha(sha));

    git_output(&["checkout", sha])?;

    cmake_configure(repo, build)?;
    cmake_build(build)?;

    let bench_bin = build.join("bin").join("bench_bitcoin");
    if !bench_bin.exists() {
        return Err(format!(
            "bench_bitcoin not found at {}",
            bench_bin.display()
        ));
    }

    let all: Result<Vec<_>, _> = (1..=runs)
        .map(|i| {
            println!("  [{label}] run {i}/{runs}");
            run_bench(&bench_bin, filter)
        })
        .collect();

    Ok(merge_runs(all?))
}

#[allow(clippy::too_many_arguments)]
fn compare(
    repo: &Path,
    build: &Path,
    base_sha: &str,
    head_sha: &str,
    base_info: &CommitInfo,
    head_info: &CommitInfo,
    filter: &str,
    runs: usize,
) -> Result<(), String> {
    let base_results = build_and_run(repo, build, "base", base_sha, filter, runs)?;
    let head_results = build_and_run(repo, build, "head", head_sha, filter, runs)?;
    print_table(base_info, head_info, &base_results, &head_results);
    Ok(())
}

fn run() -> Result<(), String> {
    let mut argv = env::args();
    let prog = argv.next().unwrap_or_default();

    let mut filter = DEFAULT_FILTER.to_owned();
    let mut base = DEFAULT_BASE.to_owned();
    let mut build_dir = DEFAULT_BUILD.to_owned();
    let mut runs: usize = RUNS;

    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--filter" => {
                filter = argv.next().ok_or("--filter requires a value")?;
            }
            "--base" => {
                base = argv.next().ok_or("--base requires a value")?;
            }
            "--build" => {
                build_dir = argv.next().ok_or("--build requires a value")?;
            }
            "--runs" => {
                runs = argv
                    .next()
                    .ok_or("--runs requires a value")?
                    .parse::<usize>()
                    .map_err(|_| "--runs must be a positive integer")?;
                if runs == 0 {
                    return Err("--runs must be at least 1".to_owned());
                }
            }
            "-h" | "--help" => {
                print_help(&prog);
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    let repo = find_repo_root()?;

    let base_sha = resolve_base(&base)?;
    let head_sha = git_output(&["rev-parse", "HEAD"])?;

    if base_sha == head_sha {
        eprintln!(
            "warning: base and HEAD resolve to the same commit ({})",
            short_sha(&base_sha)
        );
    }

    let base_info = CommitInfo {
        short: short_sha(&base_sha).to_owned(),
        subject: commit_subject(&base_sha),
    };
    let head_info = CommitInfo {
        short: short_sha(&head_sha).to_owned(),
        subject: commit_subject(&head_sha),
    };

    let restore = git_output(&["symbolic-ref", "--short", "HEAD"])?;

    println!("  base   : {}  {}", base_info.short, base_info.subject);
    println!("  head   : {}  {}", head_info.short, head_info.subject);
    println!("  filter : {filter}");
    println!("  runs   : {runs}");

    let build = repo.join(&build_dir);
    let result = compare(
        &repo, &build, &base_sha, &head_sha, &base_info, &head_info, &filter, runs,
    );

    let _ = git_output(&["checkout", &restore]);

    result
}

fn main() {
    if let Err(e) = run() {
        eprintln!("\nerror: {e}");
        std::process::exit(1);
    }
}
