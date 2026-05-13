# Auto-merge tool

This is a tool to fetch commits from an upstream repository and apply the changes if no conflicts exist. Conflicting commit hashes are reported.

## Usage

Checkout a feature branch:
```
git checkout -b daily-cherry-pick
```

Run the script
```
cargo run --release -- --remote=upstream --branch=master
```
