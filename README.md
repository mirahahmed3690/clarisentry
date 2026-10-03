# clarisentry

**A static analyzer for Clarity (Stacks) smart contracts.**

Clarity is one of the most under-tooled smart-contract ecosystems: Solidity has
Slither and Aderyn, Solana has a growing set of scanners — Clarity has almost
no open-source, CLI-native security linter. `clarisentry` is a first step. Point
it at a `.clar` file or a project and it flags **Clarity-specific**
vulnerability classes with file, line, severity, and a fix.

```
$ clarisentry ./contracts

+----------+----------------------------+--------------------+-------------------------------------------------+
| SEVERITY | RULE                       | LOCATION           | ISSUE                                            |
+----------+----------------------------+--------------------+-------------------------------------------------+
| HIGH     | missing-auth-check         | vault.clar:8       | public `set-owner` writes state with no caller  |
|          |                            |                    | check — anyone may call this privileged action. |
| HIGH     | as-contract-tx-sender-auth | vault.clar:21      | tx-sender checked inside as-contract (= the      |
|          |                            |                    | contract, not the caller).                       |
| LOW      | unwrap-panic               | vault.clar:26      | unwrap-panic aborts with no error value.         |
+----------+----------------------------+--------------------+-------------------------------------------------+
```

## Why Clarity needs its own rules

Clarity is not Solidity or Rust. It is a LISP-like, decidable language with **no
reentrancy, no integer overflow** (arithmetic traps at runtime), and explicit
responses. The usual EVM/Solana bug classes mostly don't apply. Clarity's real
footguns are different — and that's exactly what `clarisentry` targets.

| Rule | Severity | What it catches |
|------|----------|-----------------|
| `missing-auth-check` | High | A `define-public` that writes a map/var or moves an asset but never references `tx-sender` or `contract-caller` — no caller authorization. |
| `as-contract-tx-sender-auth` | High | An `is-eq`/`asserts!` on `tx-sender` **inside** `as-contract`, where `tx-sender` is the contract's own principal — the check doesn't validate the real caller. |
| `unwrap-panic` | Low | `unwrap-panic` / `unwrap-err-panic` abort with no error value; a reachable error branch is a griefing/DoS vector. |

> **v1 status:** these are AST-based heuristics tuned for high signal.
> `missing-auth-check` is deliberately conservative — it skips any function that
> references `tx-sender`/`contract-caller` at all, trading some false negatives
> for far fewer false positives. The roadmap adds data-flow to tell an auth
> *check* from an incidental use.

## Install

```bash
git clone https://github.com/mirahahmed3690/clarisentry
cd clarisentry
cargo install --path .
```

## Usage

```bash
clarisentry ./contracts          # scan a directory of .clar files
clarisentry vault.clar           # scan one file
clarisentry --json ./contracts   # machine-readable
clarisentry --list               # list all rules
clarisentry --fail-on high .     # exit 1 on any High (for CI)
```

Exit code is `1` when a finding at or above `--fail-on` (default `high`) is
present, so it drops straight into CI.

## How it works

1. **Parse** — a small s-expression reader turns each `.clar` file into a tree
   of atoms and lists, tracking the line of every form.
2. **Check** — each rule walks the tree looking for its pattern.
3. **Report** — a colored table, or JSON.

### Adding a rule

One file in `src/rules/`, implement the `Rule` trait, register it in
`all_rules()`. That's the whole extension surface.

## Roadmap

- **v2** — `tx-sender` vs `contract-caller` advisory; dynamic `contract-call?`
  (trait) arbitrary-call detection; unchecked `contract-call?` response; data-flow
  to distinguish an auth check from an incidental `tx-sender` use.
- **v3** — SARIF output, Clarinet project integration, a detection benchmark
  against known Stacks exploits.

## License

MIT.
