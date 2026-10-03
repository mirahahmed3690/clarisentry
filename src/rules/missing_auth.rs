//! Rule: public function mutates state or moves assets with no caller check.
//!
//! In Clarity the #1 access-control bug is a `define-public` that writes a map /
//! data-var or moves an asset but never checks WHO is calling. The idiomatic
//! guard is `(asserts! (is-eq tx-sender <owner>) err)` (or `contract-caller`).
//! If a state-changing public function references neither `tx-sender` nor
//! `contract-caller` anywhere, anyone can invoke the privileged action.

use super::{as_define_public, Context, Rule, ASSET_MOVES, STATE_WRITES};
use crate::finding::{Finding, Severity};
use crate::sexpr::Form;

pub struct MissingAuth;

/// Well-written Clarity contracts often centralize authorization in a helper
/// (`(try! (check-dao-auth))`, `(asserts! (is-authorized) ...)`, etc.) rather
/// than inlining `tx-sender`. Treat a call to such a helper as an auth check so
/// we don't flood real contracts with false positives. Heuristic on the callee
/// name — tuned for high precision (prefer a false negative over a false alarm).
fn is_auth_guard_call(head: &str) -> bool {
    let h = head.to_lowercase();
    // Substrings that strongly imply an auth check (not a setter). Note: bare
    // "owner"/"admin" is deliberately excluded — it matches setters like
    // `set-owner`. Those are caught only via the auth-check PREFIXes below.
    const SUBSTR: &[&str] = &[
        "auth", "approved", "permission", "allowed", "-dao", "whitelist", "guard",
    ];
    const PREFIX: &[&str] = &[
        "check-", "assert-", "only-", "verify-", "require-", "is-dao", "is-owner", "is-admin",
        "is-approved", "can-",
    ];
    SUBSTR.iter().any(|s| h.contains(s)) || PREFIX.iter().any(|p| h.starts_with(p))
}

/// Does the function BODY invoke a call that looks like an auth guard? The
/// function's own signature (its name + args) is excluded so a setter named
/// `set-owner` isn't mistaken for an auth helper.
fn calls_auth_guard(form: &Form) -> bool {
    let Some(items) = form.items() else {
        return false;
    };
    let mut found = false;
    // items[0] = `define-public`, items[1] = signature; body starts at [2].
    for body in items.iter().skip(2) {
        body.walk(&mut |f| {
            if let Some(h) = f.head() {
                if is_auth_guard_call(h) {
                    found = true;
                }
            }
        });
    }
    found
}

impl Rule for MissingAuth {
    fn id(&self) -> &'static str {
        "missing-auth-check"
    }

    fn description(&self) -> &'static str {
        "Public function changes state / moves assets without a tx-sender or contract-caller check"
    }

    fn check(&self, ctx: &Context, out: &mut Vec<Finding>) {
        for form in ctx.forms {
            let Some((name, line)) = as_define_public(form) else {
                continue;
            };

            let writes = form.contains_call(STATE_WRITES);
            let moves = form.contains_call(ASSET_MOVES);
            if !writes && !moves {
                continue; // read-only-ish public fn; nothing privileged to guard
            }

            let has_sender = form.contains_atom("tx-sender");
            let has_caller = form.contains_atom("contract-caller");
            if has_sender || has_caller {
                continue; // some caller-based check is present
            }
            if calls_auth_guard(form) {
                continue; // authorization delegated to an auth-helper function
            }

            let what = if moves {
                "moves assets"
            } else {
                "writes contract state"
            };
            out.push(Finding::new(
                self.id(),
                Severity::High,
                ctx.path,
                line,
                format!(
                    "public function `{name}` {what} but never references `tx-sender` or \
                     `contract-caller` — anyone may be able to call this privileged action."
                ),
                "Gate it with an authorization check, e.g. \
                 `(asserts! (is-eq tx-sender <owner>) (err u401))` near the top of the body."
                    .to_string(),
            ));
        }
    }
}
