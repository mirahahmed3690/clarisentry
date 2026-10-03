//! Rule: public function mutates state or moves assets with no caller check.
//!
//! In Clarity the #1 access-control bug is a `define-public` that writes a map /
//! data-var or moves an asset but never checks WHO is calling. The idiomatic
//! guard is `(asserts! (is-eq tx-sender <owner>) err)` (or `contract-caller`).
//! If a state-changing public function references neither `tx-sender` nor
//! `contract-caller` anywhere, anyone can invoke the privileged action.

use super::{as_define_public, Context, Rule, ASSET_MOVES, STATE_WRITES};
use crate::finding::{Finding, Severity};

pub struct MissingAuth;

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
