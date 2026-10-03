//! Rule: use of `unwrap-panic` / `unwrap-err-panic`.
//!
//! These abort the whole transaction with a runtime error when the input is
//! `none` / not the expected branch. Unlike `unwrap!`/`try!`, they carry no
//! error value, so callers can't distinguish failure modes and an attacker may
//! be able to force a predictable abort (griefing / DoS of a shared flow). Each
//! use is worth reviewing: is the `none`/err branch truly unreachable?

use super::{Context, Rule};
use crate::finding::{Finding, Severity};

pub struct UnwrapPanic;

const PANIC_FORMS: &[&str] = &["unwrap-panic", "unwrap-err-panic"];

impl Rule for UnwrapPanic {
    fn id(&self) -> &'static str {
        "unwrap-panic"
    }

    fn description(&self) -> &'static str {
        "unwrap-panic / unwrap-err-panic aborts with no error value (review reachability)"
    }

    fn check(&self, ctx: &Context, out: &mut Vec<Finding>) {
        for form in ctx.forms {
            form.walk(&mut |f| {
                if let Some(h) = f.head() {
                    if PANIC_FORMS.contains(&h) {
                        out.push(Finding::new(
                            self.id(),
                            Severity::Low,
                            ctx.path,
                            f.line(),
                            format!(
                                "`{h}` aborts the transaction on the error/none branch with no \
                                 error value — confirm that branch is unreachable for untrusted input."
                            ),
                            "Prefer `(unwrap! expr (err u...))` or `try!` so the failure is a \
                             typed error the caller can handle, unless the branch is provably \
                             impossible."
                                .to_string(),
                        ));
                    }
                }
            });
        }
    }
}
