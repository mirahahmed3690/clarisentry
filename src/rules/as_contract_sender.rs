//! Rule: `tx-sender` used for authorization inside an `as-contract` block.
//!
//! `as-contract` runs the enclosed expression with `tx-sender` set to the
//! CONTRACT's own principal, not the caller's. An authorization check on
//! `tx-sender` inside `as-contract` therefore compares the contract against
//! itself — it is always true (or always wrong), silently defeating the guard.
//! (A classic Clarity footgun.)

use super::{Context, Rule};
use crate::finding::{Finding, Severity};
use crate::sexpr::Form;

pub struct AsContractSender;

impl Rule for AsContractSender {
    fn id(&self) -> &'static str {
        "as-contract-tx-sender-auth"
    }

    fn description(&self) -> &'static str {
        "tx-sender used in an is-eq/asserts check inside as-contract (refers to the contract)"
    }

    fn check(&self, ctx: &Context, out: &mut Vec<Finding>) {
        for form in ctx.forms {
            form.walk(&mut |f| {
                if f.head() != Some("as-contract") {
                    return;
                }
                // Look for an auth-shaped check (is-eq / asserts!) that references
                // tx-sender anywhere inside this as-contract subtree.
                let mut flagged_line: Option<usize> = None;
                f.walk(&mut |g| {
                    if flagged_line.is_some() {
                        return;
                    }
                    if matches!(g.head(), Some("is-eq") | Some("asserts!"))
                        && references_tx_sender(g)
                    {
                        flagged_line = Some(g.line());
                    }
                });
                if let Some(line) = flagged_line {
                    out.push(Finding::new(
                        self.id(),
                        Severity::High,
                        ctx.path,
                        line,
                        "`tx-sender` is checked inside an `as-contract` block, where it equals \
                         the contract's own principal — this authorization check does not \
                         validate the real caller."
                            .to_string(),
                        "Capture the caller before entering `as-contract` \
                         (e.g. `(let ((caller tx-sender)) ... (as-contract ...))`) and check \
                         the saved `caller`, or move the check outside the `as-contract`."
                            .to_string(),
                    ));
                }
            });
        }
    }
}

fn references_tx_sender(form: &Form) -> bool {
    form.contains_atom("tx-sender")
}
