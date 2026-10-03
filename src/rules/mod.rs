//! Rule engine. Each Clarity vulnerability class is a `Rule`. Adding a class =
//! add one file, implement `Rule`, register in `all_rules()`.

use crate::finding::Finding;
use crate::sexpr::Form;

mod as_contract_sender;
mod missing_auth;
mod unwrap_panic;

pub struct Context<'a> {
    pub path: &'a str,
    pub forms: &'a [Form],
}

pub trait Rule {
    fn id(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn check(&self, ctx: &Context, out: &mut Vec<Finding>);
}

pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(missing_auth::MissingAuth),
        Box::new(as_contract_sender::AsContractSender),
        Box::new(unwrap_panic::UnwrapPanic),
    ]
}

// ---- shared helpers over Clarity forms ----

/// State-mutating calls: writing a map or data-var.
pub(crate) const STATE_WRITES: &[&str] = &["map-set", "map-insert", "map-delete", "var-set"];

/// Asset-moving calls (native STX, fungible, non-fungible).
pub(crate) const ASSET_MOVES: &[&str] = &[
    "stx-transfer?",
    "stx-transfer-memo?",
    "ft-transfer?",
    "ft-mint?",
    "ft-burn?",
    "nft-transfer?",
    "nft-mint?",
    "nft-burn?",
];

/// Is this form a `(define-public (name (args...)) body...)`? Returns (name, line).
pub(crate) fn as_define_public(form: &Form) -> Option<(String, usize)> {
    if form.head()? != "define-public" {
        return None;
    }
    let items = form.items()?;
    // items[1] is the signature list `(name (arg ty) ...)`
    let sig = items.get(1)?;
    let name = sig.items()?.first()?.atom()?.to_string();
    Some((name, form.line()))
}
