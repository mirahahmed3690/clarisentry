//! A small s-expression reader for Clarity source.
//!
//! Clarity is a LISP-like language, so its syntax parses cleanly into a tree of
//! atoms and lists. We track the 1-based line of every form so findings can
//! point at real locations. Comments start with `;` and run to end of line;
//! string literals are kept as single atoms.

#[derive(Debug, Clone)]
pub enum Form {
    Atom { text: String, line: usize },
    List { items: Vec<Form>, line: usize },
}

impl Form {
    pub fn line(&self) -> usize {
        match self {
            Form::Atom { line, .. } => *line,
            Form::List { line, .. } => *line,
        }
    }

    /// The atom text, if this form is an atom.
    pub fn atom(&self) -> Option<&str> {
        match self {
            Form::Atom { text, .. } => Some(text),
            _ => None,
        }
    }

    /// The head atom of a list, e.g. `define-public` in `(define-public ...)`.
    pub fn head(&self) -> Option<&str> {
        match self {
            Form::List { items, .. } => items.first().and_then(|f| f.atom()),
            _ => None,
        }
    }

    pub fn items(&self) -> Option<&[Form]> {
        match self {
            Form::List { items, .. } => Some(items),
            _ => None,
        }
    }

    /// Visit this form and every nested form, pre-order.
    pub fn walk<'a>(&'a self, f: &mut dyn FnMut(&'a Form)) {
        f(self);
        if let Form::List { items, .. } = self {
            for it in items {
                it.walk(f);
            }
        }
    }

    /// Does this form (anywhere in its subtree) contain an atom equal to `name`?
    pub fn contains_atom(&self, name: &str) -> bool {
        let mut found = false;
        self.walk(&mut |f| {
            if let Form::Atom { text, .. } = f {
                if text == name {
                    found = true;
                }
            }
        });
        found
    }

    /// Does the subtree contain a list whose head is one of `heads`?
    pub fn contains_call(&self, heads: &[&str]) -> bool {
        let mut found = false;
        self.walk(&mut |f| {
            if let Some(h) = f.head() {
                if heads.contains(&h) {
                    found = true;
                }
            }
        });
        found
    }
}

struct Lexer<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
    line: usize,
}

enum Tok {
    Open(usize),
    Close,
    Atom(String, usize),
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Lexer {
            chars: src.chars().peekable(),
            line: 1,
        }
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.chars.next();
        if c == Some('\n') {
            self.line += 1;
        }
        c
    }

    fn tokens(mut self) -> Vec<Tok> {
        let mut out = Vec::new();
        while let Some(&c) = self.chars.peek() {
            match c {
                '(' | '{' => {
                    let l = self.line;
                    self.bump();
                    out.push(Tok::Open(l));
                }
                ')' | '}' => {
                    self.bump();
                    out.push(Tok::Close);
                }
                ';' => {
                    // comment to end of line
                    while let Some(&c) = self.chars.peek() {
                        if c == '\n' {
                            break;
                        }
                        self.bump();
                    }
                }
                '"' => {
                    let l = self.line;
                    let mut s = String::from("\"");
                    self.bump();
                    while let Some(&c) = self.chars.peek() {
                        s.push(c);
                        self.bump();
                        if c == '"' {
                            break;
                        }
                    }
                    out.push(Tok::Atom(s, l));
                }
                // Commas separate Clarity tuple fields; treat them as whitespace
                // so `caller: tx-sender,` yields the atom `tx-sender`, not `tx-sender,`.
                c if c.is_whitespace() || c == ',' => {
                    self.bump();
                }
                _ => {
                    let l = self.line;
                    let mut s = String::new();
                    while let Some(&c) = self.chars.peek() {
                        if c.is_whitespace()
                            || matches!(c, '(' | ')' | '{' | '}' | ';' | '"' | ',')
                        {
                            break;
                        }
                        s.push(c);
                        self.bump();
                    }
                    if !s.is_empty() {
                        out.push(Tok::Atom(s, l));
                    }
                }
            }
        }
        out
    }
}

/// Parse Clarity source into the sequence of top-level forms. Unbalanced parens
/// are tolerated (best-effort) so partial files still yield useful structure.
pub fn parse(src: &str) -> Vec<Form> {
    let toks = Lexer::new(src).tokens();
    let mut pos = 0;
    let mut forms = Vec::new();
    while pos < toks.len() {
        if let Some(f) = parse_one(&toks, &mut pos) {
            forms.push(f);
        } else {
            pos += 1;
        }
    }
    forms
}

fn parse_one(toks: &[Tok], pos: &mut usize) -> Option<Form> {
    match toks.get(*pos)? {
        Tok::Atom(s, l) => {
            *pos += 1;
            Some(Form::Atom {
                text: s.clone(),
                line: *l,
            })
        }
        Tok::Open(l) => {
            let line = *l;
            *pos += 1;
            let mut items = Vec::new();
            while let Some(t) = toks.get(*pos) {
                if matches!(t, Tok::Close) {
                    *pos += 1;
                    break;
                }
                if let Some(f) = parse_one(toks, pos) {
                    items.push(f);
                } else {
                    break;
                }
            }
            Some(Form::List { items, line })
        }
        Tok::Close => {
            *pos += 1;
            None
        }
    }
}
