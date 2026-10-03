use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule: String,
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    pub message: String,
    pub fix: String,
}

impl Finding {
    pub fn new(
        rule: &str,
        severity: Severity,
        file: &str,
        line: usize,
        message: impl Into<String>,
        fix: impl Into<String>,
    ) -> Self {
        Finding {
            rule: rule.to_string(),
            severity,
            file: file.to_string(),
            line,
            message: message.into(),
            fix: fix.into(),
        }
    }
}
