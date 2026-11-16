/// Utility for masking sensitive tokens, keys, environment variables, and command-line arguments.
#[derive(Debug, Clone, Copy, Default)]
pub struct SecretMasker;

impl SecretMasker {
    /// Creates a new `SecretMasker`.
    pub fn new() -> Self {
        Self
    }
    /// Mask an environment variable value if the variable name indicates sensitive content.
    pub fn mask_env_var(key: &str, value: &str) -> String {
        let upper_key = key.to_uppercase();

        let sensitive_substrings = [
            "KEY",
            "SECRET",
            "TOKEN",
            "AUTH",
            "PASS",
            "CREDENTIAL",
            "PRIVATE",
            "SIGNING",
            "CERT",
            "BEARER",
            "COOKIE",
            "SESSION",
            "SSH",
            "WEBHOOK",
        ];

        let is_sensitive = sensitive_substrings
            .iter()
            .any(|sub| upper_key.contains(sub));

        if is_sensitive || Self::is_suspicious_token_value(value) {
            Self::redact_value(value)
        } else {
            value.to_string()
        }
    }

    /// Mask sensitive flags and values in command line argument lists.
    pub fn mask_cmdline(args: &[String]) -> Vec<String> {
        let mut masked = Vec::with_capacity(args.len());
        let mut mask_next = false;

        let flag_triggers = [
            "--token",
            "-token",
            "--api-key",
            "--apikey",
            "--password",
            "-password",
            "--secret",
            "-secret",
            "--auth-token",
            "--access-token",
        ];

        for arg in args {
            if mask_next {
                masked.push(Self::redact_value(arg));
                mask_next = false;
                continue;
            }

            let lower = arg.to_lowercase();

            // Check if this flag expects a sensitive argument next
            if flag_triggers.iter().any(|t| &lower == t) {
                masked.push(arg.clone());
                mask_next = true;
                continue;
            }

            // Check if flag is an inline key-value (e.g., --api-key=secret)
            if let Some((k, v)) = arg.split_once('=') {
                let k_lower = k.to_lowercase();
                if flag_triggers.iter().any(|t| {
                    k_lower == *t
                        || k_lower.contains("secret")
                        || k_lower.contains("token")
                        || k_lower.contains("password")
                }) {
                    masked.push(format!("{}={}", k, Self::redact_value(v)));
                    continue;
                }
            }

            // Check if argument contains a URL with embedded basic auth (e.g. postgres://user:pass@host:5432)
            if let Some(masked_url) = Self::mask_url_credentials(arg) {
                masked.push(masked_url);
                continue;
            }

            // Check for direct high-entropy token patterns
            if Self::is_suspicious_token_value(arg) {
                masked.push(Self::redact_value(arg));
            } else {
                masked.push(arg.clone());
            }
        }

        masked
    }

    /// Masks credentials in URLs like `protocol://user:pass@host/path`.
    pub fn mask_url_credentials(val: &str) -> Option<String> {
        if let Some(scheme_end) = val.find("://") {
            let after_scheme = &val[scheme_end + 3..];
            if let Some(at_idx) = after_scheme.find('@') {
                let user_info = &after_scheme[..at_idx];
                let remainder = &after_scheme[at_idx..];
                let scheme = &val[..scheme_end + 3];

                let masked_user_info = if let Some((user, _pass)) = user_info.split_once(':') {
                    format!("{}:[REDACTED]", user)
                } else {
                    "[REDACTED]".to_string()
                };

                return Some(format!("{}{}{}", scheme, masked_user_info, remainder));
            }
        }
        None
    }

    /// Redacts a sensitive string, preserving only first 2 and last 2 characters if long enough.
    pub fn redact_value(val: &str) -> String {
        let len = val.chars().count();
        if len <= 4 {
            "********".to_string()
        } else if len <= 12 {
            let first = val.chars().take(1).collect::<String>();
            let last = val
                .chars()
                .next_back()
                .map(|c| c.to_string())
                .unwrap_or_default();
            format!("{}***{}", first, last)
        } else {
            let first: String = val.chars().take(3).collect();
            let last: String = val
                .chars()
                .rev()
                .take(3)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            format!("{}...[REDACTED]...{}", first, last)
        }
    }

    /// Detects high-entropy tokens matching common provider patterns.
    pub fn is_suspicious_token_value(val: &str) -> bool {
        let prefixes = [
            "sk-ant-",  // Anthropic
            "sk-proj-", // OpenAI project
            "sk-",      // OpenAI generic
            "ghp_",     // GitHub Personal Access Token
            "gho_",     // GitHub OAuth
            "xoxb-",    // Slack Bot Token
            "xoxp-",    // Slack User Token
            "AKIA",     // AWS Access Key ID
        ];

        prefixes.iter().any(|prefix| val.starts_with(prefix))
    }

    /// Masks sensitive container or process labels.
    pub fn mask_labels(
        labels: &std::collections::HashMap<String, String>,
    ) -> std::collections::HashMap<String, String> {
        let mut masked = std::collections::HashMap::with_capacity(labels.len());
        for (k, v) in labels {
            let k_upper = k.to_uppercase();
            let is_sensitive_key = [
                "KEY",
                "SECRET",
                "TOKEN",
                "AUTH",
                "PASS",
                "CREDENTIAL",
                "PRIVATE",
                "CERT",
                "SIGNING",
            ]
            .iter()
            .any(|sub| k_upper.contains(sub));

            if is_sensitive_key || Self::is_suspicious_token_value(v) {
                masked.insert(k.clone(), Self::redact_value(v));
            } else {
                masked.insert(k.clone(), v.clone());
            }
        }
        masked
    }

    /// Masks general text containing sensitive values or patterns (instance method).
    pub fn mask_sensitive_text(&self, text: &str) -> String {
        Self::mask_string(text)
    }

    /// Masks a general string, checking for embedded URLs with credentials, suspicious tokens,
    /// or sensitive substrings.
    pub fn mask_string(val: &str) -> String {
        if let Some(masked) = Self::mask_url_credentials(val) {
            return masked;
        }

        for prefix in [
            "sk-ant-", "sk-proj-", "sk-", "ghp_", "gho_", "xoxb-", "xoxp-", "AKIA",
        ] {
            if let Some(idx) = val.find(prefix) {
                let end = val[idx..]
                    .find(|c: char| {
                        c.is_whitespace()
                            || c == '"'
                            || c == '\''
                            || c == '<'
                            || c == '>'
                            || c == ';'
                            || c == ','
                    })
                    .map(|e| idx + e)
                    .unwrap_or(val.len());
                let secret_slice = &val[idx..end];
                let redacted = Self::redact_value(secret_slice);
                return format!(
                    "{}{}{}",
                    &val[..idx],
                    redacted,
                    Self::mask_string(&val[end..])
                );
            }
        }

        if Self::is_suspicious_token_value(val) {
            Self::redact_value(val)
        } else {
            val.to_string()
        }
    }

    /// Masks URLs or returns the value masked as a string.
    pub fn mask_url(val: &str) -> String {
        Self::mask_string(val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_env_var_by_key() {
        assert_eq!(
            SecretMasker::mask_env_var("ANTHROPIC_API_KEY", "sk-ant-api03-123456789abcdef"),
            "sk-...[REDACTED]...def"
        );
        assert_eq!(
            SecretMasker::mask_env_var("DATABASE_PASSWORD", "supersecret123"),
            "sup...[REDACTED]...123"
        );
        assert_eq!(SecretMasker::mask_env_var("USER", "developer"), "developer");
    }

    #[test]
    fn test_mask_env_var_by_value_prefix() {
        assert_eq!(
            SecretMasker::mask_env_var("CUSTOM_VARIABLE", "sk-ant-secret1234567"),
            "sk-...[REDACTED]...567"
        );
    }

    #[test]
    fn test_mask_cmdline_flags() {
        let args = vec![
            "node".to_string(),
            "server.js".to_string(),
            "--token".to_string(),
            "secrettoken123".to_string(),
            "--port".to_string(),
            "8080".to_string(),
        ];
        let masked = SecretMasker::mask_cmdline(&args);
        assert_eq!(masked[0], "node");
        assert_eq!(masked[1], "server.js");
        assert_eq!(masked[2], "--token");
        assert_eq!(masked[3], "sec...[REDACTED]...123");
        assert_eq!(masked[4], "--port");
        assert_eq!(masked[5], "8080");
    }

    #[test]
    fn test_mask_cmdline_url() {
        let args = vec![
            "psql".to_string(),
            "postgres://postgres:secretpassword123@localhost:5432/mydb".to_string(),
        ];
        let masked = SecretMasker::mask_cmdline(&args);
        assert_eq!(masked[0], "psql");
        assert_eq!(
            masked[1],
            "postgres://postgres:[REDACTED]@localhost:5432/mydb"
        );
    }
}
