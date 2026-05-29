//! The AI judge — Svault's behavioural gate.
//!
//! For medium/high-sensitivity secrets (and any secret flagged `require_reason`)
//! the daemon asks a cheap, fast LLM, via the user's OpenRouter account, whether
//! the caller's stated *reason* plausibly justifies the request given the
//! secret's name/scope/tier and the caller's recent activity. The model returns
//! a structured `{decision, score, reason}`, which [`crate::gate`] turns into an
//! allow/deny against per-tier thresholds.
//!
//! The daemon is synchronous (thread-per-connection), so the HTTP call is
//! **blocking** (`ureq`). A [`JudgeTransport`] seam lets tests inject a fake so
//! `cargo test` never touches the network. The judge is **off until a key is
//! configured** — no key or `enabled = false` means the daemon falls back to the
//! static tier rules (high = human-only).

use anyhow::{anyhow, Result};
use std::time::Duration;

use crate::config::JudgeConfig;
use crate::policy::Tier;

/// What the judge said about one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JudgeVerdict {
    Allow {
        score: u8,
        rationale: String,
    },
    Deny {
        score: u8,
        rationale: String,
    },
    /// The model couldn't be reached or returned something unusable. The gate
    /// applies the tier-dependent fail mode (fail-open for medium, closed high).
    Unavailable {
        err: String,
    },
}

/// Everything the model needs to score one request. No secret *value* is ever
/// included — only the name and metadata.
pub struct JudgeContext<'a> {
    pub caller: &'a str,
    pub scope: &'a str,
    pub reason: &'a str,
    pub secret: &'a str,
    pub tier: Tier,
    pub vault: &'a str,
    pub recent: &'a str,
}

/// The HTTP seam. `chat` sends a system+user prompt to a chat-completions model
/// and returns the assistant's message content. Implemented by
/// [`OpenRouterTransport`] in production and a fake in tests.
pub trait JudgeTransport: Send + Sync {
    fn chat(&self, model: &str, system: &str, user: &str) -> Result<String>;
}

/// Production transport: blocking `ureq` against an OpenRouter-compatible
/// `/chat/completions` endpoint.
pub struct OpenRouterTransport {
    agent: ureq::Agent,
    base_url: String,
    api_key: zeroize::Zeroizing<String>,
}

impl OpenRouterTransport {
    pub fn new(api_key: zeroize::Zeroizing<String>, base_url: String, timeout: Duration) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(5))
            .timeout(timeout)
            .build();
        Self {
            agent,
            base_url,
            api_key,
        }
    }
}

impl JudgeTransport for OpenRouterTransport {
    fn chat(&self, model: &str, system: &str, user: &str) -> Result<String> {
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "model": model,
            "temperature": 0,
            "max_tokens": 300,
            "messages": [
                { "role": "system", "content": system },
                { "role": "user", "content": user },
            ],
        });
        let resp = self
            .agent
            .post(&url)
            .set("Authorization", &format!("Bearer {}", *self.api_key))
            .set("Content-Type", "application/json")
            .set("HTTP-Referer", "https://github.com/Soluzy/Svault")
            .set("X-Title", "Svault")
            .send_json(body)
            .map_err(|e| anyhow!("openrouter request failed: {e}"))?;
        let v: serde_json::Value = resp
            .into_json()
            .map_err(|e| anyhow!("openrouter response not JSON: {e}"))?;
        v["choices"][0]["message"]["content"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("openrouter response had no message content"))
    }
}

/// A ready-to-use judge: a transport plus the resolved thresholds and the
/// global default model. Built once at daemon start (and per-call in the CLI
/// fallback). Per-vault model overrides are applied by the caller.
pub struct JudgeRuntime {
    pub model: String,
    pub allow_threshold: u8,
    pub high_threshold: u8,
    pub transport: Box<dyn JudgeTransport>,
}

impl JudgeRuntime {
    /// Build a runtime from config, resolving the API key. Returns `None` when
    /// the judge is disabled or no key is available (caller then runs the static
    /// tier rules).
    pub fn from_config(cfg: &JudgeConfig) -> Option<Self> {
        if !cfg.enabled {
            return None;
        }
        let key = crate::config::openrouter_key(cfg)?;
        let transport = OpenRouterTransport::new(
            key,
            cfg.base_url.clone(),
            Duration::from_secs(cfg.timeout_secs),
        );
        Some(Self {
            model: cfg.model.clone(),
            allow_threshold: cfg.allow_threshold,
            high_threshold: cfg.high_threshold,
            transport: Box::new(transport),
        })
    }
}

const SYSTEM_PROMPT: &str = "\
You are the access-control judge for Svault, a secret manager that gates AI-agent \
access to credentials. Given a structured request, decide whether the stated reason \
plausibly and specifically justifies handing this secret to this caller right now, \
considering the secret's sensitivity tier and the caller's recent activity. Deny vague, \
generic, mismatched, or suspicious requests (e.g. a reason unrelated to the secret's \
scope, or a burst of requests). Reply with ONLY a compact JSON object and nothing else: \
{\"decision\":\"allow\"|\"deny\",\"score\":0-100,\"reason\":\"<short>\"}. \
score is your confidence (0-100) that the request is legitimate.";

fn user_prompt(ctx: &JudgeContext) -> String {
    format!(
        "Caller: {}\nSecret: {}\nScope: {}\nSensitivity tier: {}\nVault: {}\nStated reason: {}\nRecent activity: {}",
        ctx.caller, ctx.secret, ctx.scope, ctx.tier, ctx.vault, ctx.reason, ctx.recent
    )
}

/// Ask the judge about one request. `model` lets the caller pass a per-vault
/// override; pass `rt.model.clone()` for the default.
pub fn evaluate(rt: &JudgeRuntime, model: &str, ctx: &JudgeContext) -> JudgeVerdict {
    match rt.transport.chat(model, SYSTEM_PROMPT, &user_prompt(ctx)) {
        Ok(content) => parse_verdict(&content),
        Err(e) => JudgeVerdict::Unavailable { err: e.to_string() },
    }
}

/// Parse the model's reply into a verdict. Tolerates code-fenced or
/// prose-wrapped JSON by extracting the first `{...}` block. An unparseable
/// reply is treated as `Unavailable` so the tier fail mode applies.
fn parse_verdict(content: &str) -> JudgeVerdict {
    let Some(json) = extract_json(content) else {
        return JudgeVerdict::Unavailable {
            err: "judge reply was not JSON".to_string(),
        };
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return JudgeVerdict::Unavailable {
            err: "judge reply was not valid JSON".to_string(),
        };
    };
    let decision = v["decision"].as_str().unwrap_or("").to_lowercase();
    let score = v["score"].as_u64().unwrap_or(0).min(100) as u8;
    let rationale = v["reason"].as_str().unwrap_or("").trim().to_string();
    match decision.as_str() {
        "allow" => JudgeVerdict::Allow { score, rationale },
        "deny" => JudgeVerdict::Deny { score, rationale },
        _ => JudgeVerdict::Unavailable {
            err: "judge reply had no allow/deny decision".to_string(),
        },
    }
}

fn extract_json(s: &str) -> Option<&str> {
    let start = s.find('{')?;
    let end = s.rfind('}')?;
    if end > start {
        Some(&s[start..=end])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeTransport(Result<String, String>);
    impl JudgeTransport for FakeTransport {
        fn chat(&self, _m: &str, _s: &str, _u: &str) -> Result<String> {
            self.0.clone().map_err(|e| anyhow!(e))
        }
    }

    fn rt(reply: Result<String, String>) -> JudgeRuntime {
        JudgeRuntime {
            model: "test".into(),
            allow_threshold: 60,
            high_threshold: 80,
            transport: Box::new(FakeTransport(reply)),
        }
    }

    fn ctx() -> JudgeContext<'static> {
        JudgeContext {
            caller: "claude",
            scope: "database",
            reason: "run the nightly migration",
            secret: "DB_URL",
            tier: Tier::Medium,
            vault: "proj",
            recent: "none",
        }
    }

    #[test]
    fn parses_allow() {
        let v = evaluate(
            &rt(Ok(
                r#"{"decision":"allow","score":82,"reason":"plausible"}"#.into(),
            )),
            "test",
            &ctx(),
        );
        assert_eq!(
            v,
            JudgeVerdict::Allow {
                score: 82,
                rationale: "plausible".into()
            }
        );
    }

    #[test]
    fn parses_code_fenced_json() {
        let v = evaluate(
            &rt(Ok(
                "```json\n{\"decision\":\"deny\",\"score\":10,\"reason\":\"vague\"}\n```".into(),
            )),
            "test",
            &ctx(),
        );
        assert_eq!(
            v,
            JudgeVerdict::Deny {
                score: 10,
                rationale: "vague".into()
            }
        );
    }

    #[test]
    fn malformed_is_unavailable() {
        assert!(matches!(
            evaluate(&rt(Ok("I cannot help with that".into())), "test", &ctx()),
            JudgeVerdict::Unavailable { .. }
        ));
    }

    #[test]
    fn transport_error_is_unavailable() {
        assert!(matches!(
            evaluate(&rt(Err("timeout".into())), "test", &ctx()),
            JudgeVerdict::Unavailable { .. }
        ));
    }
}
