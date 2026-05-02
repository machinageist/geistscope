// Author: Jeff
// Date: 2026-05-01
// Description: Unified LLM client — Ollama (local) and Anthropic (remote)

pub mod anthropic;
pub mod ollama;

pub use anthropic::AnthropicClient;
pub use ollama::OllamaClient;

#[derive(Debug)]
pub enum LlmError {
    Http(reqwest::Error),
    Api(String),
    EmptyResponse,
}

impl std::fmt::Display for LlmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(e) => write!(f, "http: {e}"),
            Self::Api(msg) => write!(f, "api error: {msg}"),
            Self::EmptyResponse => write!(f, "empty response from model"),
        }
    }
}

impl std::error::Error for LlmError {}

impl From<reqwest::Error> for LlmError {
    fn from(e: reqwest::Error) -> Self { Self::Http(e) }
}

/// Unified interface over Ollama and Anthropic backends
pub enum LlmClient {
    Ollama(OllamaClient),
    Anthropic(AnthropicClient),
}

impl LlmClient {
    /// Local Ollama instance at the default endpoint (localhost:11434)
    pub fn ollama(model: impl Into<String>) -> Self {
        Self::Ollama(OllamaClient::new("http://localhost:11434", model))
    }

    /// Local Ollama at a custom endpoint
    pub fn ollama_at(endpoint: impl Into<String>, model: impl Into<String>) -> Self {
        Self::Ollama(OllamaClient::new(endpoint, model))
    }

    /// Anthropic API (remote)
    pub fn anthropic(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        Self::Anthropic(AnthropicClient::new(api_key, model))
    }

    /// Send a system + user prompt; returns the model's text reply
    pub async fn complete(&self, system: &str, user: &str) -> Result<String, LlmError> {
        match self {
            Self::Ollama(c) => c.complete(system, user).await,
            Self::Anthropic(c) => c.complete(system, user).await,
        }
    }
}
