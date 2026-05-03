// Author: Jeff
// Date: 2026-05-01
// Description: Unified LLM client — Ollama (local) and Anthropic (remote)

pub mod anthropic;
pub mod ollama;

pub use anthropic::AnthropicClient;
pub use ollama::OllamaClient;

#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("api error: {0}")]
    Api(String),
    #[error("empty response from model")]
    EmptyResponse,
}

/// Unified interface over Ollama and Anthropic backends
pub enum LlmClient {
    Ollama(OllamaClient),
    Anthropic(AnthropicClient),
}

impl LlmClient {
    /// Local Ollama instance at the default endpoint (localhost:11434)
    pub fn ollama(model: impl Into<String>) -> Result<Self, LlmError> {
        Ok(Self::Ollama(OllamaClient::new("http://localhost:11434", model)?))
    }

    /// Local Ollama at a custom endpoint
    pub fn ollama_at(endpoint: impl Into<String>, model: impl Into<String>) -> Result<Self, LlmError> {
        Ok(Self::Ollama(OllamaClient::new(endpoint, model)?))
    }

    /// Anthropic API (remote)
    pub fn anthropic(api_key: impl Into<String>, model: impl Into<String>) -> Result<Self, LlmError> {
        Ok(Self::Anthropic(AnthropicClient::new(api_key, model)?))
    }

    /// Send a system + user prompt; returns the model's text reply
    pub async fn complete(&self, system: &str, user: &str) -> Result<String, LlmError> {
        match self {
            Self::Ollama(c) => c.complete(system, user).await,
            Self::Anthropic(c) => c.complete(system, user).await,
        }
    }
}
