/*******************************************************************
 * Filename:        ollama.rs
 * Author:          Jeff
 * Date:            2026-05-01
 * Description:     Ollama local LLM backend — chat completion via /api/chat
 * Notes:           Requires Ollama running at the configured endpoint.
 *                  stream=false blocks until completion; 120s timeout.
 *******************************************************************/

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::LlmError;

pub struct OllamaClient {
    endpoint: String,
    model: String,
    http: reqwest::Client,
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<Message<'a>>,
    stream: bool,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct ChatResponse {
    message: ResponseMessage,
}

#[derive(Deserialize)]
struct ResponseMessage {
    content: String,
}

impl OllamaClient {
    // Build an Ollama client; returns LlmError if the underlying HTTP builder fails
    pub fn new(endpoint: impl Into<String>, model: impl Into<String>) -> Result<Self, LlmError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()?;
        Ok(Self { endpoint: endpoint.into(), model: model.into(), http })
    }

    // Send system + user messages and return the assistant's reply text
    pub async fn complete(&self, system: &str, user: &str) -> Result<String, LlmError> {
        let url = format!("{}/api/chat", self.endpoint);
        let body = ChatRequest {
            model: &self.model,
            messages: vec![
                Message { role: "system", content: system },
                Message { role: "user", content: user },
            ],
            stream: false,
        };

        let resp: ChatResponse = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        if resp.message.content.is_empty() {
            return Err(LlmError::EmptyResponse);
        }
        Ok(resp.message.content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_serializes_correctly() {
        let req = ChatRequest {
            model: "mistral",
            messages: vec![
                Message { role: "system", content: "sys" },
                Message { role: "user", content: "usr" },
            ],
            stream: false,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["model"], "mistral");
        assert_eq!(json["stream"], false);
        assert_eq!(json["messages"][0]["role"], "system");
        assert_eq!(json["messages"][1]["role"], "user");
    }
}
