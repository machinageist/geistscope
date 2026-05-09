/*******************************************************************
 * Filename:        anthropic.rs
 * Author:          Jeff
 * Date:            2026-05-01
 * Description:     Anthropic API backend — messages endpoint
 * Notes:           MAX_TOKENS raised from 2048 to 8192; prioritization tables
 *                  routinely exceed the old limit.
 *******************************************************************/

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::LlmError;

const ANTHROPIC_API_URL: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2023-06-01";
// raised from 2048 — prioritization tables and analysis routinely exceed the old limit
const MAX_TOKENS: u32 = 8192;

pub struct AnthropicClient {
    api_key: String,
    model: String,
    http: reqwest::Client,
}

#[derive(Serialize)]
struct Request<'a> {
    model: &'a str,
    max_tokens: u32,
    system: &'a str,
    messages: Vec<UserMessage<'a>>,
}

#[derive(Serialize)]
struct UserMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct Response {
    content: Vec<ContentBlock>,
}

#[derive(Deserialize)]
struct ContentBlock {
    #[serde(rename = "type")]
    kind: String,
    text: Option<String>,
}

impl AnthropicClient {
    // Build an Anthropic client; returns LlmError if the underlying HTTP builder fails
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Result<Self, LlmError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()?;
        Ok(Self { api_key: api_key.into(), model: model.into(), http })
    }

    // Send system + user messages and return the first text content block from the response
    pub async fn complete(&self, system: &str, user: &str) -> Result<String, LlmError> {
        let body = Request {
            model: &self.model,
            max_tokens: MAX_TOKENS,
            system,
            messages: vec![UserMessage { role: "user", content: user }],
        };

        let resp: Response = self
            .http
            .post(ANTHROPIC_API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        resp.content
            .into_iter()
            .find(|b| b.kind == "text")
            .and_then(|b| b.text)
            .filter(|t| !t.is_empty())
            .ok_or(LlmError::EmptyResponse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_serializes_correctly() {
        let req = Request {
            model: "claude-sonnet-4-6",
            max_tokens: MAX_TOKENS,
            system: "sys",
            messages: vec![UserMessage { role: "user", content: "usr" }],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["model"], "claude-sonnet-4-6");
        assert_eq!(json["max_tokens"], MAX_TOKENS);
        assert_eq!(json["system"], "sys");
        assert_eq!(json["messages"][0]["role"], "user");
    }
}
