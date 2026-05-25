/*******************************************************************
 * Filename:        anthropic.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     ChatBackend impl for Anthropic Messages API with tool use
 * Notes:           Maps ChatMessage to Anthropic content blocks. Tool use
 *                  arrives as `tool_use` blocks; results go back as
 *                  `tool_result` blocks inside a user message.
 *******************************************************************/

use serde_json::{Value, json};

use super::types::{
    ChatBackend, ChatContent, ChatError, ChatMessage, ChatRole, ChatStep, ToolCall, ToolDef,
};

const ANTHROPIC_API_BASE: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const DEFAULT_MAX_TOKENS: u32 = 4096;

pub struct AnthropicChat {
    client: reqwest::Client,
    api_key: String,
    model: String,
}

impl AnthropicChat {
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Result<Self, ChatError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(ChatError::Http)?;
        Ok(Self {
            client,
            api_key: api_key.into(),
            model: model.into(),
        })
    }
}

#[async_trait::async_trait]
impl ChatBackend for AnthropicChat {
    fn model_label(&self) -> String {
        format!("anthropic/{}", self.model)
    }

    async fn step(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolDef],
    ) -> Result<ChatStep, ChatError> {
        let mut system_text = String::new();
        let mut api_messages: Vec<Value> = Vec::new();

        for msg in messages {
            match (&msg.role, &msg.content) {
                (ChatRole::System, ChatContent::Text(t)) => {
                    if !system_text.is_empty() {
                        system_text.push_str("\n\n");
                    }
                    system_text.push_str(t);
                }
                (ChatRole::User, ChatContent::Text(t)) => {
                    api_messages.push(json!({ "role": "user", "content": t }));
                }
                (ChatRole::Assistant, ChatContent::Text(t)) => {
                    api_messages.push(json!({ "role": "assistant", "content": t }));
                }
                (ChatRole::Assistant, ChatContent::ToolCalls(calls)) => {
                    let blocks: Vec<Value> = calls
                        .iter()
                        .map(|c| {
                            json!({
                                "type": "tool_use",
                                "id": c.id,
                                "name": c.name,
                                "input": c.args,
                            })
                        })
                        .collect();
                    api_messages.push(json!({ "role": "assistant", "content": blocks }));
                }
                (
                    ChatRole::User,
                    ChatContent::ToolResult {
                        call_id,
                        content,
                        is_error,
                        ..
                    },
                ) => {
                    api_messages.push(json!({
                        "role": "user",
                        "content": [{
                            "type": "tool_result",
                            "tool_use_id": call_id,
                            "content": content,
                            "is_error": is_error,
                        }],
                    }));
                }
                _ => {} // unsupported role/content combos are ignored
            }
        }

        let api_tools: Vec<Value> = tools
            .iter()
            .map(|t| {
                json!({
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.parameters,
                })
            })
            .collect();

        let body = json!({
            "model": self.model,
            "max_tokens": DEFAULT_MAX_TOKENS,
            "system": system_text,
            "messages": api_messages,
            "tools": api_tools,
        });

        let resp = self
            .client
            .post(ANTHROPIC_API_BASE)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(ChatError::Api(format!("status {status}: {text}")));
        }

        let value: Value = resp.json().await?;
        parse_anthropic_response(&value)
    }
}

// Extract text or tool calls from an Anthropic Messages response payload
fn parse_anthropic_response(value: &Value) -> Result<ChatStep, ChatError> {
    let blocks = value
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| ChatError::Decode("missing content array".into()))?;

    let mut text_buf = String::new();
    let mut tool_calls: Vec<ToolCall> = Vec::new();
    for block in blocks {
        match block.get("type").and_then(Value::as_str) {
            Some("text") => {
                if let Some(t) = block.get("text").and_then(Value::as_str) {
                    text_buf.push_str(t);
                }
            }
            Some("tool_use") => {
                let id = block
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let name = block
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let input = block.get("input").cloned().unwrap_or(Value::Null);
                tool_calls.push(ToolCall {
                    id,
                    name,
                    args: input,
                });
            }
            _ => {}
        }
    }

    if !tool_calls.is_empty() {
        Ok(ChatStep::ToolCalls(tool_calls))
    } else {
        Ok(ChatStep::Message(text_buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_text_only_response() {
        let v = json!({
            "content": [{"type": "text", "text": "hello"}]
        });
        let step = parse_anthropic_response(&v).unwrap();
        match step {
            ChatStep::Message(t) => assert_eq!(t, "hello"),
            _ => panic!("expected message"),
        }
    }

    #[test]
    fn parse_tool_use_response() {
        let v = json!({
            "content": [
                {"type": "text", "text": "calling tool"},
                {"type": "tool_use", "id": "abc", "name": "tls.scan", "input": {"target": "example.com"}}
            ]
        });
        let step = parse_anthropic_response(&v).unwrap();
        match step {
            ChatStep::ToolCalls(calls) => {
                assert_eq!(calls.len(), 1);
                assert_eq!(calls[0].name, "tls.scan");
            }
            _ => panic!("expected tool calls"),
        }
    }
}
