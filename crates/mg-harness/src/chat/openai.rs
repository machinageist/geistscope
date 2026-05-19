/*******************************************************************
 * Filename:        openai.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     ChatBackend impl for any OpenAI /v1/chat/completions API
 * Notes:           Works against the real OpenAI API and any compatible
 *                  server (LM Studio, vLLM, llama.cpp, OpenRouter, etc.).
 *                  Tool calls round-trip via the standard tool_calls field.
 *******************************************************************/

use serde_json::{Value, json};

use super::types::{
    ChatBackend, ChatContent, ChatError, ChatMessage, ChatRole, ChatStep, ToolCall, ToolDef,
};

const DEFAULT_OPENAI_BASE: &str = "https://api.openai.com/v1";

pub struct OpenAiChat {
    client: reqwest::Client,
    api_key: Option<String>,
    base_url: String,
    model: String,
}

impl OpenAiChat {
    pub fn new(
        api_key: Option<String>,
        base_url: Option<String>,
        model: impl Into<String>,
    ) -> Result<Self, ChatError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(ChatError::Http)?;
        Ok(Self {
            client,
            api_key,
            base_url: base_url.unwrap_or_else(|| DEFAULT_OPENAI_BASE.into()),
            model: model.into(),
        })
    }
}

#[async_trait::async_trait]
impl ChatBackend for OpenAiChat {
    fn model_label(&self) -> String {
        format!("openai/{}", self.model)
    }

    async fn step(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolDef],
    ) -> Result<ChatStep, ChatError> {
        let mut api_messages: Vec<Value> = Vec::new();

        for msg in messages {
            match (&msg.role, &msg.content) {
                (ChatRole::System, ChatContent::Text(t)) => {
                    api_messages.push(json!({ "role": "system", "content": t }));
                }
                (ChatRole::User, ChatContent::Text(t)) => {
                    api_messages.push(json!({ "role": "user", "content": t }));
                }
                (ChatRole::Assistant, ChatContent::Text(t)) => {
                    api_messages.push(json!({ "role": "assistant", "content": t }));
                }
                (ChatRole::Assistant, ChatContent::ToolCalls(calls)) => {
                    let tool_calls: Vec<Value> = calls
                        .iter()
                        .map(|c| {
                            json!({
                                "id": c.id,
                                "type": "function",
                                "function": {
                                    "name": c.name,
                                    "arguments": c.args.to_string(),
                                },
                            })
                        })
                        .collect();
                    api_messages.push(json!({
                        "role": "assistant",
                        "content": Value::Null,
                        "tool_calls": tool_calls,
                    }));
                }
                (
                    ChatRole::User,
                    ChatContent::ToolResult { call_id, content, .. },
                ) => {
                    api_messages.push(json!({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": content,
                    }));
                }
                _ => {}
            }
        }

        let api_tools: Vec<Value> = tools
            .iter()
            .map(|t| {
                json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    },
                })
            })
            .collect();

        let mut body = json!({
            "model": self.model,
            "messages": api_messages,
        });
        if !api_tools.is_empty() {
            body["tools"] = Value::Array(api_tools);
        }

        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let mut req = self.client.post(&url).json(&body);
        if let Some(key) = &self.api_key {
            req = req.bearer_auth(key);
        }
        let resp = req.send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(ChatError::Api(format!("status {status}: {text}")));
        }

        let value: Value = resp.json().await?;
        parse_openai_response(&value)
    }
}

// Extract text or tool calls from an OpenAI chat-completions response payload
fn parse_openai_response(value: &Value) -> Result<ChatStep, ChatError> {
    let msg = value
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
        .and_then(|c| c.get("message"))
        .ok_or_else(|| ChatError::Decode("missing choices[0].message".into()))?;

    if let Some(tcs) = msg.get("tool_calls").and_then(Value::as_array)
        && !tcs.is_empty()
    {
        let mut calls = Vec::new();
        for tc in tcs {
            let id = tc.get("id").and_then(Value::as_str).unwrap_or("").to_string();
            let func = tc.get("function").cloned().unwrap_or(Value::Null);
            let name = func.get("name").and_then(Value::as_str).unwrap_or("").to_string();
            // arguments comes back as a JSON-encoded string per OpenAI spec
            let args = match func.get("arguments").and_then(Value::as_str) {
                Some(s) => serde_json::from_str(s).unwrap_or(Value::Null),
                None => func.get("arguments").cloned().unwrap_or(Value::Null),
            };
            calls.push(ToolCall { id, name, args });
        }
        return Ok(ChatStep::ToolCalls(calls));
    }

    let text = msg
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    Ok(ChatStep::Message(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_openai_text_response() {
        let v = json!({
            "choices": [{"message": {"role": "assistant", "content": "hi"}}]
        });
        match parse_openai_response(&v).unwrap() {
            ChatStep::Message(t) => assert_eq!(t, "hi"),
            _ => panic!("expected message"),
        }
    }

    #[test]
    fn parse_openai_tool_calls() {
        let v = json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "tls.scan",
                            "arguments": "{\"target\":\"example.com\"}"
                        }
                    }]
                }
            }]
        });
        match parse_openai_response(&v).unwrap() {
            ChatStep::ToolCalls(c) => {
                assert_eq!(c.len(), 1);
                assert_eq!(c[0].name, "tls.scan");
                assert_eq!(c[0].args["target"], "example.com");
            }
            _ => panic!("expected tool calls"),
        }
    }
}
