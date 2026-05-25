/*******************************************************************
 * Filename:        ollama.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     ChatBackend impl for Ollama /api/chat (native tool use)
 * Notes:           Ollama 0.3+ supports tool calling natively on models like
 *                  qwen2.5-coder, llama3.1, mistral-large. We use the native
 *                  endpoint rather than its OpenAI-compat path because the
 *                  native one returns structured tool_calls reliably.
 *******************************************************************/

use serde_json::{Value, json};

use super::types::{
    ChatBackend, ChatContent, ChatError, ChatMessage, ChatRole, ChatStep, ToolCall, ToolDef,
};

pub struct OllamaChat {
    client: reqwest::Client,
    base_url: String,
    model: String,
}

impl OllamaChat {
    pub fn new(base_url: Option<String>, model: impl Into<String>) -> Result<Self, ChatError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(600))
            .build()
            .map_err(ChatError::Http)?;
        Ok(Self {
            client,
            base_url: base_url.unwrap_or_else(|| "http://localhost:11434".into()),
            model: model.into(),
        })
    }
}

#[async_trait::async_trait]
impl ChatBackend for OllamaChat {
    fn model_label(&self) -> String {
        format!("ollama/{}", self.model)
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
                                "function": {
                                    "name": c.name,
                                    "arguments": c.args,
                                },
                            })
                        })
                        .collect();
                    api_messages.push(json!({
                        "role": "assistant",
                        "content": "",
                        "tool_calls": tool_calls,
                    }));
                }
                (ChatRole::User, ChatContent::ToolResult { content, .. }) => {
                    // Ollama uses a "tool" role and does not key by call id
                    api_messages.push(json!({
                        "role": "tool",
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
            "stream": false,
        });
        if !api_tools.is_empty() {
            body["tools"] = Value::Array(api_tools);
        }

        let url = format!("{}/api/chat", self.base_url.trim_end_matches('/'));
        let resp = self.client.post(&url).json(&body).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(ChatError::Api(format!("status {status}: {text}")));
        }

        let value: Value = resp.json().await?;
        parse_ollama_response(&value)
    }
}

// Extract text or tool calls from an Ollama /api/chat response payload
fn parse_ollama_response(value: &Value) -> Result<ChatStep, ChatError> {
    let msg = value
        .get("message")
        .ok_or_else(|| ChatError::Decode("missing message".into()))?;

    if let Some(tcs) = msg.get("tool_calls").and_then(Value::as_array)
        && !tcs.is_empty()
    {
        let mut calls = Vec::new();
        for (i, tc) in tcs.iter().enumerate() {
            let func = tc.get("function").cloned().unwrap_or(Value::Null);
            let name = func
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            // Ollama returns arguments as an object directly (not stringified)
            let args = func.get("arguments").cloned().unwrap_or(Value::Null);
            // Ollama doesn't issue ids — synthesize one for round-tripping
            calls.push(ToolCall {
                id: format!("ollama-{i}"),
                name,
                args,
            });
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
    fn parse_ollama_text() {
        let v = json!({"message": {"role": "assistant", "content": "ok"}});
        match parse_ollama_response(&v).unwrap() {
            ChatStep::Message(t) => assert_eq!(t, "ok"),
            _ => panic!("expected message"),
        }
    }

    #[test]
    fn parse_ollama_tool_calls() {
        let v = json!({
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "function": {"name": "graph.summary", "arguments": {}}
                }]
            }
        });
        match parse_ollama_response(&v).unwrap() {
            ChatStep::ToolCalls(c) => {
                assert_eq!(c.len(), 1);
                assert_eq!(c[0].name, "graph.summary");
            }
            _ => panic!("expected tool calls"),
        }
    }
}
