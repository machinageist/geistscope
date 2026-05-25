/*******************************************************************
 * Filename:        types.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     Backend-neutral chat types for the mg-harness chat REPL
 * Notes:           ChatBackend trait abstracts Anthropic / OpenAI / Ollama.
 *                  ChatMessage uses an explicit Role-and-Content shape so we
 *                  can faithfully round-trip tool-use turns across all three
 *                  vendor JSON schemas without losing information.
 *******************************************************************/

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---- core chat shapes

#[derive(Debug, Clone)]
pub enum ChatRole {
    System,
    User,
    Assistant,
}

#[derive(Debug, Clone)]
pub enum ChatContent {
    // Plain text from user, system, or assistant
    Text(String),
    // Assistant requested one or more tool calls in this turn
    ToolCalls(Vec<ToolCall>),
    // User-side message carrying the result of a tool call
    ToolResult {
        call_id: String,
        content: String,
        is_error: bool,
    },
}

#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: ChatContent,
}

impl ChatMessage {
    pub fn system(text: impl Into<String>) -> Self {
        Self {
            role: ChatRole::System,
            content: ChatContent::Text(text.into()),
        }
    }
    pub fn user(text: impl Into<String>) -> Self {
        Self {
            role: ChatRole::User,
            content: ChatContent::Text(text.into()),
        }
    }
    pub fn assistant_text(text: impl Into<String>) -> Self {
        Self {
            role: ChatRole::Assistant,
            content: ChatContent::Text(text.into()),
        }
    }
    pub fn assistant_tool_calls(calls: Vec<ToolCall>) -> Self {
        Self {
            role: ChatRole::Assistant,
            content: ChatContent::ToolCalls(calls),
        }
    }
    pub fn tool_result(call: &ToolCall, content: String, is_error: bool) -> Self {
        Self {
            role: ChatRole::User,
            content: ChatContent::ToolResult {
                call_id: call.id.clone(),
                content,
                is_error,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub args: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}

#[derive(Debug, Clone)]
pub enum ChatStep {
    // Assistant produced a final text answer for this turn
    Message(String),
    // Assistant wants to invoke one or more tools; client must reply with results
    ToolCalls(Vec<ToolCall>),
}

// ---- backend trait

#[async_trait::async_trait]
pub trait ChatBackend: Send + Sync {
    // Send the conversation + tool catalog; return next step
    async fn step(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolDef],
    ) -> Result<ChatStep, ChatError>;

    // Human-readable model identifier for logs / banner
    fn model_label(&self) -> String;
}

#[derive(Debug, thiserror::Error)]
pub enum ChatError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("api: {0}")]
    Api(String),
    #[error("decode: {0}")]
    Decode(String),
}
