use crate::{AikeyError, ChatMessage, ChatResponse, ChatRole, TokenUsage};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use zeroize::Zeroizing;

/// Provider adapter trait
pub trait ProviderAdapter: Send + Sync {
    /// Make a chat request with retry logic
    fn chat(
        &self,
        api_key: &Zeroizing<String>,
        model: &str,
        messages: Vec<ChatMessage>,
    ) -> Result<ChatResponse, AikeyError>;
}

/// OpenAI adapter
pub struct OpenAIAdapter {
    client: reqwest::blocking::Client,
}

impl OpenAIAdapter {
    pub fn new() -> Self {
        Self {
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    fn make_request_with_retry(
        &self,
        api_key: &str,
        model: &str,
        messages: &[ChatMessage],
    ) -> Result<ChatResponse, AikeyError> {
        let mut attempts = 0;
        let max_attempts = 3;

        loop {
            attempts += 1;

            match self.make_request(api_key, model, messages) {
                Ok(response) => return Ok(response),
                Err(e) => {
                    if attempts >= max_attempts {
                        return Err(e);
                    }
                    // Exponential backoff: 1s, 2s, 4s
                    let delay = Duration::from_secs(2u64.pow(attempts - 1));
                    std::thread::sleep(delay);
                }
            }
        }
    }

    fn make_request(
        &self,
        api_key: &str,
        model: &str,
        messages: &[ChatMessage],
    ) -> Result<ChatResponse, AikeyError> {
        #[derive(Serialize)]
        struct OpenAIRequest {
            model: String,
            messages: Vec<OpenAIMessage>,
        }

        #[derive(Serialize)]
        struct OpenAIMessage {
            role: String,
            content: String,
        }

        #[derive(Deserialize)]
        struct OpenAIResponse {
            choices: Vec<OpenAIChoice>,
            model: String,
            usage: Option<OpenAIUsage>,
        }

        #[derive(Deserialize)]
        struct OpenAIChoice {
            message: OpenAIResponseMessage,
        }

        #[derive(Deserialize)]
        struct OpenAIResponseMessage {
            content: String,
        }

        #[derive(Deserialize)]
        struct OpenAIUsage {
            prompt_tokens: u32,
            completion_tokens: u32,
            total_tokens: u32,
        }

        let openai_messages: Vec<OpenAIMessage> = messages
            .iter()
            .map(|msg| OpenAIMessage {
                role: match msg.role {
                    ChatRole::System => "system".to_string(),
                    ChatRole::User => "user".to_string(),
                    ChatRole::Assistant => "assistant".to_string(),
                },
                content: msg.content.clone(),
            })
            .collect();

        let request_body = OpenAIRequest {
            model: model.to_string(),
            messages: openai_messages,
        };

        let response = self
            .client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AikeyError::Provider(format!(
                "OpenAI API error ({}): {}",
                status, error_text
            )));
        }

        let openai_response: OpenAIResponse = response.json()?;

        let content = openai_response
            .choices
            .first()
            .map(|choice| choice.message.content.clone())
            .ok_or_else(|| AikeyError::Provider("No response from OpenAI".to_string()))?;

        let usage = openai_response.usage.map(|u| TokenUsage {
            prompt_tokens: u.prompt_tokens,
            completion_tokens: u.completion_tokens,
            total_tokens: u.total_tokens,
        });

        Ok(ChatResponse {
            content,
            model: openai_response.model,
            provider: "openai".to_string(),
            usage,
        })
    }
}

impl ProviderAdapter for OpenAIAdapter {
    fn chat(
        &self,
        api_key: &Zeroizing<String>,
        model: &str,
        messages: Vec<ChatMessage>,
    ) -> Result<ChatResponse, AikeyError> {
        self.make_request_with_retry(api_key.as_str(), model, &messages)
    }
}

/// Anthropic adapter
pub struct AnthropicAdapter {
    client: reqwest::blocking::Client,
}

impl AnthropicAdapter {
    pub fn new() -> Self {
        Self {
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    fn make_request_with_retry(
        &self,
        api_key: &str,
        model: &str,
        messages: &[ChatMessage],
    ) -> Result<ChatResponse, AikeyError> {
        let mut attempts = 0;
        let max_attempts = 3;

        loop {
            attempts += 1;

            match self.make_request(api_key, model, messages) {
                Ok(response) => return Ok(response),
                Err(e) => {
                    if attempts >= max_attempts {
                        return Err(e);
                    }
                    // Exponential backoff: 1s, 2s, 4s
                    let delay = Duration::from_secs(2u64.pow(attempts - 1));
                    std::thread::sleep(delay);
                }
            }
        }
    }

    fn make_request(
        &self,
        api_key: &str,
        model: &str,
        messages: &[ChatMessage],
    ) -> Result<ChatResponse, AikeyError> {
        #[derive(Serialize)]
        struct AnthropicRequest {
            model: String,
            messages: Vec<AnthropicMessage>,
            max_tokens: u32,
        }

        #[derive(Serialize)]
        struct AnthropicMessage {
            role: String,
            content: String,
        }

        #[derive(Deserialize)]
        struct AnthropicResponse {
            content: Vec<AnthropicContent>,
            model: String,
            usage: Option<AnthropicUsage>,
        }

        #[derive(Deserialize)]
        struct AnthropicContent {
            text: String,
        }

        #[derive(Deserialize)]
        struct AnthropicUsage {
            input_tokens: u32,
            output_tokens: u32,
        }

        // Anthropic doesn't support system messages in the messages array
        // Filter them out for now (proper handling would move to system parameter)
        let anthropic_messages: Vec<AnthropicMessage> = messages
            .iter()
            .filter(|msg| !matches!(msg.role, ChatRole::System))
            .map(|msg| AnthropicMessage {
                role: match msg.role {
                    ChatRole::User => "user".to_string(),
                    ChatRole::Assistant => "assistant".to_string(),
                    ChatRole::System => "user".to_string(), // Fallback
                },
                content: msg.content.clone(),
            })
            .collect();

        let request_body = AnthropicRequest {
            model: model.to_string(),
            messages: anthropic_messages,
            max_tokens: 4096,
        };

        let response = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AikeyError::Provider(format!(
                "Anthropic API error ({}): {}",
                status, error_text
            )));
        }

        let anthropic_response: AnthropicResponse = response.json()?;

        let content = anthropic_response
            .content
            .first()
            .map(|c| c.text.clone())
            .ok_or_else(|| AikeyError::Provider("No response from Anthropic".to_string()))?;

        let usage = anthropic_response.usage.map(|u| TokenUsage {
            prompt_tokens: u.input_tokens,
            completion_tokens: u.output_tokens,
            total_tokens: u.input_tokens + u.output_tokens,
        });

        Ok(ChatResponse {
            content,
            model: anthropic_response.model,
            provider: "anthropic".to_string(),
            usage,
        })
    }
}

impl ProviderAdapter for AnthropicAdapter {
    fn chat(
        &self,
        api_key: &Zeroizing<String>,
        model: &str,
        messages: Vec<ChatMessage>,
    ) -> Result<ChatResponse, AikeyError> {
        self.make_request_with_retry(api_key.as_str(), model, &messages)
    }
}
