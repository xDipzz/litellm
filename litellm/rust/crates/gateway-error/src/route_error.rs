use axum::{
    Extension, Json,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use crate::{AnthropicError, AnthropicErrorType};

/// An error answered in the envelope of the route it failed on: `route_error_content` in Python.
#[derive(Clone, Debug)]
pub struct RouteError {
    status: StatusCode,
    anthropic: AnthropicError,
    openai: Value,
    headers: HeaderMap,
}

impl RouteError {
    pub fn new(status: StatusCode, message: impl Into<String>, openai: Value) -> Self {
        Self {
            status,
            anthropic: AnthropicError {
                error_type: AnthropicErrorType::for_status(status),
                message: message.into(),
            },
            openai,
            headers: HeaderMap::new(),
        }
    }

    /// The OpenAI body is `ProxyException.to_dict()`, whose `code` is the status as text.
    pub fn proxy_exception(
        status: StatusCode,
        message: impl Into<String>,
        openai_type: &str,
    ) -> Self {
        let message = message.into();
        let openai = json!({"error": {
            "message": message,
            "type": openai_type,
            "param": null,
            "code": status.as_u16().to_string(),
        }});
        Self::new(status, message, openai)
    }

    pub fn with_anthropic_type(self, error_type: AnthropicErrorType) -> Self {
        Self {
            anthropic: AnthropicError {
                error_type,
                ..self.anthropic
            },
            ..self
        }
    }

    pub fn with_header(self, name: HeaderName, value: HeaderValue) -> Self {
        let mut headers = self.headers;
        headers.append(name, value);
        Self { headers, ..self }
    }
}

impl IntoResponse for RouteError {
    fn into_response(self) -> Response {
        (
            self.status,
            self.headers,
            Extension(self.anthropic),
            Json(self.openai),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use rstest::rstest;

    use super::*;

    async fn json_body(response: Response) -> Value {
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap()
    }

    #[rstest]
    #[tokio::test]
    async fn answers_with_the_openai_body_and_carries_the_anthropic_error() {
        let response = RouteError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too big",
            json!({"error": "too big"}),
        )
        .with_header(
            HeaderName::from_static("retry-after"),
            HeaderValue::from_static("1"),
        )
        .into_response();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(response.headers()["retry-after"], "1");
        assert_eq!(
            response.extensions().get::<AnthropicError>(),
            Some(&AnthropicError {
                error_type: AnthropicErrorType::RequestTooLarge,
                message: "too big".into(),
            })
        );
        assert_eq!(json_body(response).await, json!({"error": "too big"}));
    }

    #[rstest]
    #[tokio::test]
    async fn a_proxy_exception_body_has_the_status_as_text() {
        let response = RouteError::proxy_exception(
            StatusCode::SERVICE_UNAVAILABLE,
            "busy",
            "overloaded_error",
        )
        .with_anthropic_type(AnthropicErrorType::Overloaded)
        .into_response();

        assert_eq!(
            response
                .extensions()
                .get::<AnthropicError>()
                .unwrap()
                .error_type,
            AnthropicErrorType::Overloaded
        );
        assert_eq!(
            json_body(response).await,
            json!({"error": {"message": "busy", "type": "overloaded_error", "param": null, "code": "503"}})
        );
    }
}
