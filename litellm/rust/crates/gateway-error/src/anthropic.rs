use axum::http::StatusCode;
use serde_json::{Map, Value, json};

#[derive(Clone, Copy, Debug, PartialEq, Eq, strum::IntoStaticStr)]
pub enum AnthropicErrorType {
    #[strum(serialize = "invalid_request_error")]
    InvalidRequest,
    #[strum(serialize = "authentication_error")]
    Authentication,
    #[strum(serialize = "billing_error")]
    Billing,
    #[strum(serialize = "permission_error")]
    Permission,
    #[strum(serialize = "not_found_error")]
    NotFound,
    #[strum(serialize = "conflict_error")]
    Conflict,
    #[strum(serialize = "request_too_large")]
    RequestTooLarge,
    #[strum(serialize = "rate_limit_error")]
    RateLimit,
    #[strum(serialize = "api_error")]
    Api,
    #[strum(serialize = "timeout_error")]
    Timeout,
    #[strum(serialize = "overloaded_error")]
    Overloaded,
}

impl AnthropicErrorType {
    /// `proxy_error_type`: Python's `ANTHROPIC_ERROR_TYPE_MAP` plus the proxy's own statuses.
    pub fn for_status(status: StatusCode) -> Self {
        match status.as_u16() {
            401 => Self::Authentication,
            402 => Self::Billing,
            403 => Self::Permission,
            404 => Self::NotFound,
            409 => Self::Conflict,
            413 => Self::RequestTooLarge,
            429 => Self::RateLimit,
            504 => Self::Timeout,
            529 => Self::Overloaded,
            408 => Self::Api,
            400..500 => Self::InvalidRequest,
            _ => Self::Api,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnthropicError {
    pub error_type: AnthropicErrorType,
    pub message: String,
}

impl AnthropicError {
    pub fn body(&self, request_id: Option<&str>) -> Value {
        let error_type: &'static str = self.error_type.into();
        let envelope = json!({
            "type": "error",
            "error": {"type": error_type, "message": self.message},
        });
        match (envelope, request_id) {
            (Value::Object(envelope), Some(request_id)) => Value::Object(
                envelope
                    .into_iter()
                    .chain([("request_id".to_owned(), Value::from(request_id))])
                    .collect::<Map<_, _>>(),
            ),
            (envelope, _) => envelope,
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::bad_request(400, AnthropicErrorType::InvalidRequest)]
    #[case::unauthorized(401, AnthropicErrorType::Authentication)]
    #[case::payment_required(402, AnthropicErrorType::Billing)]
    #[case::forbidden(403, AnthropicErrorType::Permission)]
    #[case::not_found(404, AnthropicErrorType::NotFound)]
    #[case::request_timeout(408, AnthropicErrorType::Api)]
    #[case::conflict(409, AnthropicErrorType::Conflict)]
    #[case::too_large(413, AnthropicErrorType::RequestTooLarge)]
    #[case::unsupported_media(415, AnthropicErrorType::InvalidRequest)]
    #[case::rate_limited(429, AnthropicErrorType::RateLimit)]
    #[case::internal(500, AnthropicErrorType::Api)]
    #[case::unavailable(503, AnthropicErrorType::Api)]
    #[case::gateway_timeout(504, AnthropicErrorType::Timeout)]
    #[case::overloaded(529, AnthropicErrorType::Overloaded)]
    fn the_type_follows_proxy_error_type(
        #[case] status: u16,
        #[case] expected: AnthropicErrorType,
    ) {
        assert_eq!(
            AnthropicErrorType::for_status(StatusCode::from_u16(status).unwrap()),
            expected
        );
    }

    #[rstest]
    #[case::without_request_id(
        None,
        json!({"type": "error", "error": {"type": "request_too_large", "message": "too big"}})
    )]
    #[case::with_request_id(
        Some("req_1"),
        json!({"type": "error", "error": {"type": "request_too_large", "message": "too big"}, "request_id": "req_1"})
    )]
    #[case::empty_request_id_is_kept(
        Some(""),
        json!({"type": "error", "error": {"type": "request_too_large", "message": "too big"}, "request_id": ""})
    )]
    fn the_body_is_the_anthropic_envelope(
        #[case] request_id: Option<&str>,
        #[case] expected: Value,
    ) {
        let error = AnthropicError {
            error_type: AnthropicErrorType::RequestTooLarge,
            message: "too big".into(),
        };
        assert_eq!(error.body(request_id), expected);
    }
}
