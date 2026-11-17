use std::convert::Infallible;

use axum::{
    extract::FromRequestParts,
    http::{HeaderMap, request::Parts},
};

const ANTHROPIC_MESSAGES_ROUTES: [&str; 4] = [
    "/v1/messages",
    "/v1/messages/count_tokens",
    "/claude_code_gateway/v1/messages",
    "/claude_code_gateway/v1/messages/count_tokens",
];
const ANTHROPIC_PASS_THROUGH_PREFIX: &str = "/anthropic/";
const ANTHROPIC_SHAPED_MODEL_LIST_ROUTES: [&str; 3] =
    ["/v1/models", "/models", "/claude_code_gateway/v1/models"];

/// The error envelope a route answers with, `uses_anthropic_error_envelope` in Python.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Surface {
    Anthropic { request_id: Option<String> },
    OpenAi,
}

impl<S: Send + Sync> FromRequestParts<S> for Surface {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Infallible> {
        Ok(Self::of(parts.uri.path(), &parts.headers))
    }
}

impl Surface {
    pub fn of(path: &str, headers: &HeaderMap) -> Self {
        let anthropic = ANTHROPIC_MESSAGES_ROUTES.contains(&path)
            || path.starts_with(ANTHROPIC_PASS_THROUGH_PREFIX)
            || (ANTHROPIC_SHAPED_MODEL_LIST_ROUTES.contains(&path)
                && headers.contains_key("anthropic-version"));
        if !anthropic {
            return Self::OpenAi;
        }
        Self::Anthropic {
            request_id: headers
                .get("x-request-id")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use rstest::rstest;

    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(name, value)| {
                (
                    axum::http::HeaderName::from_static(name),
                    HeaderValue::from_static(value),
                )
            })
            .collect()
    }

    #[rstest]
    #[case::messages("/v1/messages", &[])]
    #[case::count_tokens("/v1/messages/count_tokens", &[])]
    #[case::claude_code("/claude_code_gateway/v1/messages", &[])]
    #[case::pass_through("/anthropic/v1/messages", &[])]
    #[case::model_list_with_version("/v1/models", &[("anthropic-version", "2023-06-01")])]
    fn anthropic_routes_use_the_anthropic_envelope(
        #[case] path: &str,
        #[case] pairs: &[(&'static str, &'static str)],
    ) {
        assert_eq!(
            Surface::of(path, &headers(pairs)),
            Surface::Anthropic { request_id: None }
        );
    }

    #[rstest]
    #[case::chat("/v1/chat/completions", &[("anthropic-version", "2023-06-01")])]
    #[case::model_list_without_version("/v1/models", &[])]
    #[case::messages_subpath("/v1/messages/batches", &[])]
    #[case::pass_through_without_slash("/anthropic", &[])]
    fn other_routes_use_the_openai_envelope(
        #[case] path: &str,
        #[case] pairs: &[(&'static str, &'static str)],
    ) {
        assert_eq!(Surface::of(path, &headers(pairs)), Surface::OpenAi);
    }

    #[rstest]
    fn the_anthropic_surface_carries_the_request_id() {
        assert_eq!(
            Surface::of("/v1/messages", &headers(&[("x-request-id", "req_1")])),
            Surface::Anthropic {
                request_id: Some("req_1".into())
            }
        );
    }
}
