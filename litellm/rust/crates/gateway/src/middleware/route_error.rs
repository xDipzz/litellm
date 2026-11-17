use axum::{body::Body, extract::Request, http::header, middleware::Next, response::Response};
use litellm_gateway_error::{AnthropicError, Surface};

/// Swaps a `RouteError`'s OpenAI body for its Anthropic one on routes that answer in that
/// envelope, keeping the status and headers every inner layer set.
pub(super) async fn render(surface: Surface, request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    let Surface::Anthropic { request_id } = surface else {
        return response;
    };
    let Some(body) = response
        .extensions()
        .get::<AnthropicError>()
        .map(|error| error.body(request_id.as_deref()))
    else {
        return response;
    };
    let (mut parts, _) = response.into_parts();
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(body.to_string()))
}

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        http::{HeaderName, HeaderValue, StatusCode},
        response::IntoResponse,
        routing::post,
    };
    use litellm_gateway_error::RouteError;
    use rstest::rstest;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::*;

    fn app() -> Router {
        let fail = || async {
            RouteError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "too big",
                json!({"error": "too big"}),
            )
            .with_header(
                HeaderName::from_static("retry-after"),
                HeaderValue::from_static("1"),
            )
        };
        Router::new()
            .route("/v1/messages", post(fail))
            .route("/v1/chat/completions", post(fail))
            .route(
                "/v1/messages/count_tokens",
                post(|| async { "ok".into_response() }),
            )
            .layer(axum::middleware::from_fn(render))
    }

    async fn send(path: &str, request_id: Option<&str>) -> (StatusCode, Option<String>, String) {
        let request = request_id
            .into_iter()
            .fold(Request::post(path), |request, id| {
                request.header("x-request-id", id)
            })
            .body(Body::empty())
            .unwrap();
        let response = app().oneshot(request).await.unwrap();
        let status = response.status();
        let retry_after = response
            .headers()
            .get("retry-after")
            .map(|value| value.to_str().unwrap().to_owned());
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        (
            status,
            retry_after,
            String::from_utf8(body.to_vec()).unwrap(),
        )
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
    #[tokio::test]
    async fn an_anthropic_route_answers_in_the_anthropic_envelope(
        #[case] request_id: Option<&str>,
        #[case] expected: Value,
    ) {
        let (status, retry_after, body) = send("/v1/messages", request_id).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(retry_after.as_deref(), Some("1"));
        assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), expected);
    }

    #[rstest]
    #[case::openai_route("/v1/chat/completions", r#"{"error":"too big"}"#)]
    #[case::not_a_route_error("/v1/messages/count_tokens", "ok")]
    #[tokio::test]
    async fn other_responses_are_untouched(#[case] path: &str, #[case] expected: &str) {
        assert_eq!(send(path, Some("req_1")).await.2, expected);
    }
}
