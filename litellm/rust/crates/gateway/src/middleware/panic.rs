use std::any::Any;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use litellm_gateway_error::RouteError;
use serde_json::json;
use tower_http::catch_panic::CatchPanicLayer;

const MESSAGE: &str = "Internal server error";

type Panic = Box<dyn Any + Send + 'static>;

/// `otel_unhandled_exception_handler`: a handler that panics answers what Python answers for an
/// exception nothing caught.
pub(super) fn layer() -> CatchPanicLayer<fn(Panic) -> Response> {
    CatchPanicLayer::custom(internal_server_error as fn(Panic) -> Response)
}

fn internal_server_error(panic: Panic) -> Response {
    let detail = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied());
    tracing::error!(panic = detail, "a request handler panicked");
    RouteError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        MESSAGE,
        json!({"error": {"message": MESSAGE, "type": "internal_server_error"}}),
    )
    .into_response()
}

#[cfg(test)]
mod tests {
    use axum::{Router, body::Body, extract::Request, routing::post};
    use litellm_gateway_error::{AnthropicError, AnthropicErrorType};
    use rstest::rstest;
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;

    async fn panics() -> &'static str {
        panic!("handler bug")
    }

    #[rstest]
    #[tokio::test]
    async fn a_panicking_handler_answers_an_internal_server_error() {
        let app = Router::new()
            .route("/v1/messages", post(panics))
            .layer(layer());
        let response = app
            .oneshot(Request::post("/v1/messages").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response.extensions().get::<AnthropicError>(),
            Some(&AnthropicError {
                error_type: AnthropicErrorType::Api,
                message: MESSAGE.into(),
            })
        );
        let body = axum::body::to_bytes(Body::new(response.into_body()), 1024)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"error": {"message": "Internal server error", "type": "internal_server_error"}})
        );
    }
}
