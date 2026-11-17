use std::{convert::Infallible, fmt::Display};

use axum::{
    extract::{Request, State},
    http::{HeaderName, HeaderValue},
    middleware::{Next, from_fn_with_state},
    response::Response,
};
use tower::{Layer, Service, ServiceExt};
use tower_http::set_header::SetResponseHeader;

use crate::{Forward, rewrite::VERDICT_HEADER};

/// What the gateway serves: a native app in front of Python from [`Forward::behind`], or the
/// `Forward` alone. Only [`run`](crate::run) and [`serve`](crate::serve) take it, since a layer
/// around it would also wrap the requests Python answers.
pub struct Gated<S>(pub(crate) S);

impl From<Forward> for Gated<Forward> {
    fn from(python: Forward) -> Self {
        Self(python)
    }
}

/// Runs `screen` on each request, then sends it to `native` if it passed, otherwise to Python as
/// `screen` handed it back.
async fn screened<A, Screened, Why>(
    State((screen, python)): State<(A, Forward)>,
    request: Request,
    native: Next,
) -> Result<Response, Infallible>
where
    A: Fn(Request) -> Screened,
    Screened: Future<Output = Result<Request, (Box<Request>, Why)>>,
    Why: Display + Into<&'static str>,
{
    match screen(request).await {
        Ok(request) => Ok(native.run(request).await),
        Err((request, why)) => {
            tracing::debug!(%why, "python answers a request the native app handed back");
            python.because(why.into()).oneshot(*request).await
        }
    }
}

impl Forward {
    /// `native` in front of Python. `screen` sees every request before `native` does, and either
    /// lets it in or hands it back as the client sent it, with why. Python answers every request
    /// handed back, and none of them pass through `native` or a layer it has. `screen` is the only
    /// thing that sends a request to Python, so a request it passes gets `native`'s answer even
    /// when that is a 404. Each response names who answered it in [`VERDICT_HEADER`].
    pub fn behind<S, A, Screened, Why>(
        self,
        native: S,
        screen: A,
    ) -> Gated<
        impl Service<Request, Response = Response, Error = Infallible, Future: Send + 'static>
        + Clone
        + Send
        + 'static,
    >
    where
        S: Service<Request, Response = Response, Error = Infallible>
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
        A: Fn(Request) -> Screened + Clone + Send + Sync + 'static,
        Screened: Future<Output = Result<Request, (Box<Request>, Why)>> + Send + 'static,
        Why: Display + Into<&'static str> + Send + 'static,
    {
        let native = SetResponseHeader::overriding(
            native,
            HeaderName::from_static(VERDICT_HEADER),
            HeaderValue::from_static("native"),
        );
        Gated(from_fn_with_state((screen, self), screened::<A, Screened, Why>).layer(native))
    }

    /// Python's answer naming Python and `why` in [`VERDICT_HEADER`], which replaces any copy the
    /// answer carried.
    fn because(self, why: &str) -> SetResponseHeader<Self, HeaderValue> {
        SetResponseHeader::overriding(
            self,
            HeaderName::from_static(VERDICT_HEADER),
            python_verdict(why),
        )
    }
}

fn python_verdict(why: &str) -> HeaderValue {
    const PYTHON: HeaderValue = HeaderValue::from_static("python");
    HeaderValue::try_from(format!("python; reason={why}")).unwrap_or(PYTHON)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::code("body", "python; reason=body")]
    #[case::unprintable_code("a\nb", "python")]
    fn a_python_verdict_names_python_and_why(#[case] why: &str, #[case] header: &str) {
        assert_eq!(python_verdict(why), header);
    }
}
