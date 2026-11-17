use axum::extract::Request;

/// Why the gateway does not serve a request the way the Python proxy would.
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
pub enum Refused {
    #[error("the gateway serves nothing natively yet")]
    #[strum(serialize = "configuration")]
    Configuration,
}

/// Passes the requests the gateway serves the way the Python proxy would, and hands every other
/// one back as the client sent it, with why.
// TODO(#52003): screen by the allowlist instead of refusing every request
pub async fn screen(request: Request) -> Result<Request, (Box<Request>, Refused)> {
    Err((Box::new(request), Refused::Configuration))
}
