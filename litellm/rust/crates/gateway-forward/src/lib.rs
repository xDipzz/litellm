mod client;
mod connections;
mod connector;
mod error;
mod forward;
mod gate;
mod input;
mod rewrite;
mod server;
mod settings;
mod websocket;

use std::{convert::Infallible, time::Duration};

use axum::{extract::Request, response::Response};
use tokio::net::TcpListener;
use tower::Service;

use connections::Connections;
pub use error::Error;
pub(crate) use error::Rejection;
pub use forward::Forward;
pub use gate::Gated;
pub use input::input_closed;
pub use rewrite::{PEER_HEADER, VERDICT_HEADER};
pub use settings::{Settings, Upstream};

/// Binds the public listener and serves the app `app` builds until `shutdown` resolves, then
/// drains for `settings.shutdown_drain`. `app` gets the `Forward` to put its native routes in
/// front of.
pub async fn run<S>(
    settings: Settings,
    app: impl FnOnce(Forward) -> Gated<S>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), Error>
where
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    let listener = TcpListener::bind((settings.host.as_str(), settings.port)).await?;
    tracing::info!(address = %listener.local_addr()?, "forwarding gateway listening");
    serve(
        listener,
        settings.upstream,
        settings.upstream_keepalive,
        settings.shutdown_drain,
        app,
        shutdown,
    )
    .await;
    Ok(())
}

/// Serves the app `app` builds on `listener` until `shutdown` resolves, then lets open requests
/// and WebSockets finish for up to `drain` before closing whatever is left. Python shuts down
/// alongside and ends long streams itself, so `drain` only backstops a Python that never does.
/// `app` gets the `Forward` that relays to `upstream`, and idle client connections are closed
/// after `upstream_keepalive`, as uvicorn did.
pub async fn serve<S>(
    listener: TcpListener,
    upstream: Upstream,
    upstream_keepalive: Duration,
    drain: Duration,
    app: impl FnOnce(Forward) -> Gated<S>,
    shutdown: impl Future<Output = ()>,
) where
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    let connections = Connections::default();
    let python = Forward::new(&upstream, upstream_keepalive, connections.clone());
    server::serve(
        app(python).0,
        listener,
        upstream_keepalive,
        connections,
        shutdown,
        drain,
    )
    .await;
}
