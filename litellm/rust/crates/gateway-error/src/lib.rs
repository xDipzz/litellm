//! Error bodies whose envelope follows the request route, as the proxy's
//! `litellm/proxy/common_utils/anthropic_error_payload.py` picks them.
//!
//! A [`RouteError`] answers with its OpenAI body and carries its [`AnthropicError`] in the
//! response extensions. The gateway's outermost layer extracts the [`Surface`] to learn which
//! envelope the route uses and swaps in the Anthropic body there, because `IntoResponse` cannot see
//! the request.

mod anthropic;
mod route_error;
mod surface;

pub use anthropic::{AnthropicError, AnthropicErrorType};
pub use route_error::RouteError;
pub use surface::Surface;
