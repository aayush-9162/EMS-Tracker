//! The admin console, compiled into the binary so deployment is one file.

use axum::http::{header, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

const INDEX: &str = include_str!("../ui/index.html");
const APP_JS: &str = include_str!("../ui/app.js");
const STYLE: &str = include_str!("../ui/style.css");
const ICON: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#1f2a44"/><circle cx="16" cy="16" r="7" fill="#3ecf8e"/></svg>"##;

fn asset(body: &'static str, content_type: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            // Always revalidate: a new server build must never be paired with a stale script.
            (header::CACHE_CONTROL, HeaderValue::from_static("no-cache")),
        ],
        body,
    )
        .into_response()
}

pub async fn serve(uri: Uri) -> Response {
    match uri.path() {
        "/" | "/index.html" => asset(INDEX, "text/html; charset=utf-8"),
        "/app.js" => asset(APP_JS, "text/javascript; charset=utf-8"),
        "/style.css" => asset(STYLE, "text/css; charset=utf-8"),
        "/favicon.svg" | "/favicon.ico" => asset(ICON, "image/svg+xml"),
        _ => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}
