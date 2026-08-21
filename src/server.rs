//! HTTP API + a paste-bytecode console for Unweave.
//!   GET  /            the console UI
//!   GET  /health      "ok"
//!   POST /disasm {"hex":"..."}  -> full analysis JSON

use anyhow::Result;
use axum::{
    extract::DefaultBodyLimit,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct Req {
    hex: String,
}

pub fn serve(port: u16) -> Result<()> {
    let app = Router::new()
        .route("/", get(|| async { Html(include_str!("ui.html")) }))
        .route("/health", get(|| async { "ok" }))
        .route("/disasm", post(disasm))
        // Explicit 4MB body cap so an oversized payload is rejected at the edge
        // (413) before it reaches parse_hex. Not left to axum's implicit default.
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024));
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
        eprintln!("unweave console on http://127.0.0.1:{port}  (UI at /, POST /disasm)");
        axum::serve(listener, app).await?;
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

async fn disasm(Json(req): Json<Req>) -> impl IntoResponse {
    let code = match crate::parse_hex(&req.hex) {
        Ok(code) => code,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    };
    // Analysis is CPU-bound: run it off the async pool and cap it so one request
    // cannot starve the server.
    let work = tokio::task::spawn_blocking(move || crate::disasm_json(&code));
    match tokio::time::timeout(std::time::Duration::from_secs(3), work).await {
        Ok(Ok(v)) => (StatusCode::OK, Json(v)),
        Ok(Err(_)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "analysis failed" })),
        ),
        Err(_) => (
            StatusCode::GATEWAY_TIMEOUT,
            Json(json!({ "error": "analysis timed out" })),
        ),
    }
}
