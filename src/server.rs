//! HTTP API + a paste-bytecode console for Unweave.
//!   GET  /            the console UI
//!   GET  /health      "ok"
//!   POST /disasm {"hex":"..."}  -> full analysis JSON

use anyhow::Result;
use axum::{
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
        .route("/disasm", post(disasm));
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
    match crate::parse_hex(&req.hex) {
        Ok(code) => (StatusCode::OK, Json(crate::disasm_json(&code))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}
