use pillar_api::{router, StaticApp};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = std::env::args()
        .nth(1)
        .map(|value| value.parse::<u16>())
        .transpose()?
        .unwrap_or(39879);
    // Authenticated routes stay closed unless the operator supplies tokens.
    let auth_tokens = std::env::var("PILLAR_API_AUTH_TOKENS")
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|token| !token.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let app = router(
        StaticApp::observed_mainnet().with_auth_tokens(auth_tokens),
        "static-fixture",
    );
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("static Pillar fixture server listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
