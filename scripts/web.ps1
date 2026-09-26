# Demo web app in Docker: http://localhost:8787
docker run --rm --name zuri-web `
  -v "${PSScriptRoot}/..:/app" `
  -v zuri-cargo:/usr/local/cargo/registry `
  -v zuri-target:/app/target `
  -e ZURI_RPC_URL `
  -p 8787:8787 `
  -w /app rust:1 cargo run --release --bin zuri-web
