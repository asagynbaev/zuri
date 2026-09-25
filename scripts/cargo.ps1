# cargo in Docker, for machines without the MSVC linker.
# ./scripts/cargo.ps1 run -- demo
docker run --rm `
  -v "${PSScriptRoot}/..:/app" `
  -v zuri-cargo:/usr/local/cargo/registry `
  -v zuri-target:/app/target `
  -e ZURI_RPC_URL `
  -w /app rust:1 cargo @args
