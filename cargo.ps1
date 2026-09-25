# Runs cargo inside the official rust image. This machine has no MSVC linker
# (Visual Studio is installed without the C++ workload), so native Windows
# builds fail at link time. Usage: ./cargo.ps1 run -- run
docker run --rm `
  -v "${PSScriptRoot}:/app" `
  -v zuri-cargo:/usr/local/cargo/registry `
  -v zuri-target:/app/target `
  -e ZURI_RPC_URL `
  -w /app rust:1 cargo @args
