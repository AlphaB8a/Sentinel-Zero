# Ironclad TUI Architecture

- Async kernel (tokio) multiplexes: input, physics, IPC
- Physics (sysinfo) runs off the async runtime (spawn_blocking)
- Presentation (ratatui) is pure rendering
- Plugins speak NDJSON over Unix sockets
