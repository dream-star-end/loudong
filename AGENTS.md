## Cursor Cloud specific instructions

### Project overview

VulnHunter is an LLM-driven Web Application Security Testing AI Agent built with Python 3.12, FastAPI, PostgreSQL, Redis, and MinIO. The architecture follows the PRD in `VulnHunter_PRD_v2.docx`: an Orchestrator Agent dispatches work to 6 specialized sub-agents (Recon, Crawl, AuthZ, Input, BizLogic, Evidence).

### Infrastructure services

PostgreSQL, Redis, and MinIO run via Docker Compose. Before starting the dev server, ensure Docker is running and start the containers:

```
sudo dockerd > /dev/null 2>&1 &   # if Docker daemon isn't already running
sudo docker compose up -d
```

### Key commands

| Action | Command |
|--------|---------|
| Install deps | `pip install -e ".[dev]" && pip install aiosqlite` |
| Lint | `ruff check .` |
| Auto-fix lint | `ruff check . --fix` |
| Tests | `pytest tests/ -v` |
| Dev server | `uvicorn vulnhunter.main:app --host 0.0.0.0 --port 8000 --reload` |
| Swagger docs | http://localhost:8000/docs |

### Gotchas

- `~/.local/bin` must be on `PATH` for `ruff`, `pytest`, `uvicorn` to be found. The setup adds it to `~/.bashrc`.
- API tests use SQLite via `aiosqlite` (not the real PostgreSQL), so `aiosqlite` must be installed alongside the dev extras.
- The FastAPI app gracefully handles a missing database on startup (logs a warning), so the dev server can start even without Docker containers, but persistence and the health check's `postgres`/`redis` fields will show "unavailable".
