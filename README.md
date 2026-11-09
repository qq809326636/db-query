English | [简体中文](README.zh.md)

# DB Query MCP

A read-only database query MCP server built in Rust: configure multiple databases and only allow read-only queries (SQL SELECT statements and Redis read-only commands).

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Configuration](#configuration)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Development Guide](#development-guide)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Introduction

DB Query MCP is a database MCP (Model Context Protocol) server written in Rust that lets AI clients query databases safely. Via `config.toml` you can connect to multiple databases (PostgreSQL, MySQL, SQLite, Redis) and select the query target by name. Every query goes through syntax validation first — only SELECT-style statements are allowed, while any statement that modifies data or structure is rejected, preventing AI from accidentally mutating your data. It fits scenarios that need AI-assisted data analysis while guaranteeing read-only safety.

## Features

- 🔌 Multiple databases: PostgreSQL, MySQL, SQLite, and Redis (delivered)
- ⚙️ Multi-instance configuration: configure multiple database connections via `config.toml` and switch query targets by name
- 🛡️ Read-only safety: SQL passes syntax validation first; only SELECT-style statements are allowed, everything else is rejected
- 🧩 Modular layering: syntax validation, database adapters, and the MCP server live in separate crates for easy extension
- 🦀 Built in Rust: implemented in Rust and served as an MCP server for clients

## Getting Started

### Prerequisites

- Rust stable toolchain (edition 2024, a fairly recent stable)
- A reachable target database (e.g. PostgreSQL, MySQL) or a SQLite database file

### Installation

```bash
git clone https://github.com/qq809326636/db-query.git
cd db-query
cargo build
```

### Running

```bash
cargo run -p cli -- mcp --transport streamable  # binary name: excapp-db
```

### Docker Deployment

```bash
# Build the image (version defaults to 1.0.0, override with --version; produces
# excapp-db:1.0.0, excapp-db:1.0.0-g<git-short-sha> (inside a git repo) and excapp-db:latest)
./docker-build.sh

# Prepare the config before deploying
cp config.template.toml config.toml
#   - Edit the database connections in config.toml;
#   - Change addr under [app.mcp.streamable] to "0.0.0.0" (otherwise it is
#     reachable only inside the container), keep port at 8000; externally
#     everything goes through the host's 16000 mapping;
#   - The host's config.toml must be readable by the in-container app user
#     (uid 1000), e.g. chmod 644.

docker compose up -d       # the image must be built and tagged by docker-build.sh first
docker compose logs -f     # follow logs
docker compose down        # stop (SIGTERM graceful shutdown)
```

Version upgrades: change the `image` in `docker-compose.yaml` to the new version tag and run `up -d` again.

## Usage

The service runs as an MCP server: register it in any MCP-capable client, then query the configured databases. Only statements that pass syntax validation are executed:

```sql
-- Allowed: query statements
SELECT count(*) FROM orders WHERE created_at >= current_date;

-- Rejected: any statement that modifies data or structure
-- UPDATE orders SET status = 'paid'
```

### MCP Tools

The service provides seven tools, addressing query targets by `uid`; chaining them in order is recommended:

| Tool | Purpose | Key inputs |
|------|---------|------------|
| `list-connection` | List configured connections (local read, no database access) | — |
| `list-database` | List databases visible to a connection | `uid` |
| `list-schema` | List schemas in a database (system schemas excluded) | `uid` + `database` |
| `list-table` | List tables and views in a schema (with partition semantics) | `uid` + `database` + `schema` (optional) |
| `describe-table` | Table structure, DDL and comments | `uid` + `database` + `schema` (optional) + `table` |
| `execute-sql` | Validate and execute read-only SQL (row / byte / timeout triple protection) | `uid` + `database` + `schema` (optional) + `sql` |

Typical flow: `list-connection` to find the uid → `list-database` to pick a database → `list-schema` to locate the schema → `list-table` to find tables → `describe-table` to inspect the structure → `execute-sql` to query data. There is also a guide prompt plus seven tool-matching usage prompts (the `lang` parameter selects zh / en).

## Configuration

Configure multiple databases via `config.toml`; the server selects the query target by `name`. See [config.template.toml](config.template.toml):

```toml
# PostgreSQL / MySQL: network connection form (see config.template.toml for the extra_opts key whitelist)
[[databases]]
uid = "primary"          # unique connection identifier; duplicates are rejected
name = "primary"         # name, for users to recognize
description = "..."      # brief description of the database scope, etc.
type = "postgres"        # database type (postgres / mysql / sqlite)
dialect = "postgres"     # SQL dialect (postgres / mysql / sqlite)
username = "user"
password = "password"
host = "localhost"
port = 5432
db = "app"
extra_opts = ""          # extra connection options, optional

# SQLite: file-based form (connection-layer read-only hard constraint mode=ro, never creates files)
[[databases]]
uid = "sqlite-file"
name = "sqlite-file"
description = "..."
type = "sqlite"
dialect = "sqlite"
username = ""            # SQLite ignores username / password / host / port
password = ""
host = ""
port = 0
db = "/path/to/app.db"   # the db field carries the file path
extra_opts = ""
```

Beyond connection settings, the optional `[validator.sql]` policy section can tighten the allowed statement kinds (`whitelist.kinds`, tighten-only) and append to the function blacklist (`<dialect>.blacklist.function`, append-only); omitting it entirely means the built-in policy. See [config.template.toml](config.template.toml) for the full key reference.

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Rust |
| Frontend | None |
| Client | None |
| UI library | None |

## Project Structure

A multi-crate workspace layered by responsibility:

```text
.
├── crates/
│   ├── cli/               # CLI tool (binary name excapp-db): conf / mcp / sql
│   ├── core/              # shared infrastructure: config loading, state storage (AppState)
│   ├── sql-mcp/           # MCP server library (lib), seven tools + stdio and Streamable HTTP transports
│   ├── sql-validator/     # SQL syntax validation library, only read-only queries pass
│   └── sql-executor/      # database connection and query execution library, read-only query execution per database
├── deps/                  # test-dependency database orchestration (docker compose: PG18 / MySQL8 / Redis8)
├── benchmark/             # non-functional benchmark suite (security scenario)
├── docker-build.sh        # image build script (a convenience wrapper around the Dockerfile)
├── docker-compose.yaml    # deployment orchestration (host 16000 -> container 8000)
├── .cSpell.json           # spell-check ignore configuration
├── .gitignore             # Git ignore rules
├── config.template.toml   # configuration file template
├── LICENSE                # MIT License
├── README.md              # project documentation (English)
└── README.zh.md           # project documentation (Chinese)
```

## Development Guide

```bash
# Run tests
cargo test

# Lint and format
cargo fmt
cargo clippy

# Build
cargo build

# Release build (LTO + stripped symbols, for deployment artifacts)
cargo build --release

# Fast release build (low optimization, no LTO, for verifying release behavior during development)
cargo build --profile release-fast

# Integration test dependencies: start the three test containers (PG18 :10001 / MySQL8 :10002 / Redis8 :10003)
docker compose -f deps/docker-compose.yaml up -d
```

Security baseline benchmarks (attack payload library / concurrent resource protection / credential-leak audit, see [benchmark/](benchmark/)):

```bash
cd benchmark/security/scripts
python3 run.py                # all active cases (dual target databases)
```

## Roadmap

- [x] Support PostgreSQL with read-only queries and SQL syntax validation (first milestone)
- [x] Support MySQL queries (v0.2.0)
- [x] Support SQLite queries (v0.2.0)
- [x] Support read-only Redis command queries (execute-redis + metadata mapping)

For more ideas, see [Issues](https://github.com/qq809326636/db-query/issues).

## Contributing

Issues and Pull Requests are welcome!

1. Fork this repository
2. Create a branch: `git checkout -b feat/your-feature`
3. Commit your changes: `git commit -m "feat: add your feature"`
4. Push the branch and open a Pull Request

## License

This project is open-sourced under the [MIT License](LICENSE).



