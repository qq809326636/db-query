English | [简体中文](README.zh.md)

# DB Query MCP

A read-only database query MCP server built in Rust: configure multiple databases and only allow SELECT statements that pass syntax validation.

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

- 🔌 Multiple databases: PostgreSQL, MySQL, SQLite, and Redis, with PostgreSQL delivered first
- ⚙️ Multi-instance configuration: configure multiple database connections via `config.toml` and switch query targets by name
- 🛡️ Read-only safety: SQL passes syntax validation first; only SELECT-style statements are allowed, everything else is rejected
- 🧩 Modular layering: syntax validation, database adapters, and the MCP server live in separate crates for easy extension
- 🦀 Built in Rust: implemented in Rust and served as an MCP server for clients

## Getting Started

### Prerequisites

- Rust stable toolchain
- A reachable target database (e.g. PostgreSQL)

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

## Usage

The service runs as an MCP server: register it in any MCP-capable client, then query the configured databases. Only statements that pass syntax validation are executed:

```sql
-- Allowed: query statements
SELECT count(*) FROM orders WHERE created_at >= current_date;

-- Rejected: any statement that modifies data or structure
-- UPDATE orders SET status = 'paid'
```

## Configuration

Configure multiple databases via `config.toml`; the server selects the query target by `name`. See [config.template.toml](config.template.toml):

```toml
[[databases]]
uid = "primary"          # unique connection identifier; duplicates are rejected
name = "primary"         # name, for users to recognize
description = "..."      # brief description of the database scope, etc.
type = "postgres"        # database type
dialect = "postgres"     # SQL dialect
username = "user"
password = "password"
host = "localhost"
port = 5432
db = "app"
extra_opts = ""          # extra connection options, optional
```

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
│   ├── sql-mcp/           # MCP server library (lib), six tools + stdio and Streamable HTTP transports
│   ├── sql-validator/     # SQL syntax validation library, only read-only queries pass
│   └── sql-executor/      # database connection and query execution library, read-only query execution per database
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
```

## Roadmap

- [ ] Support PostgreSQL with read-only queries and SQL syntax validation (first milestone)
- [ ] Support MySQL queries
- [ ] Support SQLite queries
- [ ] Support Redis queries

For more ideas, see [Issues](https://github.com/qq809326636/db-query/issues).

## Contributing

Issues and Pull Requests are welcome!

1. Fork this repository
2. Create a branch: `git checkout -b feat/your-feature`
3. Commit your changes: `git commit -m "feat: add your feature"`
4. Push the branch and open a Pull Request

## License

This project is open-sourced under the [MIT License](LICENSE).



