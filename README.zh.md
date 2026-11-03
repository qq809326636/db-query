[English](README.md) | 简体中文

# 数据查询 MCP

Rust 实现的只读数据库查询 MCP 服务器：支持配置多个数据库，仅放行通过语法校验的 SELECT 查询语句。

## 目录

- [简介](#简介)
- [特性](#特性)
- [快速开始](#快速开始)
- [使用说明](#使用说明)
- [配置](#配置)
- [技术栈](#技术栈)
- [项目结构](#项目结构)
- [开发指南](#开发指南)
- [路线图](#路线图)
- [参与贡献](#参与贡献)
- [许可证](#许可证)

## 简介

数据查询 MCP 是一个用 Rust 实现的数据库 MCP（Model Context Protocol）服务器，让 AI 客户端能够安全地查询数据库。通过 `config.toml` 可接入多个数据库（PostgreSQL、MySQL、SQLite、Redis），按名称区分查询目标。所有查询先经过语法校验，仅放行 SELECT 类查询语句，修改数据或结构的语句一律拒绝执行，避免 AI 误操作数据。适用于需要 AI 辅助数据分析、同时必须保证数据只读安全的场景。

## 特性

- 🔌 多数据库支持：PostgreSQL、MySQL、SQLite、Redis，首批落地 PostgreSQL
- ⚙️ 多实例配置：通过 `config.toml` 配置多个数据库连接，按名称切换查询目标
- 🛡️ 只读安全：SQL 先经语法校验，仅放行 SELECT 类查询语句，其余语句一律拒绝执行
- 🧩 模块化分层：语法校验、数据库适配、MCP 服务器分属独立 crate，便于扩展
- 🦀 Rust 实现：以 Rust 构建，作为 MCP 服务器供客户端调用

## 快速开始

### 环境要求

- Rust stable 工具链
- 可访问的目标数据库（如 PostgreSQL）

### 安装

```bash
git clone https://github.com/qq809326636/db-query.git
cd db-query
cargo build
```

### 运行

```bash
cargo run -p cli -- mcp --transport streamable  # 二进制名 excapp-db
```

## 使用说明

本服务作为 MCP 服务器运行，在支持 MCP 协议的客户端中注册后即可查询已配置的数据库。服务只执行通过语法校验的查询语句：

```sql
-- 允许执行：查询语句
SELECT count(*) FROM orders WHERE created_at >= current_date;

-- 拒绝执行：任何修改数据或结构的语句
-- UPDATE orders SET status = 'paid'
```

## 配置

通过 `config.toml` 配置多个数据库，服务按 `name` 区分查询目标。参考 [config.template.toml](config.template.toml)：

```toml
[[databases]]
uid = "primary"          # 连接唯一标识，重复会报错
name = "primary"         # 名称，便于用户识别
description = "..."      # 简单描述数据库覆盖范围等
type = "postgres"        # 数据库类型
dialect = "postgres"     # SQL 方言
username = "user"
password = "password"
host = "localhost"
port = 5432
db = "app"
extra_opts = ""          # 附加连接参数，可省略
```

## 技术栈

| 层次 | 技术栈 |
|------|--------|
| 后端 | Rust |
| 前端 | 无 |
| 客户端 | 无 |
| UI 组件库 | 无 |

## 项目结构

多 crate workspace，按职责分层：

```text
.
├── crates/
│   ├── cli/               # 命令行工具（binary 名 excapp-db）：conf / mcp / sql
│   ├── core/              # 共享基础设施：配置加载、状态存储（AppState）
│   ├── sql-mcp/           # MCP 服务器库（lib），六工具 + stdio 与 Streamable HTTP 传输
│   ├── sql-validator/     # SQL 语法校验库，仅放行只读查询
│   └── sql-executor/      # 数据库连接与查询执行库，封装各数据库的只读查询执行
├── .cSpell.json           # 拼写检查忽略配置
├── .gitignore             # Git 忽略规则
├── config.template.toml   # 配置文件模板
├── LICENSE                # MIT License
├── README.md              # 项目说明（英文）
└── README.zh.md           # 项目说明（中文）
```

## 开发指南

```bash
# 运行测试
cargo test

# 代码检查与格式化
cargo fmt
cargo clippy

# 构建
cargo build

# 发布构建（LTO + 裁剪符号，部署产物）
cargo build --release

# 快速发布构建（低优化、无 LTO，开发期验证 release 行为）
cargo build --profile release-fast
```

## 路线图

- [ ] 接入 PostgreSQL，实现只读查询与 SQL 语法校验（首个目标）
- [ ] 支持 MySQL 查询
- [ ] 支持 SQLite 查询
- [ ] 支持 Redis 查询

更多想法见 [Issues](https://github.com/qq809326636/db-query/issues)。

## 参与贡献

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建分支：`git checkout -b feat/your-feature`
3. 提交修改：`git commit -m "feat: add your feature"`
4. 推送分支并发起 Pull Request

## 许可证

本项目基于 [MIT License](LICENSE) 开源。
