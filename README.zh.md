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

- 🔌 多数据库支持：PostgreSQL、MySQL、SQLite（已落地），Redis（规划中）
- ⚙️ 多实例配置：通过 `config.toml` 配置多个数据库连接，按名称切换查询目标
- 🛡️ 只读安全：SQL 先经语法校验，仅放行 SELECT 类查询语句，其余语句一律拒绝执行
- 🧩 模块化分层：语法校验、数据库适配、MCP 服务器分属独立 crate，便于扩展
- 🦀 Rust 实现：以 Rust 构建，作为 MCP 服务器供客户端调用

## 快速开始

### 环境要求

- Rust stable 工具链（edition 2024，需较新稳定版）
- 可访问的目标数据库（如 PostgreSQL、MySQL）或 SQLite 数据库文件

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

### Docker 部署

```bash
# 构建镜像（缺省版本 1.0.0，可用 --version 覆盖；产出 excapp-db:1.0.0、
# excapp-db:1.0.0-g<git短sha>（如处于 git 仓库）与 excapp-db:latest 三个 tag）
./docker-build.sh

# 部署前准备：生成配置并调整监听地址
cp config.template.toml config.toml
#   - 编辑 config.toml 的数据库连接；
#   - [app.mcp.streamable] 的 addr 改为 "0.0.0.0"（否则仅容器内可达），
#     port 保持 8000，对外统一经宿主机 16000 映射；
#   - 宿主机 config.toml 需对容器内 app 用户（uid 1000）可读，如 chmod 644。

docker compose up -d       # 镜像需先由 docker-build.sh 构建并打对应版本 tag
docker compose logs -f     # 跟踪日志
docker compose down        # 停止（SIGTERM 优雅退出）
```

版本升级：同步修改 `docker-compose.yaml` 的 `image` 为新版本 tag 后重新 `up -d`。

## 使用说明

本服务作为 MCP 服务器运行，在支持 MCP 协议的客户端中注册后即可查询已配置的数据库。服务只执行通过语法校验的查询语句：

```sql
-- 允许执行：查询语句
SELECT count(*) FROM orders WHERE created_at >= current_date;

-- 拒绝执行：任何修改数据或结构的语句
-- UPDATE orders SET status = 'paid'
```

### MCP 工具

服务提供六个工具，按 `uid` 寻址查询目标，建议按顺序组合使用：

| 工具 | 作用 | 主要入参 |
|------|------|----------|
| `list-connection` | 列出配置的全部连接（本地读取，不连数据库） | — |
| `list-database` | 列出连接可见的数据库 | `uid` |
| `list-schema` | 列出库内 schema（排除系统 schema） | `uid` + `database` |
| `list-table` | 列出 schema 内表与视图（含分区语义） | `uid` + `database` + `schema`（可选） |
| `describe-table` | 表结构、DDL 与注释 | `uid` + `database` + `schema`（可选） + `table` |
| `execute-sql` | 校验并执行只读 SQL（行数 / 字节 / 超时三重保护） | `uid` + `database` + `schema`（可选） + `sql` |

典型流程：`list-connection` 找 uid → `list-database` 选库 → `list-schema` 定位 schema → `list-table` 找表 → `describe-table` 看结构 → `execute-sql` 查询数据。另有 guide 指引 Prompt 与六个工具对应的使用指引 Prompt（`lang` 参数可选 zh / en）。

## 配置

通过 `config.toml` 配置多个数据库，服务按 `name` 区分查询目标。参考 [config.template.toml](config.template.toml)：

```toml
# PostgreSQL / MySQL：网络连接形态（extra_opts 见 config.template.toml 的键白名单）
[[databases]]
uid = "primary"          # 连接唯一标识，重复会报错
name = "primary"         # 名称，便于用户识别
description = "..."      # 简单描述数据库覆盖范围等
type = "postgres"        # 数据库类型（postgres / mysql / sqlite）
dialect = "postgres"     # SQL 方言（postgres / mysql / sqlite）
username = "user"
password = "password"
host = "localhost"
port = 5432
db = "app"
extra_opts = ""          # 附加连接参数，可省略

# SQLite：文件库形态（连接层只读硬约束 mode=ro，不创建文件）
[[databases]]
uid = "sqlite-file"
name = "sqlite-file"
description = "..."
type = "sqlite"
dialect = "sqlite"
username = ""            # SQLite 忽略 username / password / host / port
password = ""
host = ""
port = 0
db = "/path/to/app.db"   # db 字段承载文件路径
extra_opts = ""
```

除连接配置外，`[validator.sql]` 策略段可选收紧放行类别（`whitelist.kinds`，只能收紧）与追加函数黑名单（`<dialect>.blacklist.function`，只可追加）；整体省略即内置策略。完整键说明见 [config.template.toml](config.template.toml)。

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
│   └── sql-executor/      # 数据库连接与查询执行库，封装各数据库的只读查询执行├── deps/                  # 测试依赖数据库编排（docker compose：PG18 / MySQL8 / Redis8）
├── benchmark/             # 非功能基准测试（security 安全压测场景）
├── docker-build.sh        # 镜像构建脚本（Dockerfile 的便捷封装）
├── docker-compose.yaml    # 部署编排（宿主机 16000 → 容器 8000）├── .cSpell.json           # 拼写检查忽略配置
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

# 集成测试依赖：启动三库测试容器（PG18 :10001 / MySQL8 :10002 / Redis8 :10003）
docker compose -f deps/docker-compose.yaml up -d
```

安全基线基准测试（攻击载荷库 / 并发资源保护 / 凭据泄露审计，详见 [benchmark/](benchmark/)）：

```bash
cd benchmark/security/scripts
python3 run.py                # 全部生效用例（双目标库）
```

## 路线图

- [x] 接入 PostgreSQL，实现只读查询与 SQL 语法校验（首个目标）
- [x] 支持 MySQL 查询（v0.2.0）
- [x] 支持 SQLite 查询（v0.2.0）
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
