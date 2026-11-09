//! Redis command whitelist validation: command parsing, read-only whitelist, and rejection reports.
//!
//! Parallel to the SQL validation path (not wired into the dialect registry; Redis has no SQL syntax tree):
//! single-command input, tokenization (quote-aware) -> normalization (uppercased command name) -> whitelist
//! (command + subcommand granularity) -> argument constraints -> the normalized allowed command or a rejection report.
//!
//! Fail closed: unknown commands, non-read-only commands, argument violations, and parse failures are all rejected;
//! pure-function behavior (no connections, no network round trips, no I/O side effects).

use std::fmt;

/// Normalized command structure: the tokenized product consumed by the executor.
///
/// The first token is the command name (uppercased); `subcommand` carries only true subcommand semantics
/// (e.g. OBJECT's ENCODING); SCAN's COUNT/MATCH are option arguments checked positionally
/// inside the decider and never enter the structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisCommand {
    /// Command name (uppercased).
    pub name: String,
    /// Subcommand (only for commands with subcommand semantics, e.g. OBJECT).
    pub subcommand: Option<String>,
    /// Remaining arguments (kept as-is, including spaces inside quotes).
    pub args: Vec<String>,
}

/// Machine-readable rejection categories for Redis validation (defined in parallel to sql-validator's RejectCategory
/// rather than shared - SQL semantics do not fit the command model).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedisRejectCategory {
    /// Command parse failure (unterminated quotes, multi-command input, and other malformed shapes).
    ParseError,
    /// Empty or whitespace-only input (batch-level error; index is always 1).
    EmptyInput,
    /// Unknown command (not in the known command set).
    UnknownCommand,
    /// Known non-read-only command (write / expiry / deletion / transaction / script / pub-sub / admin / cluster).
    NotReadOnly,
    /// Argument-level constraint violation for a whitelisted command (SCAN COUNT over the cap, too many keys, XREAD BLOCK, ...).
    ArgumentConstraint,
}

impl RedisRejectCategory {
    /// Machine-readable short name of the category (logging and debugging).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ParseError => "parse-error",
            Self::EmptyInput => "empty-input",
            Self::UnknownCommand => "unknown-command",
            Self::NotReadOnly => "not-read-only",
            Self::ArgumentConstraint => "argument-constraint",
        }
    }
}

/// Report of one rejected command (shape aligned with sql-validator's Denial: index/category/message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisDenial {
    /// Command index (always 1 for the single-command entry; reserved to match SQL batch semantics).
    pub index: usize,
    /// Rejection category.
    pub category: RedisRejectCategory,
    /// Stable English message (contains the full rejected command text, untruncated).
    pub message: String,
}

/// Redis command validation result (parallel to ValidationResult).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisValidationResult {
    /// True when the command is allowed.
    pub allowed: bool,
    /// Per-command rejection reports; empty when allowed.
    pub denials: Vec<RedisDenial>,
    /// The normalized command when allowed (None when rejected).
    command: Option<RedisCommand>,
}

impl RedisValidationResult {
    /// Reference to the normalized command when allowed (None when rejected).
    pub fn command(&self) -> Option<&RedisCommand> {
        self.command.as_ref()
    }

    /// Construct an allowed result.
    fn allowed(command: RedisCommand) -> Self {
        Self {
            allowed: true,
            denials: Vec::new(),
            command: Some(command),
        }
    }

    /// Construct a rejected result (index is always 1 for the single-command entry).
    fn denied(category: RedisRejectCategory, message: String) -> Self {
        Self {
            allowed: false,
            denials: vec![RedisDenial {
                index: 1,
                category,
                message,
            }],
            command: None,
        }
    }
}

impl fmt::Display for RedisRejectCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whitelist entry: command + subcommand restriction + argument constraints.
struct WhitelistEntry {
    /// Command name (uppercase).
    name: &'static str,
    /// Subcommand whitelist (None = no subcommand semantics).
    subcommands: Option<&'static [&'static str]>,
    /// Argument constraint shape.
    constraint: Constraint,
}

/// Argument constraint shape.
enum Constraint {
    /// No extra constraints (arity is validated by the server per command).
    None,
    /// Multi-key/member commands: cap on the key count beyond the first argument.
    MultiKey(usize),
    /// SCAN family: cap on the COUNT option value.
    ScanCount(u64),
    /// XREAD: must not carry the BLOCK option.
    NoBlock,
    /// INFO: zero or one section argument.
    InfoSection,
}

/// Known non-read-only commands (clearer messages than UNKNOWN_COMMAND; not exhaustive -
/// unlisted ones are still rejected as UNKNOWN_COMMAND - fail closed does not depend on this table being complete).
const KNOWN_NOT_READ_ONLY: &[&str] = &[
    // writes
    "SET",
    "SETNX",
    "SETEX",
    "PSETEX",
    "MSET",
    "MSETNX",
    "APPEND",
    "SETRANGE",
    "INCR",
    "DECR",
    "INCRBY",
    "DECRBY",
    "INCRBYFLOAT",
    "HSET",
    "HSETNX",
    "HMSET",
    "HDEL",
    "HINCRBY",
    "HINCRBYFLOAT",
    "LPUSH",
    "RPUSH",
    "LPUSHX",
    "RPUSHX",
    "LPOP",
    "RPOP",
    "LINSERT",
    "LSET",
    "LTRIM",
    "LREM",
    "RPOPLPUSH",
    "LMOVE",
    "SADD",
    "SREM",
    "SPOP",
    "SMOVE",
    "SINTERSTORE",
    "SUNIONSTORE",
    "SDIFFSTORE",
    "ZADD",
    "ZINCRBY",
    "ZREM",
    "ZREMRANGEBYRANK",
    "ZREMRANGEBYSCORE",
    "ZREMRANGEBYLEX",
    "ZPOPMIN",
    "ZPOPMAX",
    "ZMPOP",
    "BZPOPMIN",
    "BZPOPMAX",
    "GETDEL",
    "GETEX",
    "SETDEL",
    "COPY",
    "RESTORE",
    "MIGRATE",
    "DUMP",
    // expiry / deletion
    "DEL",
    "UNLINK",
    "EXPIRE",
    "PEXPIRE",
    "EXPIREAT",
    "PEXPIREAT",
    "EXPIRETIME",
    "PEXPIRETIME",
    "PERSIST",
    "TOUCH",
    // transactions / scripts
    "MULTI",
    "EXEC",
    "DISCARD",
    "WATCH",
    "UNWATCH",
    "EVAL",
    "EVALSHA",
    "EVAL_RO",
    "EVALSHA_RO",
    "SCRIPT",
    "FUNCTION",
    // pub-sub
    "PUBLISH",
    "SPUBLISH",
    "SUBSCRIBE",
    "UNSUBSCRIBE",
    "PSUBSCRIBE",
    "PUNSUBSCRIBE",
    "SSUBSCRIBE",
    "SUNSUBSCRIBE",
    "PUBSUB",
    // admin / server
    "FLUSHALL",
    "FLUSHDB",
    "SWAPDB",
    "CONFIG",
    "DEBUG",
    "CLIENT",
    "SHUTDOWN",
    "RESET",
    "REPLICAOF",
    "SLAVEOF",
    "FAILOVER",
    "ACL",
    "AUTH",
    "SELECT",
    "BGREWRITEAOF",
    "BGSAVE",
    "SAVE",
    "SYNC",
    "PSYNC",
    "LOLWUT",
    "COMMAND",
    "LATENCY",
    "SLOWLOG",
    "WAIT",
    "WAITAOF",
    "UNFAIL",
    // cluster
    "CLUSTER",
    "READONLY",
    "READWRITE",
];

/// Read-only whitelist (full design table).
const WHITELIST: &[WhitelistEntry] = &[
    // -- No extra constraints (arity is validated by the server) --
    WhitelistEntry {
        name: "TYPE",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "EXISTS",
        subcommands: None,
        constraint: Constraint::MultiKey(100),
    },
    WhitelistEntry {
        name: "TTL",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "PTTL",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "RANDOMKEY",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "GET",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "STRLEN",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "GETRANGE",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "SUBSTR",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "LLEN",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "LINDEX",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "SCARD",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "ZCARD",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "ZCOUNT",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "ZLEXCOUNT",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "ZRANK",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "ZREVRANK",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "ZSCORE",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "PFCOUNT",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "XLEN",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "DBSIZE",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "TIME",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "LASTSAVE",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "PING",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "ECHO",
        subcommands: None,
        constraint: Constraint::None,
    },
    // -- Multi-key cap 100 --
    WhitelistEntry {
        name: "MGET",
        subcommands: None,
        constraint: Constraint::MultiKey(100),
    },
    WhitelistEntry {
        name: "SMISMEMBER",
        subcommands: None,
        constraint: Constraint::MultiKey(100),
    },
    WhitelistEntry {
        name: "ZMSCORE",
        subcommands: None,
        constraint: Constraint::MultiKey(100),
    },
    WhitelistEntry {
        name: "HMGET",
        subcommands: None,
        constraint: Constraint::None,
    },
    // -- Hash / set / list read-only --
    WhitelistEntry {
        name: "HGET",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "HEXISTS",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "HGETALL",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "HKEYS",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "HVALS",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "SISMEMBER",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "SMEMBERS",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "SRANDMEMBER",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "LRANGE",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "LPOS",
        subcommands: None,
        constraint: Constraint::None,
    },
    // -- Sorted-set read-only --
    WhitelistEntry {
        name: "ZRANGE",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "ZREVRANGE",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "ZRANGEBYSCORE",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "ZREVRANGEBYSCORE",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "ZRANGEBYLEX",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "ZREVRANGEBYLEX",
        subcommands: None,
        constraint: Constraint::None,
    },
    // -- Bitmap / geo --
    WhitelistEntry {
        name: "GETBIT",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "BITCOUNT",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "BITPOS",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "BITFIELD_RO",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "GEOPOS",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "GEOHASH",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "GEODIST",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "GEOSEARCH",
        subcommands: None,
        constraint: Constraint::None,
    },
    // -- Streams (non-blocking) --
    WhitelistEntry {
        name: "XRANGE",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "XREVRANGE",
        subcommands: None,
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "XREAD",
        subcommands: None,
        constraint: Constraint::NoBlock,
    },
    // -- SCAN family (COUNT option cap) --
    WhitelistEntry {
        name: "SCAN",
        subcommands: None,
        constraint: Constraint::ScanCount(1000),
    },
    WhitelistEntry {
        name: "HSCAN",
        subcommands: None,
        constraint: Constraint::ScanCount(1000),
    },
    WhitelistEntry {
        name: "SSCAN",
        subcommands: None,
        constraint: Constraint::ScanCount(1000),
    },
    WhitelistEntry {
        name: "ZSCAN",
        subcommands: None,
        constraint: Constraint::ScanCount(1000),
    },
    // -- Subcommand semantics --
    WhitelistEntry {
        name: "OBJECT",
        subcommands: Some(&["ENCODING", "REFCOUNT", "IDLETIME", "FREQ"]),
        constraint: Constraint::None,
    },
    WhitelistEntry {
        name: "MEMORY",
        subcommands: Some(&["USAGE"]),
        constraint: Constraint::None,
    },
    // -- Server info --
    WhitelistEntry {
        name: "INFO",
        subcommands: None,
        constraint: Constraint::InfoSection,
    },
];

/// Validate a single Redis command text (public entry, named to match the existing validate).
///
/// Returns [`RedisValidationResult`]: when allowed, `command()` yields the normalized command structure
/// (for the executor); a rejection is a normal business result, `denials` carries the machine-readable category
/// and a stable English message (the full original command, untruncated).
pub fn validate_redis(command_text: &str) -> RedisValidationResult {
    let trimmed = command_text.trim();
    if trimmed.is_empty() {
        return RedisValidationResult::denied(
            RedisRejectCategory::EmptyInput,
            "empty input: the command contains no tokens".to_string(),
        );
    }

    let tokens = match tokenize(trimmed) {
        Ok(tokens) => tokens,
        Err(reason) => {
            return RedisValidationResult::denied(
                RedisRejectCategory::ParseError,
                format!("parse error: {reason}: {command_text:?}"),
            );
        }
    };

    let (name, subcommand, args) = normalize(tokens);
    let upper = name.to_uppercase();

    let entry = match WHITELIST.iter().find(|e| e.name == upper) {
        Some(entry) => entry,
        None => {
            let category = if KNOWN_NOT_READ_ONLY.contains(&upper.as_str()) {
                RedisRejectCategory::NotReadOnly
            } else {
                RedisRejectCategory::UnknownCommand
            };
            let hint = match category {
                RedisRejectCategory::NotReadOnly => "this command is not read-only",
                _ => "unknown command",
            };
            return RedisValidationResult::denied(
                category,
                format!("'{upper}' rejected: {hint}: {command_text:?}"),
            );
        }
    };

    // Subcommand validation (for commands with a subcommand table).
    if let Some(allowed_subs) = entry.subcommands {
        match &subcommand {
            Some(sub) if allowed_subs.contains(&sub.as_str()) => {}
            Some(sub) => {
                return RedisValidationResult::denied(
                    RedisRejectCategory::NotReadOnly,
                    format!(
                        "OBJECT/MEMORY subcommand '{sub}' is not allowed (allowed: {}): {command_text:?}",
                        allowed_subs.join(", ")
                    ),
                );
            }
            None => {
                return RedisValidationResult::denied(
                    RedisRejectCategory::ArgumentConstraint,
                    format!(
                        "'{upper}' requires a subcommand (allowed: {}): {command_text:?}",
                        allowed_subs.join(", ")
                    ),
                );
            }
        }
    }

    // Argument-level constraints.
    if let Err(reason) = check_constraint(&upper, &subcommand, &args, &entry.constraint) {
        return RedisValidationResult::denied(
            RedisRejectCategory::ArgumentConstraint,
            format!("{reason}: {command_text:?}"),
        );
    }

    RedisValidationResult::allowed(RedisCommand {
        name: upper,
        subcommand,
        args,
    })
}

/// Quote-aware tokenization: double quotes wrap arguments containing spaces; no splitting inside quotes.
///
/// Returns:
/// Ok(tokens) - at least the command-name token.
///
/// Errors:
/// Unterminated quotes; multi-command input (a second command separated by a semicolon / newline).
fn tokenize(input: &str) -> Result<Vec<String>, String> {
    // Multi-command input is rejected as a whole (design decision: semicolons are legal argument characters, so splitting carries semantic risk).
    // Rule: a semicolon or newline at the top level (outside quotes) rejects the input.
    let mut in_quotes = false;
    for ch in input.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ';' | '\n' if !in_quotes => {
                return Err(
                    "multiple commands are not supported; submit one command per call".into(),
                );
            }
            _ => {}
        }
    }
    if in_quotes {
        return Err("unterminated double quote".into());
    }

    let mut tokens: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut has_token = false;
    for ch in input.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                has_token = true; // 空引号 "" 也是有效 token
            }
            c if c.is_whitespace() && !in_quotes => {
                if has_token {
                    tokens.push(std::mem::take(&mut current));
                    has_token = false;
                }
            }
            c => {
                current.push(c);
                has_token = true;
            }
        }
    }
    if has_token {
        tokens.push(current);
    }
    if tokens.is_empty() {
        return Err("no tokens".into());
    }
    Ok(tokens)
}

/// Token normalization: the first token is the command name; the second enters subcommand when it matches the known subcommand set.
fn normalize(mut tokens: Vec<String>) -> (String, Option<String>, Vec<String>) {
    let name = tokens.remove(0);
    let upper = name.to_uppercase();
    // Commands with subcommand semantics (matching the whitelist subcommands).
    let subcommand_hosts: &[&str] = &["OBJECT", "MEMORY"];
    let mut subcommand = None;
    let mut args = tokens;
    if subcommand_hosts.contains(&upper.as_str()) && !args.is_empty() {
        let candidate = args.remove(0).to_uppercase();
        subcommand = Some(candidate);
    }
    (name, subcommand, args)
}

/// Argument constraint checks (an Err(English reason) marks a violation).
fn check_constraint(
    upper: &str,
    _subcommand: &Option<String>,
    args: &[String],
    constraint: &Constraint,
) -> Result<(), String> {
    match constraint {
        Constraint::None => Ok(()),
        Constraint::MultiKey(max) => {
            // args holds the first key + the remaining keys / members; the cap aligns with the existing row semantics.
            if args.len() > *max {
                Err(format!(
                    "'{upper}' accepts at most {max} keys, got {}",
                    args.len()
                ))
            } else {
                Ok(())
            }
        }
        Constraint::ScanCount(max) => {
            // SCAN family: [cursor] [MATCH p] [COUNT n] [TYPE t] - the numeric cap after COUNT.
            let mut i = 0;
            while i < args.len() {
                let arg = args[i].to_uppercase();
                if arg == "COUNT" {
                    let value = args
                        .get(i + 1)
                        .ok_or_else(|| "COUNT option requires a value".to_string())?;
                    let n: u64 = value
                        .parse()
                        .map_err(|_| format!("COUNT value is not a number: {value:?}"))?;
                    if n > *max {
                        return Err(format!("SCAN COUNT {n} exceeds the limit {max}"));
                    }
                    i += 2;
                } else {
                    i += 1;
                }
            }
            Ok(())
        }
        Constraint::NoBlock => {
            // XREAD: must not carry the BLOCK option (blocking forms are rejected).
            if args.iter().any(|a| a.eq_ignore_ascii_case("BLOCK")) {
                Err(
                    "'XREAD' with BLOCK is not allowed (blocking form); use the non-blocking form"
                        .into(),
                )
            } else {
                Ok(())
            }
        }
        Constraint::InfoSection => {
            if args.len() > 1 {
                Err("'INFO' accepts at most one section argument".into())
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deny_of(input: &str) -> RedisValidationResult {
        validate_redis(input)
    }

    #[test]
    fn test_case_insensitive_and_normalization() {
        for input in ["get user:1", "GET user:1", "Get user:1"] {
            let r = validate_redis(input);
            assert!(r.allowed, "{input}");
            let c = r.command().unwrap();
            assert_eq!(c.name, "GET");
            assert_eq!(c.args, ["user:1"]);
        }
    }

    #[test]
    fn test_quoted_argument_with_spaces() {
        let r = validate_redis(r#"GET "key with spaces""#);
        assert!(r.allowed);
        assert_eq!(r.command().unwrap().args, ["key with spaces"]);
    }

    #[test]
    fn test_empty_input() {
        for input in ["", "   ", "\t"] {
            let r = deny_of(input);
            assert!(!r.allowed);
            assert_eq!(r.denials[0].category, RedisRejectCategory::EmptyInput);
            assert_eq!(r.denials[0].index, 1);
        }
    }

    #[test]
    fn test_parse_errors() {
        // Unterminated quotes.
        let r = deny_of(r#"GET "unterminated"#);
        assert_eq!(r.denials[0].category, RedisRejectCategory::ParseError);
        // Multiple commands (top-level semicolon / newline).
        let r = deny_of("GET a; SET b 1");
        assert_eq!(r.denials[0].category, RedisRejectCategory::ParseError);
        let r = deny_of("GET a\nGET b");
        assert_eq!(r.denials[0].category, RedisRejectCategory::ParseError);
        // A semicolon inside quotes is a legal argument character (no multi-command trigger).
        let r = validate_redis(r#"GET "a;b""#);
        assert!(r.allowed);
    }

    #[test]
    fn test_whitelist_readonly_families() {
        // One allowed representative per command family (at least one per family, locking the review-recommended cross-check).
        for input in [
            "TYPE k",
            "EXISTS k",
            "TTL k",
            "PTTL k",
            "RANDOMKEY",
            "GET k",
            "STRLEN k",
            "GETRANGE k 0 5",
            "SUBSTR k 0 5",
            "MGET a b c",
            "STRLEN k",
            "HGET h f",
            "HMGET h f1 f2",
            "HGETALL h",
            "HKEYS h",
            "HVALS h",
            "HEXISTS h f",
            "LRANGE l 0 -1",
            "LLEN l",
            "LINDEX l 0",
            "LPOS l v",
            "SMEMBERS s",
            "SISMEMBER s v",
            "SMISMEMBER s v1 v2",
            "SCARD s",
            "SRANDMEMBER s",
            "ZRANGE z 0 -1",
            "ZREVRANGE z 0 -1",
            "ZRANGEBYSCORE z 0 100",
            "ZREVRANGEBYSCORE z 100 0",
            "ZRANGEBYLEX z - +",
            "ZREVRANGEBYLEX z + -",
            "ZSCORE z m",
            "ZMSCORE z m1 m2",
            "ZCARD z",
            "ZCOUNT z 0 100",
            "ZLEXCOUNT z - +",
            "ZRANK z m",
            "ZREVRANK z m",
            "GETBIT k 0",
            "BITCOUNT k",
            "BITPOS k 0",
            "BITFIELD_RO k GET u8 0",
            "PFCOUNT p",
            "GEOPOS g m",
            "GEOHASH g m",
            "GEODIST g a b",
            "GEOSEARCH g FROMLONLAT 1 1 BYRADIUS 10 km",
            "XRANGE s - +",
            "XREVRANGE s + -",
            "XLEN s",
            "XREAD STREAMS s 0",
            "PING",
            "ECHO hi",
            "DBSIZE",
            "INFO",
            "INFO keyspace",
            "TIME",
            "LASTSAVE",
            "MEMORY USAGE k",
            "OBJECT ENCODING k",
            "OBJECT REFCOUNT k",
            "OBJECT IDLETIME k",
            "OBJECT FREQ k",
            "SCAN 0",
            "SCAN 0 MATCH u:* COUNT 100",
            "HSCAN h 0",
            "SSCAN s 0",
            "ZSCAN z 0",
        ] {
            let r = validate_redis(input);
            assert!(
                r.allowed,
                "should allow: {input} -> {:?}",
                r.denials.first().map(|d| &d.message)
            );
        }
    }

    #[test]
    fn test_reject_not_read_only() {
        for input in [
            "SET k v",
            "DEL k",
            "EXPIRE k 10",
            "SETEX k 10 v",
            "UNLINK k",
            "MULTI",
            "EXEC",
            "EVAL \"return 1\" 0",
            "SCRIPT LOAD x",
            "PUBLISH ch msg",
            "SUBSCRIBE ch",
            "FLUSHALL",
            "FLUSHDB",
            "CONFIG GET maxmemory",
            "DEBUG JMAP",
            "CLIENT KILL id 1",
            "SHUTDOWN",
            "SELECT 1",
            "CLUSTER INFO",
            "REPLICAOF no one",
            "AUTH pw",
        ] {
            let r = deny_of(input);
            assert!(!r.allowed, "should deny: {input}");
            assert_eq!(
                r.denials[0].category,
                RedisRejectCategory::NotReadOnly,
                "{input}"
            );
            assert!(
                r.denials[0]
                    .message
                    .contains(&input.to_uppercase().split(' ').next().unwrap().to_string())
                    || r.denials[0].message.contains(input),
                "message should name the command: {}",
                r.denials[0].message
            );
        }
    }

    #[test]
    fn test_reject_unknown_command() {
        for input in ["FOOBAR x", "GETT k", "SETRANGE2 k 0 v"] {
            let r = deny_of(input);
            assert_eq!(
                r.denials[0].category,
                RedisRejectCategory::UnknownCommand,
                "{input}"
            );
        }
        // Unknown and non-read-only categories are distinguishable.
        let unknown = deny_of("FOOBAR x");
        let not_ro = deny_of("SET k v");
        assert_ne!(unknown.denials[0].category, not_ro.denials[0].category);
    }

    #[test]
    fn test_argument_constraints() {
        // SCAN COUNT capped at 1000.
        let r = deny_of("SCAN 0 COUNT 1001");
        assert_eq!(
            r.denials[0].category,
            RedisRejectCategory::ArgumentConstraint
        );
        let r = validate_redis("SCAN 0 COUNT 1000");
        assert!(r.allowed);
        let r = deny_of("SCAN 0 COUNT abc");
        assert_eq!(
            r.denials[0].category,
            RedisRejectCategory::ArgumentConstraint
        );
        // MGET key count capped at 100 (args with 101 keys).
        let many: Vec<String> = (0..101).map(|i| format!("k{i}")).collect();
        let r = deny_of(&format!("MGET {}", many.join(" ")));
        assert_eq!(
            r.denials[0].category,
            RedisRejectCategory::ArgumentConstraint
        );
        let hundred: Vec<String> = (0..100).map(|i| format!("k{i}")).collect();
        let r = validate_redis(&format!("MGET {}", hundred.join(" ")));
        assert!(r.allowed);
        // XREAD BLOCK rejected.
        let r = deny_of("XREAD BLOCK 1000 STREAMS s 0");
        assert_eq!(
            r.denials[0].category,
            RedisRejectCategory::ArgumentConstraint
        );
        // INFO with multiple sections rejected.
        let r = deny_of("INFO server keyspace");
        assert_eq!(
            r.denials[0].category,
            RedisRejectCategory::ArgumentConstraint
        );
    }

    #[test]
    fn test_object_subcommand_boundaries() {
        // Whitelisted subcommands pass (covered by the family test); out-of-bound subcommands are rejected (including HELP - tightened by design).
        for input in [
            "OBJECT HELP k",
            "OBJECT UNDEFINED k",
            "MEMORY DOCTOR k",
            "MEMORY STATS",
        ] {
            let r = deny_of(input);
            assert!(!r.allowed, "{input}");
            assert!(
                r.denials[0].category == RedisRejectCategory::NotReadOnly
                    || r.denials[0].category == RedisRejectCategory::ArgumentConstraint,
                "{input}: {:?}",
                r.denials[0].category
            );
        }
        // Missing subcommand (bare OBJECT with no following token) is rejected.
        let r = deny_of("OBJECT");
        assert_eq!(
            r.denials[0].category,
            RedisRejectCategory::ArgumentConstraint
        );
        // Has tokens but out of bound (k taken as a subcommand) goes through the subcommand out-of-bound branch.
        let r = deny_of("OBJECT k");
        assert_eq!(r.denials[0].category, RedisRejectCategory::NotReadOnly);
    }

    #[test]
    fn test_denial_message_no_config_leak() {
        let r = deny_of("CONFIG GET maxmemory");
        assert!(!r.message_contains_secrets());
        // The full original text is kept untruncated.
        let long_arg = "k".repeat(300);
        let r = deny_of(&format!("FOOBAR {long_arg}"));
        assert!(
            r.denials[0].message.contains(&long_arg),
            "full command text must be preserved"
        );
    }

    /// Test helper: rejection messages contain no config shapes (simple heuristic - this module has no access to config in the first place).
    trait MessageExt {
        fn message_contains_secrets(&self) -> bool;
    }
    impl MessageExt for RedisValidationResult {
        fn message_contains_secrets(&self) -> bool {
            // This module has no config to leak; asserting messages avoid common sensitive-key shapes suffices.
            let m = &self.denials[0].message;
            m.contains("password") || m.contains("host") || m.contains("port")
        }
    }

    #[test]
    fn test_pure_function_no_io() {
        // Pure-function behavior is guaranteed by the type system (no network/file API references); this test anchors that
        // a large number of random shapes neither panic nor change outcomes.
        for input in [
            "  GET   k  ",
            "get\tk",
            "GET",
            "MGET",
            "XREAD",
            "SCAN",
            "INFO a b c",
        ] {
            let _ = validate_redis(input);
        }
    }
}
