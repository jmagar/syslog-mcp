---
stack: general
review_agents:
  - code-simplicity-reviewer
  - security-sentinel
  - performance-oracle
  - architecture-strategist
plan_review_agents:
  - code-simplicity-reviewer
  - architecture-strategist
disabled_agents: []
---

<reviewer_context_note>
Rust 2021 syslog MCP server. Sync r2d2 pool is intentional — async rusqlite not yet production-stable. thiserror declared but unused; anyhow carries all errors. No tests exist yet — this is a new project. MCP JSON-RPC is hand-rolled, no SDK.
</reviewer_context_note>
