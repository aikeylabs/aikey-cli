# Archived tests

Tests here are **not compiled or run** by `cargo test`. Cargo only auto-discovers
top-level `.rs` files in `tests/`, so files in this subdirectory are ignored. The
`.bak` extension is an extra belt-and-suspenders guard in case the project later
adopts a glob that descends into subdirs.

## Why archive instead of delete?

- Preserves the original intent + assertions as reference material.
- Makes resurrection straightforward if the feature comes back.
- Keeps git blame intact for future investigators.

## Archived files

| File | Archived on | Reason |
|------|-------------|--------|
| `ghost_exec_test.rs.bak` | 2026-04-17 | Tests `aikey exec` + `aikeyd` socket daemon. Both replaced: `exec` → `aikey run`; `aikeyd` daemon dropped in favour of the local proxy model (see `roadmap20260320/技术实现/阶段2-MVP业务流实现方案/20260330-aikey-use-语义升级与provider路由方案.md`). |
| `cortex_stress_test.rs.bak` | 2026-04-17 | Internal codename "cortex" stress tests (schema integrity, migration roundtrips, export/import). Tests pre-Stage-2 schema that has since been refactored via `CredentialType` enum + `user_profile_provider_bindings` tables. 0/4 passing at time of archive. |
| `feature_tests.rs.bak` | 2026-04-17 | Mixed bag: `audit_log` table tests (table removed), `clipboard` timeout flag, old `aikey add` contract. 0/8 passing. |
| `synapse_audit.rs.bak` | 2026-04-17 | Internal codename "synapse" — audit tests on a removed surface. 0/6 passing. |
| `synapse_stress_test.rs.bak` | 2026-04-17 | Internal codename "synapse" stress tests. 0/8 passing. |

## If you need to revive one

1. Move it back up to `tests/` and remove the `.bak` suffix.
2. Expect compile errors — the tests reference APIs that have moved/gone.
3. Reconcile assertions with the current design docs in
   `roadmap20260320/技术实现/` and the bugfix log in `workflow/CI/bugfix/`.
