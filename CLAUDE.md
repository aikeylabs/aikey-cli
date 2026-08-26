# aikey-cli（Rust 本地 CLI）

- cli 需要简单易用、易记、防呆设计、友好异常提示；遇到流程阻塞或必要的前提不具备时在提示里面给出解决步骤
- CLI 采用 MVC 架构设计；错误需要能全链条传播，不允许用 `unwrap()` / `panic!` 替代真错误处理
- 所有 `_internal` 隐藏命令必须复用对应公开 `aikey` 命令的非交互核心，不能并行写一套 → [internal-command-reuses-public-core.md](../workflow/CI/IDE/claude/principles/internal-command-reuses-public-core.md)
- 修改 parse 链路（候选抽取、分组、provider 推断）或 fingerprint 配置，先走 research spike 验证，没有"纯重构例外" → [import-parser-research-validation.md](../workflow/CI/IDE/claude/principles/import-parser-research-validation.md)
- vault 迁移在 `src/migrations.rs`，每条 migration 必须可重复执行（幂等） → [migration-script-spec.md](../workflow/CI/IDE/claude/principles/migration-script-spec.md)
- 需要支持多端平台 Windows、macOS、Ubuntu、CentOS/Linux；注意 claude、kimi、codex 等版本升级的兼容性
