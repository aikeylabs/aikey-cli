# Proxy Lifecycle State Machine · Review TODO

**生成于** 2026-04-28（Round 5 三态化提交后）
**Review 来源**：3 agents（reuse / quality / efficiency）平行审 `proxy_state.rs` + `proxy_proc.rs` + `proxy_lifecycle.rs` + `commands_proxy.rs` 改动
**状态**：findings 已识别，**未应用**（按用户要求保留给重构 proxy 的另一个会话处理）

---

## 高优先级（带 bug 嫌疑）

### 1. `commands_proxy.rs:815 process_alive` 不处理 EPERM → 返回 false（buggy）

```rust
fn process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
        ret == 0   // ← 漏掉 EPERM (alive but unprivileged)
    }
    ...
}
```

Canonical 版在 `proxy_proc.rs:34` 正确处理：`ret == 0 || errno == EPERM`。

**修复**：删除 `commands_proxy.rs:815-838`，import + 调用 `crate::proxy_proc::process_alive`。

**影响**：Linux 下用户跑 `aikey proxy status` 而 PID 恰好被一个 root 进程占用时，老逻辑会显示 "stopped (stale pid file)" 然后 `let _ = fs::remove_file(pid_path()?)` 默默删掉 pidfile。新逻辑识别 alive 不 stale。

### 2. 三处 `pid_path()` / 两处 `meta_path()` 各自实现

| 位置 | 函数 | 状态 |
|------|------|------|
| `commands_proxy.rs:794` | `fn pid_path()` | 私有，原始 |
| `proxy_state.rs:632` | `pub fn pidfile_path()` | Layer 1 加的 |
| `proxy_lifecycle.rs:256` | `pub fn pid_path()` | Layer 2 加的 |
| `proxy_state.rs:231` | `pub fn meta_path()` | Layer 1 |
| `proxy_lifecycle.rs:261` | `pub fn meta_path()` | Layer 2 |

`proxy_state.rs:629` 注释承认 "Stage 3 cut-over will collapse"，但 Layer 2 加了第三个。

**修复**：选 `proxy_lifecycle::run_dir + pid_path/meta_path`（已有 `create_dir_all` 钩子）作为 canonical；其余两处改成调用它的薄 re-export。

### 3. `proxy_state.rs:616-618` Sentinel `/tmp/_aikey_proxy_pidpath_unset` Windows-broken 默默 fallback

```rust
fn proxy_state_inputs() -> StateInputs {
    StateInputs {
        pid_path: pidfile_path()
            .unwrap_or_else(|_| PathBuf::from("/tmp/_aikey_proxy_pidpath_unset")),
        meta_path: meta_path()
            .unwrap_or_else(|_| PathBuf::from("/tmp/_aikey_proxy_metapath_unset")),
        ...
    }
}
```

`/tmp/_aikey_*_unset` 在 Windows 不存在（应该是 `%TEMP%`）。`home_dir()` 失败时 silent 退化成"假装 pidfile 在 /tmp 那边"，所有的 state 都会 misclassify。

**修复**：让 `proxy_state()` 返回 `Result<ProxyState, _>` 把 home_dir 失败当真 error 抛出去，调用方按 fail-loud 处理。

### 4. `proxy_lifecycle.rs:748-753` TOCTOU `binary_path.exists()` + `config_path.exists()` 在 spawn 前

```rust
if !opts.binary_path.exists() {
    return Err(StartError::BinaryMissing(...));
}
if !opts.config_path.exists() {
    return Err(StartError::ConfigMissing(...));
}
let mut child = Command::new(&opts.binary_path).spawn()...
```

Classic TOCTOU + 冗余 — `Command::spawn` 自己会失败给清晰 error，不需要 pre-check。

**修复**：删 `exists()` 检查；在 `Command::spawn` 错误路径里看 `e.kind() == NotFound` + 哪个路径失败来分支到 `BinaryMissing` vs `ConfigMissing`。

---

## 中优先级（quality / efficiency）

### 5. 魔法端口 `27200` 硬编码 4-6 处

| 位置 | 上下文 |
|------|--------|
| `proxy_state.rs:419` | `host_port` parse fallback |
| `proxy_state.rs:616-618` | sentinel default |
| `proxy_lifecycle.rs:640` | `unwrap_or_else(|_| "127.0.0.1:27200".into())` |
| `proxy_lifecycle.rs:817` | `parse_port` fallback |
| `commands_proxy.rs:28` | `PROXY_HEALTH_ADDR_DEFAULT` |

**修复**：在 `proxy_state.rs` 顶部一个 `pub const DEFAULT_PROXY_PORT: u16 = 27200;` + `pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:27200";`，五处全部 import 引用。

### 6. `compute_proxy_state` 内 `OrphanedPort {...}` 构造复制 6 次

`proxy_state.rs:466-470, 478-482, 490-495, 500-504, 514-518, 522-527` 全是同一个 struct literal 只换 `reason` 字段。

**修复**：抽 helper：
```rust
fn orphaned(port: u16, pid: u32, reason: OrphanReason) -> ProxyState {
    ProxyState::OrphanedPort { port, owner_pid: Some(pid), reason }
}
```
6 行各折叠为 1 行。

### 7. `proxy_proc.rs:240ish` Linux `/proc/PID/stat` 解析为了拿 field 19 分配 Vec<&str>

```rust
let fields: Vec<&str> = remainder.split_whitespace().collect();
let starttime = fields.get(19).and_then(...)
```

**修复**：`remainder.split_whitespace().nth(19).and_then(...)` —— 0 alloc。`compute_proxy_state` 每次调用都跑这条路径。

### 8. `proxy_lifecycle.rs:738` `http_health_ok(500ms)` 第一次必然浪费 500ms

启动后立刻 probe，proxy 还没 bind，500ms 超时浪费。后续 250ms 间隔更合理。

**修复**：先用 `port_is_bound(port)`（微秒级 `TcpListener::bind` 探测）做廉价 gate；bound 之后再 HTTP probe；初次失败重试用 50-100ms timeout，渐进 ramp 到 500ms。

### 9. 重复 `lsof` 调用 — happy path 下不需要

`compute_proxy_state` 在 ownership 验证通过后还调用 `port_owner_pid` (lsof spawn ~10-20ms)。

**修复**：ownership-verified 分支用 `port_is_bound` 短路；只有 unverified 分支才走 lsof。

### 10. `proxy_lifecycle.rs:537-552` 与 553+ doc-comment 重复

`stop_proxy` 的 doc 第一句"Stop the proxy, blocking until..."写了两次。

**修复**：删 537-552，保留 553+ 的精简版。

---

## 低优先级（cleanup / consistency）

### 11. 4-5 处 `atomic_write` 各自实现

| 位置 |
|------|
| `proxy_lifecycle.rs:272` (新加) |
| `proxy_state.rs:310` `write_meta_atomic_at` (用 inline tmp+rename) |
| `profile_activation.rs:413` (PID-suffix temp，更防御) |
| `commands_account/shell_integration.rs:133` |
| `commands_statusline.rs:1249` |

**修复**：抽一个 `crate::util::atomic_write`（用 `profile_activation` 的 PID-suffix 版作 canonical），5 处 collapse。

### 12. `MetaV1::schema_version` 是 `pub` 字段

调用方理论上能写 `meta.schema_version = 99`。

**修复**：改为 private，构造经 `read_meta_at` 已经 gate 过；外部读取也不需要这个字段。

### 13. `StartError::PersistFailed(String)` / `KillFailed(String)` 等过宽

`PersistFailed(String)` 同时承接 "pid_path 解析失败" / "sidecar serialize 失败" / "sidecar 写失败" / "pidfile 写失败"，丢失定位信息。

**修复**：拆 `PersistFailed { kind: PersistKind, source: io::Error }`，用 enum 表态哪个文件/操作失败。`KillFailed` 同样可以承载 `errno`。

### 14. birth_token 前缀字符串 `"linux:jiffies:"` / `"darwin:starttime:"` / `"windows:filetime:"` 写法点对点散布

测试在 `proxy_proc.rs:544-547` 用 raw string 断言；产线在 `proxy_proc.rs:244,267-270,300` 构造。typo drift 风险。

**修复**：抽 `const LINUX_BIRTH_TOKEN_TAG: &str = "linux:jiffies:"` 等，writer 和 test 都引用同一 const。

### 15. 测试块（`proxy_state.rs:688-1045`）部分 narrative 注释

- `proxy_state.rs:702-707` — "We use the path-explicit *_at variants…" 是 narrative；macOS HOME quirk 是 load-bearing — 拆开，留 quirk 删 narrative 部分
- `proxy_state.rs:852-861` — "Each test stages a tempdir…" 删；free-port 选择 rationale 留
- "Round 5" 引用（多处）改成 PR / commit message 引用

---

## 不修（false positive 或刻意设计）

- `process_alive` 自己（在 proxy_proc.rs:34）— canonical 实现，duplicate 在 commands_proxy.rs
- `port_is_bound` vs `port_reachable` — 语义不同（bind-probe vs connect-probe），已正确区分 + 文档化
- 测试 scaffolding (`sample_meta`, `temp_meta_path`, `build_inputs`) — test helpers 不算 duplicate
- Layer 1 / Layer 2 分层本身 — 设计对的；只有 path resolver 是漏掉的 cross-cutting

---

## 修复顺序建议

1. **Bug 类**（影响生产）：#1 process_alive EPERM、#3 sentinel /tmp、#4 TOCTOU exists pre-check
2. **Cleanup 类**（quality + 0 风险）：#5 const、#6 OrphanedPort helper、#10 doc 重复
3. **Perf 类**（measurable wins）：#7 stat 解析、#8 health probe、#9 lsof 短路
4. **Consolidation 类**（结构）：#2 path resolvers、#11 atomic_write
5. **Polish 类**（low ROI）：#12-#15

按 1→5 顺序推进，每步独立可 commit / 可 revert。

---

## Top 3 wins by impact（efficiency review 摘录）

1. **Drop redundant lsof in happy-path `compute_proxy_state`**（fix #9）— 省 ~10-20ms / state read，被 `proxy status / start / stop / restart` 都触发。
2. **Thread parsed `MetaV1` through `stop_proxy_locked`**（fix #2 关联）— 消除 double JSON parse + double `/proc/PID/stat` read。
3. **Reduce initial `http_health_ok` timeout in start poll**（fix #8）— 第一轮 500ms 浪费直接体现为 startup latency。
