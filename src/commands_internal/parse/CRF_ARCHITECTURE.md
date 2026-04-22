# CRF 接入架构对比 · V4.1 spike ↔ aikey-cli

**状态**:v4.1 parity Stage 2e 研究文档
**最后更新**:2026-04-22

## 两种 CRF 接入方式

### V4.1 spike (`workflow/CI/research/ablation-spike-v4.1/`)

**架构**:**arbiter tie-break** (精度守门员)

```
rule_extract_anchored::for each anchor line:
  tokens = tokenize_line(line)
  crf_tags = crf_tag_line(tokens)            <- 一次性 per-line 推理
  for idx, tok in tokens:
    if claimed || shape_reject { suppress; continue }
    if crf_tags[idx] == "O"       { suppress "crf_rejected_O"; continue }
    if crf_tags[idx] == "B-LABEL" { suppress "crf_rejected_LABEL"; continue }
    if crf_tags[idx] in [B-PWD, B-SECRET, B-KEY]:
       push tier=crf_review, status=Review
    else:
       push tier=rule, status=Active
```

**语义**:
- CRF 只在 rule shape filter 放行后介入
- CRF `O` / `B-LABEL` 是**拒识信号** —— 覆盖规则判断
- CRF `B-PWD/B-SECRET/B-KEY` 是**review-tier 信号** —— UI 默认不勾
- CRF **不扩展召回**,只调精度

### aikey-cli (`src/commands_internal/parse/crf.rs`)

**架构**:**additive pass** (独立补充层)

```
commands_internal/parse.rs::handle:
  cands = rule::rule_extract(text)            <- 规则层完成
  for crf_cand in crf::extract(text):          <- 独立 CRF 扫描
    if rule_seen.contains(crf_cand.value): continue
    cands.push(crf_cand with tier=Suggested)
```

**语义**:
- CRF 独立跑一遍全文,每个 `candidate_line` 行都 tokenize + tag
- CRF tag 为 `B-*` 的 token 作为**新候选** push 进去
- `Tier::Suggested` 等同 v4.1 的 `crf_review`(UI 默认不勾)
- CRF **扩展召回**(补规则漏检),**不做拒识**

## 差异表

| 维度 | V4.1 arbiter | CLI additive | 对齐策略 |
|---|---|---|---|
| CRF 默认开启 | ✓ (owner 决策 #2) | ✓ (parse.rs L120 无条件) | **一致** |
| 精度守门 | ✓ (O/B-LABEL 拒识) | ✗ | **未对齐** — 需改造 |
| 扩展召回 | ✗ | ✓ (B-* 补新候选) | CLI 强;V4.1 弱 |
| review tier | ✓ (B-PWD/SECRET/KEY) | ✓ (Tier::Suggested) | 语义一致 |
| 调用位置 | rule_extract_anchored 内联 | parse.rs handle 外层 | 结构性差异 |
| 每行推理次数 | 1 (tag_line per anchor) | 1 (tag_line per candidate_line) | 性能对等 |

## 后续迁移路径 (v1.1+)

若要达成 V4.1 arbiter 精度守门的效果,需:

### 选项 A: 在 rule_anchored.rs 内联 CRF tie-break

1. `crf.rs` 暴露 `pub fn tag_line(tokens: &[String]) -> Vec<String>` API
2. `rule_anchored.rs::extract` 内,对每 anchor 行调 `tag_line`,对每 token:
   - CRF `O` / `B-LABEL` → 不 push(或 push 带 suppress_reason)
   - CRF `B-PWD` → push Kind::PasswordLike, Tier::Suggested
   - CRF `B-KEY/B-SECRET` → push Kind::SecretLike, Tier::Suggested
   - Else → 规则判定继续
3. 保留 `crf::extract()` 作为兜底(处理 rule_anchored 之外的 candidate_line),
   或完全移除(取决于是否要保留 additive 召回能力)

**成本**: 1-2 day,涉及 rule_anchored 和 crf.rs 重构 + 测试 fixture 调整

### 选项 B: 保持现状,接受语义差异

- CLI 的 additive CRF 召回能力实际更强(补了规则漏检)
- CLI 缺的 "精度守门" 功能可以用其他方式补(如 YAML context_reject_labels 扩展)
- V4.1 spike 的 arbiter 策略是研究阶段的选择,生产上 additive 未必差

**成本**: 0, 但 v41_spike_baseline.json 的数字对齐需要妥协

## 当前 Stage 2e 决策

**结论**: 配置层面已对齐(CRF 默认开启);**架构层面保持 CLI 现有 additive 模式**。

选项 A 的 arbiter 改造列入 v1.1+ backlog,见 `KNOWN_ISSUES.md` 或继任迁移计划。

---

**相关文件**:
- `crf.rs` — CLI CRF 实现
- `rule_anchored.rs` — Layer 4 anchored password/secret 抽取
- `v41_guards.rs` — Stage 2a-2d 引入的守门工具
- `commands_internal/parse.rs` — parse 主入口,CRF 调用点 L120
- V4.1 spike main.rs:482-556 — arbiter tie-break 原型代码
