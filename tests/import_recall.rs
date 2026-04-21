//! Stage 3 解析回归测试入口
//!
//! # Phase 1（本文件初始形态）
//! - 数据模型（与 ablation-spike 对齐）
//! - 测试集加载 + smoke 验证
//! - train_test_no_leak v1：text-level 隔离断言
//!
//! # Phase 2+ 填充
//! - evaluate_rule_only / evaluate_with_crf / evaluate_with_fasttext_crf
//! - 4 维度 recall + precision + F1 + adversarial FP 双轨门控
//! - fingerprint 分类准确率
//! - pipeline_e2e_golden：跑完整流水断言每条样本的 expected 字段
//!
//! # 资产
//! testdata/*.jsonl 从 `workflow/CI/research/ablation-spike/samples/` 1:1 迁移
//! - train.jsonl      — 30 条 CRF 训练样本（Stage 3 Phase 4 训练入口用）
//! - in_dist.jsonl    — 11 条同分布基线（源自 ablation-spike/holdout.jsonl）
//! - ood_layouts.jsonl — 12 条未见过排版泛化
//! - ood_apikey.jsonl — 15 条 API KEY provider 泛化
//! - ood_realworld.jsonl — 18 条真实用户排版
//! - adversarial.jsonl — 10 条 FP 控制语料

use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

// ============================================================
// 数据模型（对齐 ablation-spike/src/main.rs ExpectedRecord）
// ============================================================

#[derive(Debug, Clone, Deserialize)]
pub struct Sample {
    pub id: String,
    #[serde(rename = "type")]
    pub sample_type: String,
    pub text: String,
    pub expected: ExpectedDraft,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ExpectedDraft {
    #[serde(default)]
    pub drafts: Vec<ExpectedRecord>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ExpectedRecord {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub password_like: Option<String>,
    #[serde(default)]
    pub secret_like: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub base_url: Option<String>,
    /// Stage 3 Phase 2 可能需要；Phase 1 只在 schema 里占位
    #[serde(default, deserialize_with = "note_or_array")]
    pub note: Option<Vec<String>>,
    /// H 层 fingerprint 期望 provider id（来自 ood_apikey / ood_realworld 的 `expected_provider` 字段）
    #[serde(default)]
    pub expected_provider: Option<String>,
}

/// `note` 字段可以是 string 或 array — 兼容两种形态
fn note_or_array<'de, D>(de: D) -> Result<Option<Vec<String>>, D::Error>
where D: serde::Deserializer<'de>
{
    use serde::de::Error;
    let v = serde_json::Value::deserialize(de)?;
    match v {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(s) => Ok(Some(vec![s])),
        serde_json::Value::Array(arr) => {
            let strs: Result<Vec<String>, _> = arr.into_iter()
                .map(|e| match e {
                    serde_json::Value::String(s) => Ok(s),
                    other => Err(D::Error::custom(format!("note array item not string: {:?}", other))),
                })
                .collect();
            Ok(Some(strs?))
        }
        other => Err(D::Error::custom(format!("note must be string|array|null, got {:?}", other))),
    }
}

// ============================================================
// 加载器
// ============================================================

pub fn testdata_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("testdata")
}

pub fn load_samples(path: &Path) -> Vec<Sample> {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {} failed: {}", path.display(), e));
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .enumerate()
        .map(|(idx, line)| {
            serde_json::from_str::<Sample>(line)
                .unwrap_or_else(|e| panic!(
                    "parse {} line {} failed: {}\ncontent: {}",
                    path.display(), idx + 1, e, line
                ))
        })
        .collect()
}

// ============================================================
// Phase 1 smoke tests
// ============================================================

const EXPECTED_SIZES: &[(&str, usize)] = &[
    ("train.jsonl", 30),
    ("in_dist.jsonl", 11),
    ("ood_layouts.jsonl", 12),
    ("ood_apikey.jsonl", 15),
    ("ood_realworld.jsonl", 18),
    ("adversarial.jsonl", 10),
];

#[test]
fn load_samples_smoke() {
    // 6 个 jsonl 都能成功反序列化
    let dir = testdata_dir();
    for (file, _) in EXPECTED_SIZES {
        let samples = load_samples(&dir.join(file));
        assert!(!samples.is_empty() || *file == "adversarial.jsonl", "{} parsed 0 samples", file);
        // 每条 sample 有非空 id 和 type
        for s in &samples {
            assert!(!s.id.is_empty(), "{}: empty id", file);
            assert!(!s.sample_type.is_empty(), "{}: empty type for {}", file, s.id);
        }
    }
}

#[test]
fn sample_count_matches_ablation_spike_baseline() {
    // 迁移完整性：数量与 ablation-spike 基线一致
    let dir = testdata_dir();
    for (file, expected) in EXPECTED_SIZES {
        let samples = load_samples(&dir.join(file));
        assert_eq!(
            samples.len(), *expected,
            "{} has {} samples, expected {}",
            file, samples.len(), expected
        );
    }
}

#[test]
fn total_sample_count() {
    // 总数应该是 96（30 train + 66 test + adversarial）
    let dir = testdata_dir();
    let total: usize = EXPECTED_SIZES.iter()
        .map(|(f, _)| load_samples(&dir.join(f)).len())
        .sum();
    assert_eq!(total, 96, "total sample count drifted from baseline");
}

// ============================================================
// train_test_no_leak v1（Phase 1 文本级隔离断言）
//
// C1 评审要求：CRF 训练集必须与测试集零重叠。v1 只检查 text 字段精确匹配；
// Phase 4 CRF 接入后会升级到 v2：per-token 级也要求不泄漏（expected.secret_like
// / password_like 值不能出现在任何测试集的 expected 里）。
// ============================================================

#[test]
fn train_test_no_leak_v1_text_level() {
    let dir = testdata_dir();
    let train = load_samples(&dir.join("train.jsonl"));
    let train_texts: std::collections::HashSet<&str> = train.iter().map(|s| s.text.as_str()).collect();

    for (file, _) in EXPECTED_SIZES.iter().filter(|(f, _)| *f != "train.jsonl") {
        let test_set = load_samples(&dir.join(file));
        for s in &test_set {
            assert!(
                !train_texts.contains(s.text.as_str()),
                "LEAK: train text appears verbatim in {} sample '{}'", file, s.id
            );
        }
    }
}

#[test]
fn train_test_no_leak_v1_secret_value_level() {
    // 更强约束：训练样本里任何 expected.secret_like / password_like 值都不能出现在测试集的 expected 里。
    // 这确保 CRF 不会"记住"测试集的具体 token 值。
    let dir = testdata_dir();
    let train = load_samples(&dir.join("train.jsonl"));

    let mut train_secrets: std::collections::HashSet<String> = std::collections::HashSet::new();
    for s in &train {
        for r in &s.expected.drafts {
            if let Some(v) = &r.secret_like { train_secrets.insert(v.clone()); }
            if let Some(v) = &r.password_like { train_secrets.insert(v.clone()); }
        }
    }

    for (file, _) in EXPECTED_SIZES.iter().filter(|(f, _)| *f != "train.jsonl") {
        let test_set = load_samples(&dir.join(file));
        for s in &test_set {
            for r in &s.expected.drafts {
                if let Some(v) = &r.secret_like {
                    assert!(!train_secrets.contains(v),
                        "LEAK: secret value '{}' from {} sample '{}' also appears in train",
                        v, file, s.id);
                }
                if let Some(v) = &r.password_like {
                    assert!(!train_secrets.contains(v),
                        "LEAK: password value '{}' from {} sample '{}' also appears in train",
                        v, file, s.id);
                }
            }
        }
    }
}

// ============================================================
// expected_provider 覆盖率抽查（Phase 3 H 层正式准确率测试的前置）
// ============================================================

#[test]
fn expected_provider_labels_present_on_apikey_set() {
    // ood_apikey 设计上**混合**了"已知 provider"（带标签）和"未知/通用"（null 表示预期 unknown）
    // 两种样本。Phase 1 只要求至少 5 个样本有显式 provider 标签（保证 fingerprint
    // 分类器在 Phase 3 时有足够 ground-truth 样本可跑准确率门控）。
    let samples = load_samples(&testdata_dir().join("ood_apikey.jsonl"));
    let with_label = samples.iter()
        .filter(|s| s.expected.drafts.iter().any(|r| r.expected_provider.is_some()))
        .count();
    assert!(with_label >= 5,
        "expected_provider labeled samples must be ≥ 5 for fingerprint accuracy test; got {}/{}",
        with_label, samples.len());
}

#[test]
fn adversarial_samples_have_empty_drafts() {
    // 对抗样本按定义 expected.drafts 必须为空（否则不是对抗）
    let samples = load_samples(&testdata_dir().join("adversarial.jsonl"));
    for s in &samples {
        assert!(s.expected.drafts.is_empty(),
            "adversarial sample '{}' has non-empty drafts — not adversarial by definition", s.id);
    }
}

// ============================================================
// Phase 2: evaluate_rule_only + 4 维度双轨门控
// ============================================================
//
// 通过 `_internal parse` 子命令跑当前规则引擎 v2，统计 recall / precision / FP。
// 双轨门控（百分比 OR 绝对计数）：解决 97 样本下单次 miss 造成大百分比波动的问题。

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin;

/// 统计单个测试集的 recall + FP（用于 adversarial）
struct EvalResult {
    recall_hit: usize,
    recall_total: usize,
    /// 对抗样本的 FP 数（仅 adversarial.jsonl 有意义）
    adversarial_fp: usize,
    /// 具体 miss 明细（sample_id, kind, expected_value）
    misses: Vec<(String, String, String)>,
    /// 对抗样本 FP 明细（sample_id, kind, actual_value）
    adv_fp_items: Vec<(String, String, String)>,
}

fn run_parse_via_cli(text: &str) -> serde_json::Value {
    // 构造一个 vault_key_hex 占位（parse 不校验是否匹配 vault）
    let payload = serde_json::json!({
        "vault_key_hex": "0".repeat(64),
        "action": "parse",
        "payload": {"text": text}
    });
    // 用 cargo_bin 拿到已构建的 cli，不需要真实 vault
    let tmp = tempfile::TempDir::new().expect("tmp");
    let out = Command::new(cargo_bin("aikey"))
        .env("HOME", tmp.path())
        .current_dir(tmp.path())
        .args(["_internal", "parse", "--stdin-json"])
        .write_stdin(payload.to_string())
        .assert()
        .success()
        .get_output()
        .clone();
    let s = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(s.trim()).unwrap_or_else(|e| panic!("parse stdout failed: {} raw={}", e, s))
}

/// 对一个测试集跑 evaluate：比对 parse 输出 candidates 与 expected 字段
fn evaluate_rule_only(path: &std::path::Path) -> EvalResult {
    let samples = load_samples(path);
    let mut hit = 0usize;
    let mut total = 0usize;
    let mut adv_fp = 0usize;
    let mut misses = Vec::new();
    let mut adv_fp_items = Vec::new();

    for s in &samples {
        let response = run_parse_via_cli(&s.text);
        let cands = response["data"]["candidates"].as_array().cloned().unwrap_or_default();

        // 收集抽取到的 value，按 kind 分桶
        let mut found: std::collections::HashMap<String, std::collections::HashSet<String>> =
            std::collections::HashMap::new();
        for c in &cands {
            if let (Some(kind), Some(value)) = (c["kind"].as_str(), c["value"].as_str()) {
                found.entry(kind.to_string())
                    .or_default()
                    .insert(value.to_string());
            }
        }

        let is_adversarial = s.expected.drafts.is_empty();
        if is_adversarial {
            // 对抗样本：任何 **非 warn-tier** candidate 都是 FP。
            // Why 排除 warn：H 层 Fingerprint 把 UUID/short_hex 标 warn，UI 默认不
            // 勾选也不自动导入。用户看到橙色警示需主动确认 —— 不算"静默误导入"。
            for c in &cands {
                let tier = c["tier"].as_str().unwrap_or("unknown");
                if tier == "warn" { continue; }
                adv_fp += 1;
                if let (Some(k), Some(v)) = (c["kind"].as_str(), c["value"].as_str()) {
                    adv_fp_items.push((s.id.clone(), k.to_string(), v.to_string()));
                }
            }
            continue;
        }

        // 每个 expected 字段都加入 total；found 里有则 hit
        for r in &s.expected.drafts {
            let checks: &[(&str, &Option<String>)] = &[
                ("email", &r.email),
                ("url", &r.url),
                ("password_like", &r.password_like),
                ("secret_like", &r.secret_like),
                ("base_url", &r.base_url),
            ];
            for (kind, exp) in checks {
                if let Some(v) = exp.as_ref() {
                    total += 1;
                    // base_url 可在 found["url"] 里查（current rule 全归 url kind）
                    let mut matched = found.get(*kind).map(|s| s.contains(v)).unwrap_or(false);
                    if !matched && *kind == "base_url" {
                        matched = found.get("url").map(|s| s.contains(v)).unwrap_or(false);
                    }
                    if matched {
                        hit += 1;
                    } else {
                        misses.push((s.id.clone(), kind.to_string(), v.clone()));
                    }
                }
            }
        }
    }

    EvalResult { recall_hit: hit, recall_total: total, adversarial_fp: adv_fp, misses, adv_fp_items }
}

/// 双轨门控：recall 百分比 OR 绝对 miss 计数（任一成立即过）
fn assert_recall_dual_gate(
    label: &str,
    result: &EvalResult,
    min_recall: f64,
    max_miss: usize,
) {
    let miss = result.recall_total.saturating_sub(result.recall_hit);
    let rate = if result.recall_total == 0 { 1.0 }
               else { result.recall_hit as f64 / result.recall_total as f64 };
    assert!(
        rate >= min_recall || miss <= max_miss,
        "{}: recall {}/{} = {:.3} < {:.3} AND miss {} > {}",
        label, result.recall_hit, result.recall_total, rate, min_recall, miss, max_miss
    );
    eprintln!(
        "[{}] R={}/{}={:.1}% miss={} (gate: ≥{:.0}% OR ≤{})",
        label, result.recall_hit, result.recall_total, rate * 100.0,
        miss, min_recall * 100.0, max_miss
    );
}

#[test]
fn rule_v2_in_dist_recall_gate() {
    // in_dist 基线：双轨 recall ≥ 89% OR miss ≤ 2
    let r = evaluate_rule_only(&testdata_dir().join("in_dist.jsonl"));
    assert_recall_dual_gate("in_dist", &r, 0.89, 2);
}

#[test]
fn rule_v2_ood_layouts_recall_gate() {
    // OOD layouts：双轨 recall ≥ 95% OR miss ≤ 1
    let r = evaluate_rule_only(&testdata_dir().join("ood_layouts.jsonl"));
    assert_recall_dual_gate("ood_layouts", &r, 0.95, 1);
}

#[test]
fn rule_v2_ood_apikey_recall_gate() {
    let r = evaluate_rule_only(&testdata_dir().join("ood_apikey.jsonl"));
    assert_recall_dual_gate("ood_apikey", &r, 0.95, 1);
}

#[test]
fn rule_v2_ood_realworld_recall_gate() {
    let r = evaluate_rule_only(&testdata_dir().join("ood_realworld.jsonl"));
    assert_recall_dual_gate("ood_realworld", &r, 0.95, 1);
}

#[test]
fn rule_v2_adversarial_fp_accounting() {
    // Phase 2 设计目标：C1（纯规则层）在对抗样本上 0 FP。
    // Phase 4 接入 CRF 后，本测试被 `rule_v2_plus_crf_adversarial_fp_cap` 取代
    // （评估 C3 总 FP ≤ 1 的门控）。保留此测试 for 记录：当前管线的 FP 来源应可追溯。
    let r = evaluate_rule_only(&testdata_dir().join("adversarial.jsonl"));
    eprintln!("[adversarial_total_fp] {} items", r.adversarial_fp);
    for (id, kind, value) in &r.adv_fp_items {
        eprintln!("  {} {} = {}", id, kind, value);
    }
    // Phase 4 的总 FP 由 c3 门控保障；这里只是统计 / 观测
}

// ============================================================
// Phase 3: H 层 Provider Fingerprint 准确率门控
// ============================================================
//
// 对带 expected_provider 标签的样本，断言 parse 响应中的 candidate.provider.id
// 与期望一致（或消歧后一致）。双轨门控：accuracy ≥ 95% OR miss ≤ 1。

struct FingerprintEval {
    correct: usize,
    total_labeled: usize,
    /// 记录错判案例（sample_id, expected, actual, token）
    mismatches: Vec<(String, String, String, String)>,
}

fn evaluate_fingerprint(path: &std::path::Path) -> FingerprintEval {
    let samples = load_samples(path);
    let mut correct = 0;
    let mut total = 0;
    let mut mismatches = Vec::new();

    for s in &samples {
        // 只评估带 expected_provider 标签的 draft
        for r in &s.expected.drafts {
            let Some(expected) = r.expected_provider.as_ref() else { continue };
            let Some(expected_secret) = r.secret_like.as_ref() else { continue };
            total += 1;

            let response = run_parse_via_cli(&s.text);
            let cands = response["data"]["candidates"].as_array().cloned().unwrap_or_default();
            // 在 candidates 里找 value == expected_secret 的 secret_like 候选
            let hit = cands.iter().find(|c| {
                c["kind"].as_str() == Some("secret_like")
                    && c["value"].as_str() == Some(expected_secret.as_str())
            });

            let actual = hit
                .and_then(|c| c["provider"]["id"].as_str())
                .unwrap_or("<no_provider>")
                .to_string();

            // POC 两轨判定：
            // - 直接命中：actual == expected
            // - ambiguous 精化：expected 是 ambiguous 基类（如 generic_sk），
            //   而 classifier 用 URL 上下文精化到了它的 siblings 之一（如 moonshot_kimi），
            //   应判为 correct —— URL 上下文提供了更具体的 provider 信息，UI 展示更准
            //   （对应 POC `classify_with_context` 两轨：direct vs with_ctx）
            if is_valid_classification(expected, &actual) {
                correct += 1;
            } else {
                let display_tok = if expected_secret.len() > 40 {
                    format!("{}...", &expected_secret[..40])
                } else {
                    expected_secret.clone()
                };
                mismatches.push((s.id.clone(), expected.clone(), actual, display_tok));
            }
        }
    }

    FingerprintEval { correct, total_labeled: total, mismatches }
}

/// 判定分类是否 valid。接受精确匹配 + "ambiguous 基类 → siblings 精化"
fn is_valid_classification(expected: &str, actual: &str) -> bool {
    if expected == actual { return true; }
    // generic_sk 可被 URL 上下文精化为具体 provider（与 YAML siblings 字段对齐）
    if expected == "generic_sk" {
        return [
            "moonshot_kimi", "deepseek", "yunwu", "zeroeleven",
            "mistral", "siliconflow", "generic_other",
        ].contains(&actual);
    }
    // zhipu_glm 类似
    if expected == "zhipu_glm" {
        return ["bigmodel", "generic_other"].contains(&actual);
    }
    false
}

#[test]
fn fingerprint_accuracy_on_ood_apikey_gate() {
    let r = evaluate_fingerprint(&testdata_dir().join("ood_apikey.jsonl"));
    let miss = r.total_labeled.saturating_sub(r.correct);
    let rate = if r.total_labeled == 0 { 1.0 } else { r.correct as f64 / r.total_labeled as f64 };
    eprintln!("[fingerprint.ood_apikey] {}/{} = {:.1}% miss={}",
        r.correct, r.total_labeled, rate * 100.0, miss);
    for (id, exp, got, tok) in &r.mismatches {
        eprintln!("  ✗ {}  exp={}  got={}  tok={}", id, exp, got, tok);
    }
    assert!(
        rate >= 0.95 || miss <= 1,
        "fingerprint.ood_apikey accuracy {}/{} ({:.1}%) miss={}: gate ≥95% OR miss≤1",
        r.correct, r.total_labeled, rate * 100.0, miss
    );
}

#[test]
fn fingerprint_accuracy_on_ood_realworld_gate() {
    let r = evaluate_fingerprint(&testdata_dir().join("ood_realworld.jsonl"));
    let miss = r.total_labeled.saturating_sub(r.correct);
    let rate = if r.total_labeled == 0 { 1.0 } else { r.correct as f64 / r.total_labeled as f64 };
    eprintln!("[fingerprint.ood_realworld] {}/{} = {:.1}% miss={}",
        r.correct, r.total_labeled, rate * 100.0, miss);
    for (id, exp, got, tok) in &r.mismatches {
        eprintln!("  ✗ {}  exp={}  got={}  tok={}", id, exp, got, tok);
    }
    assert!(
        rate >= 0.95 || miss <= 1,
        "fingerprint.ood_realworld accuracy {}/{} ({:.1}%) miss={}: gate ≥95% OR miss≤1",
        r.correct, r.total_labeled, rate * 100.0, miss
    );
}

// ============================================================
// Phase 4: CRF + Shape Filter 门控
// ============================================================
//
// Phase 2 的 evaluate_rule_only 同时也覆盖 CRF（parse.rs 三层都跑）。
// Phase 4 关心的具体要求是：
//   1. C3 in-dist recall = 100%（CRF 救回规则漏掉的混合 hex secret）
//   2. adversarial FP ≤ 1（CRF shape filter 把 FP 压在容忍阈内）

#[test]
fn rule_v2_plus_crf_in_dist_recall_100() {
    // CRF 启用后，in-dist 期望 100%（而非 89.7%）
    // Why：Phase 2 的 in_dist miss 主要是 `d853aXYZ999` 这种中等长度混合 hex —— CRF 专门救这种
    let r = evaluate_rule_only(&testdata_dir().join("in_dist.jsonl"));
    eprintln!("[c3_in_dist] {}/{}={}%",
        r.recall_hit, r.recall_total,
        (r.recall_hit as f64 / r.recall_total as f64 * 100.0) as i64);
    for (id, kind, value) in &r.misses {
        eprintln!("  ✗ {} {} = {}", id, kind, value);
    }
    assert_eq!(
        r.recall_hit, r.recall_total,
        "C3 in-dist recall should be 100% (CRF rescues Layer 1 misses); got {}/{}",
        r.recall_hit, r.recall_total
    );
}

#[test]
fn rule_v2_plus_crf_adversarial_fp_cap() {
    // CRF 启用后，adversarial FP 双轨：0 理想；≤ 1 可接受（对应 ablation-spike C3 实测基线）
    let r = evaluate_rule_only(&testdata_dir().join("adversarial.jsonl"));
    eprintln!("[c3_adversarial] FP={}", r.adversarial_fp);
    for (id, kind, value) in &r.adv_fp_items {
        eprintln!("  ✗ {} {} = {}", id, kind, value);
    }
    assert!(
        r.adversarial_fp <= 1,
        "C3 adversarial FP = {} exceeds cap of 1 (shape filter regression?)", r.adversarial_fp
    );
}

// ============================================================
// Phase 6: pipeline_e2e_golden + fingerprint_coverage_audit
// ============================================================

#[test]
fn pipeline_e2e_golden_all_samples_full_recall() {
    // 端到端断言：对 97 样本里的每一条，parse 响应的 candidates 必须覆盖
    // expected.drafts 里所有非空字段（email / password_like / secret_like / url / base_url）。
    // adversarial 集合单独在 c3_adversarial 门控检验，此测试跳过。
    let files = ["in_dist.jsonl", "ood_layouts.jsonl", "ood_apikey.jsonl", "ood_realworld.jsonl"];
    let dir = testdata_dir();
    let mut total_expected = 0usize;
    let mut total_hit = 0usize;
    let mut sample_failures: Vec<String> = Vec::new();

    for file in files.iter() {
        let r = evaluate_rule_only(&dir.join(file));
        total_expected += r.recall_total;
        total_hit += r.recall_hit;
        for (id, kind, value) in r.misses {
            sample_failures.push(format!("{}:{} {}={}", file, id, kind, value));
        }
    }

    let rate = total_hit as f64 / total_expected as f64;
    eprintln!("[e2e_golden] total recall {}/{} = {:.2}%",
        total_hit, total_expected, rate * 100.0);
    for f in &sample_failures { eprintln!("  ✗ {}", f); }

    // Stage 3 Phase 4 退出基线：4 个正样本集综合 recall = 100%
    assert_eq!(
        total_hit, total_expected,
        "e2e golden recall shortfall: {}/{} (misses: {:?})",
        total_hit, total_expected, sample_failures
    );
}

#[test]
fn fingerprint_coverage_audit() {
    // N2 评审：遍历 YAML registry 里所有 provider id，统计多少被 testdata 的
    // expected_provider 字段覆盖。未覆盖的 confirmed-tier provider 必须在 registry
    // 里标注原因（或补样本）—— 此版本只做报告，不硬性阻断。

    // 解析 YAML（直接读文件，避免 cli 依赖）
    let yaml_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("data").join("provider_fingerprint.yaml");
    let yaml_text = std::fs::read_to_string(&yaml_path)
        .expect("provider_fingerprint.yaml missing");
    let yaml: serde_yaml::Value = serde_yaml::from_str(&yaml_text).expect("parse yaml");
    let providers = yaml["providers"].as_sequence().expect("providers array");
    let all_ids: Vec<(String, String)> = providers.iter()
        .filter_map(|p| {
            let id = p["id"].as_str()?.to_string();
            let tier = p["tier"].as_str()?.to_string();
            Some((id, tier))
        })
        .collect();

    // 收集 testdata 的 expected_provider 标签
    let mut covered: std::collections::HashSet<String> = std::collections::HashSet::new();
    let dir = testdata_dir();
    for file in ["in_dist.jsonl", "ood_layouts.jsonl", "ood_apikey.jsonl", "ood_realworld.jsonl"] {
        for s in load_samples(&dir.join(file)) {
            for r in &s.expected.drafts {
                if let Some(p) = &r.expected_provider {
                    covered.insert(p.clone());
                }
            }
        }
    }

    let mut uncovered_confirmed = Vec::new();
    let mut covered_count = 0;
    for (id, tier) in &all_ids {
        if covered.contains(id) {
            covered_count += 1;
        } else if tier == "confirmed" {
            uncovered_confirmed.push(id.clone());
        }
    }

    eprintln!("[fingerprint_coverage] {}/{} providers covered by testdata",
        covered_count, all_ids.len());
    eprintln!("  covered: {:?}", covered);
    if !uncovered_confirmed.is_empty() {
        eprintln!("  uncovered confirmed-tier providers (expect in Stage 3.1+ sample expansion):");
        for id in &uncovered_confirmed { eprintln!("    - {}", id); }
    }

    // Stage 3 Phase 4 不硬性要求 100% 覆盖（POC 样本是已知子集）。
    // 但至少 5 个 confirmed 必须被 covered 才能保证 Phase 3 准确率门控有代表性样本。
    let confirmed_covered = all_ids.iter()
        .filter(|(id, t)| t == "confirmed" && covered.contains(id))
        .count();
    assert!(confirmed_covered >= 5,
        "only {} confirmed-tier providers have testdata; need ≥5 for fingerprint gate validity",
        confirmed_covered);
}

#[test]
fn fingerprint_warn_tier_signal_for_uuid() {
    // APK-04 的 expected_provider 是 "uuid"（warn tier）；UI 需要拿到 warn 信号
    let samples = load_samples(&testdata_dir().join("ood_apikey.jsonl"));
    let apk04 = samples.iter().find(|s| s.id == "APK-04").expect("APK-04 exists");
    let response = run_parse_via_cli(&apk04.text);
    let cands = response["data"]["candidates"].as_array().cloned().unwrap_or_default();

    let uuid_val = "550e8400-e29b-41d4-a716-446655440000";
    let uuid_cand = cands.iter().find(|c| c["value"].as_str() == Some(uuid_val));
    if let Some(c) = uuid_cand {
        // candidate.tier 应该升级为 warn
        assert_eq!(c["tier"].as_str(), Some("warn"),
            "UUID candidate should have tier=warn, got: {:?}", c["tier"]);
        // provider.id 应该是 uuid
        assert_eq!(c["provider"]["id"].as_str(), Some("uuid"));
    }
    // 若规则层没抽取到 UUID，跳过（UUID 只在 label 锚点时才进 candidates）
}
