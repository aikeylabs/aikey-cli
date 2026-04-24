//! CRF model validator (called by `release.sh` after `train_crf` produces a
//! new `data/crf-phase1.bin`).
//!
//! Measures end-to-end extraction recall / FP on the ablation spike v4.1 sample
//! corpus (5 dimensions × ~76 samples). Runs the FULL pipeline —
//! `rule::rule_extract` merged with `crf::extract` (same order as production
//! `parse.rs::run_parse_v2_rules`) — because a CRF regression manifests through
//! the combined candidate pool, not the CRF layer alone.
//!
//! Emits a JSON report on stdout with the shape consumed by `release.sh`:
//!   {
//!     "model_path": "data/crf-phase1.bin",
//!     "model_sha256": "...",
//!     "total_samples": 76,
//!     "metrics": {
//!       "per_dimension": {
//!         "holdout":      { "samples": 13, "recall": 0.92, "fp": 0 },
//!         "ood-apikey":   { ... },
//!         "ood-realworld": { ... },
//!         "ood-layouts":  { ... },
//!         "adversarial":  { "samples": 13, "recall": null, "fp": 3 }
//!       },
//!       "overall": { "recall": 0.88, "fp_adversarial": 3 }
//!     }
//!   }
//!
//! Exit code 0 on success regardless of metrics — release.sh does the
//! baseline comparison + user prompt, not this bin.

use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use aikeylabs_aikey_cli::commands_internal::parse::crf;
use aikeylabs_aikey_cli::commands_internal::parse::rule;
use serde::Deserialize;
use sha2::{Digest, Sha256};

// Schema 对齐 spike samples/*.jsonl 行格式 + crf.rs 里的 TrainSample 类似结构。
#[derive(Debug, Deserialize)]
struct Sample {
    #[allow(dead_code)]
    id: String,
    text: String,
    #[serde(default)]
    expected: Expected,
}

#[derive(Debug, Default, Deserialize)]
struct Expected {
    #[serde(default)]
    drafts: Vec<ExpectedDraft>,
}

#[derive(Debug, Default, Deserialize)]
struct ExpectedDraft {
    #[serde(default)] email: Option<String>,
    #[serde(default)] password_like: Option<String>,
    #[serde(default)] secret_like: Option<String>,
    #[serde(default)] url: Option<String>,
    #[serde(default)] base_url: Option<String>,
}

#[derive(Debug, Default, Clone)]
struct DimStats {
    samples: usize,
    expected_total: usize,
    hits: usize,
    /// 总 FP (rule + CRF 合并层), 等同于旧版单一 `fp` 字段。
    fp: usize,
    /// v4.2.1 per-layer 拆分:
    ///   - fp_rule:      规则层 (rule::rule_extract 含 title/anchored 等所有 sub-layers) 产出的 FP
    ///   - fp_crf_only:  CRF 独有的 FP (rule 层未命中,CRF 额外命中的)
    /// Why 要拆: adversarial FP 退化时能精确定位是规则 regex / title layer 改坏,
    /// 还是 CRF 模型退化;不拆时 baseline 只看得见总数,debug 很难回溯。
    fp_rule: usize,
    fp_crf_only: usize,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let model_path = parse_flag(&args, "--model")
        .unwrap_or_else(|| PathBuf::from("data/crf-phase1.bin"));
    let samples_dir = parse_flag(&args, "--samples")
        .unwrap_or_else(|| PathBuf::from("../workflow/CI/research/ablation/ablation-spike-v4.1/samples"));

    // Model file sanity check. Empty .bin 意味着 train_crf 未运行 —— 明确报错。
    let model_bytes = match fs::read(&model_path) {
        Ok(b) if b.is_empty() => {
            eprintln!("[validate-crf] ERROR: model file {} is empty — run train_crf first", model_path.display());
            process::exit(2);
        }
        Ok(b) => b,
        Err(e) => {
            eprintln!("[validate-crf] ERROR: read({}): {}", model_path.display(), e);
            process::exit(2);
        }
    };
    let model_sha256 = {
        let mut h = Sha256::new();
        h.update(&model_bytes);
        format!("{:x}", h.finalize())
    };

    // 5 维度样本集 (与 TITLE_ABLATION_REPORT 对齐)
    let dimensions = [
        ("holdout",        "holdout.jsonl"),
        ("ood-apikey",     "ood-apikey.jsonl"),
        ("ood-realworld",  "ood-realworld.jsonl"),
        ("ood-layouts",    "ood.jsonl"),  // spike 里这个文件存 layouts 维度
        ("adversarial",    "adversarial.jsonl"),
    ];

    let mut per_dim: Vec<(String, DimStats)> = Vec::new();
    for (name, filename) in &dimensions {
        let path = samples_dir.join(filename);
        let stats = eval_dimension(&path, *name == "adversarial");
        per_dim.push((name.to_string(), stats));
    }

    // Overall 指标: sum of hits / sum of expected across non-adv dims
    let mut total_hits = 0usize;
    let mut total_expected = 0usize;
    let mut adv_fp = 0usize;
    for (name, st) in &per_dim {
        if name == "adversarial" {
            adv_fp = st.fp;
        } else {
            total_hits += st.hits;
            total_expected += st.expected_total;
        }
    }
    let overall_recall = if total_expected > 0 {
        total_hits as f64 / total_expected as f64
    } else {
        0.0
    };

    // Emit JSON report (single line, release.sh 用 jq 提取)
    let per_dim_json: Vec<String> = per_dim.iter().map(|(name, st)| {
        let recall = if st.expected_total > 0 {
            format!("{:.4}", st.hits as f64 / st.expected_total as f64)
        } else {
            "null".to_string()
        };
        format!(
            r#""{}":{{"samples":{},"expected":{},"hits":{},"recall":{},"fp":{},"fp_rule":{},"fp_crf_only":{}}}"#,
            name, st.samples, st.expected_total, st.hits, recall, st.fp, st.fp_rule, st.fp_crf_only
        )
    }).collect();

    println!(
        r#"{{"model_path":"{}","model_sha256":"{}","total_samples":{},"metrics":{{"per_dimension":{{{}}},"overall":{{"recall":{:.4},"fp_adversarial":{}}}}}}}"#,
        model_path.display(),
        model_sha256,
        per_dim.iter().map(|(_, s)| s.samples).sum::<usize>(),
        per_dim_json.join(","),
        overall_recall,
        adv_fp
    );
}

fn parse_flag(args: &[String], flag: &str) -> Option<PathBuf> {
    let mut i = 1;
    while i < args.len() {
        if args[i] == flag {
            if i + 1 < args.len() {
                return Some(PathBuf::from(&args[i + 1]));
            }
        } else if let Some(p) = args[i].strip_prefix(&format!("{}=", flag)) {
            return Some(PathBuf::from(p));
        }
        i += 1;
    }
    None
}

fn eval_dimension(path: &Path, is_adversarial: bool) -> DimStats {
    let mut stats = DimStats::default();
    let content = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("[validate-crf] skip {} (not found)", path.display());
            return stats;
        }
    };

    for line in content.lines() {
        if line.trim().is_empty() { continue; }
        let sample: Sample = match serde_json::from_str(line) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[validate-crf] bad jsonl in {}: {}", path.display(), e);
                continue;
            }
        };
        stats.samples += 1;

        // Expected 字段集合(把 5 类字段扁平成一个 HashSet<String>)
        let mut expected_values: HashSet<String> = HashSet::new();
        for d in &sample.expected.drafts {
            if let Some(v) = &d.email         { expected_values.insert(v.clone()); }
            if let Some(v) = &d.password_like { expected_values.insert(v.clone()); }
            if let Some(v) = &d.secret_like   { expected_values.insert(v.clone()); }
            if let Some(v) = &d.url           { expected_values.insert(v.clone()); }
            if let Some(v) = &d.base_url      { expected_values.insert(v.clone()); }
        }
        stats.expected_total += expected_values.len();

        // 跑生产路径 = rule::rule_extract + crf::extract (同 parse.rs::run_parse_v2_rules)
        let rule_cands = rule::rule_extract(&sample.text);
        let rule_values: HashSet<String> = rule_cands.iter().map(|c| c.value.clone()).collect();
        // CRF 候选单独来(去重策略同 parse.rs:137-145);记录 rule 未命中的 CRF-only 子集
        let rule_seen_kv: HashSet<String> = rule_cands.iter()
            .map(|c| format!("{}\x00{}", c.kind.as_str(), c.value))
            .collect();
        let mut crf_only_values: HashSet<String> = HashSet::new();
        let mut all_values: HashSet<String> = rule_values.clone();
        for cc in crf::extract(&sample.text) {
            let key = format!("{}\x00{}", cc.kind.as_str(), cc.value);
            if !rule_seen_kv.contains(&key) {
                all_values.insert(cc.value.clone());
                if !rule_values.contains(&cc.value) {
                    crf_only_values.insert(cc.value.clone());
                }
            }
        }

        if is_adversarial {
            // Adversarial 样本 expected.drafts == [] → 任何 predicted 都是 FP。
            // 拆 rule/crf 维度:rule_values 是规则层贡献,crf_only 是 CRF 额外带入。
            // 注:同值被两层都命中时归规则层 (rule 优先级高)。
            let crf_only_fp = crf_only_values.len();
            let rule_fp = all_values.len().saturating_sub(crf_only_fp);
            stats.fp += all_values.len();
            stats.fp_rule += rule_fp;
            stats.fp_crf_only += crf_only_fp;
        } else {
            let hits = expected_values.intersection(&all_values).count();
            stats.hits += hits;
        }
    }

    stats
}
