//! Third-party config guard — the ONE door through which aikey reads, writes,
//! removes and repairs content in configuration files it does NOT own
//! (`~/.codex/config.toml`, `~/.kimi/config.toml`, Claude Code `settings.json`,
//! the Claude Desktop profile).
//!
//! spec: R-third-party-config-guard-1 坏文件是一等状态，不得冒充其它状态
//! spec: R-third-party-config-guard-2 一切写盘经唯一守卫：先备份、结构化改、校验、原子写
//! spec: R-third-party-config-guard-3 修复只删 aikey 自有内容，坏文件只诊断不自动改
//! spec: R-third-party-config-guard-4 一句话三处共用
//! design: roadmap20260320/技术实现/阶段9-商业化版本/third-party-config-guard/design.md
//!   (DEC-third-party-config-guard-1 … -9)
//!
//! Why this module exists (2026-09-04 winpc2). `~/.codex/config.toml` carried a
//! duplicate top-level `model_provider` — invalid TOML. Detection collapsed
//! "cannot parse" into "our block is absent" and told the user to "activate an
//! OpenAI key first". Activating a key ran the writer, which refused the
//! unparseable file, printed one WARN to stderr (invisible from the tray) and
//! returned success. The user did that five times. Meanwhile `unuse` on the
//! same file took a TEXT-STRIP fallback: delete every line containing
//! `# managed by aikey`, plain `fs::write`, no backup, no verify. Five sandbox
//! replays showed neither path could fix the file; a third party rewriting it
//! did. Four surfaces had four private copies of these rules, with 21 places
//! where they disagreed. This module replaces all of them with:
//!
//!   read → strict parse (no healing) → classify → policy refusal →
//!   structural edit → render → byte-compare → versioned backup → verify
//!   (re-parse AND expected post-state) → the ONE atomic write → outcome.
//!
//! Invariants (each has a fence, see tests/third_party_write_guard_fence.rs):
//!   I1 product code writes these files only through `commit` below;
//!   I2 any byte change is preceded by a versioned backup that is never consumed;
//!   I3 an unparseable file is never touched by an automatic path;
//!   I6 one sentence per reason code, used byte-for-byte by every surface.

use std::path::{Path, PathBuf};

use serde::Serialize;

// ───────────────────────────── identity & policy ─────────────────────────────

/// The injection surfaces the guard knows. `as_str` matches the labels
/// `injected_provider_toml_paths()` has always emitted, so `aikey env`,
/// `hook repair <tool>` and the tray keep one vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SurfaceId {
    Codex,
    Kimi,
    Claude,
    ClaudeDesktop,
}

impl SurfaceId {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SurfaceId::Codex => "codex",
            SurfaceId::Kimi => "kimi",
            SurfaceId::Claude => "claude",
            SurfaceId::ClaudeDesktop => "claude-desktop",
        }
    }

    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "codex" => Some(SurfaceId::Codex),
            "kimi" => Some(SurfaceId::Kimi),
            "claude" => Some(SurfaceId::Claude),
            "claude-desktop" => Some(SurfaceId::ClaudeDesktop),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Format {
    Toml,
    Json,
}

impl Format {
    fn name(self) -> &'static str {
        match self {
            Format::Toml => "TOML",
            Format::Json => "JSON",
        }
    }
}

/// What `Merge` may do when the file is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreatePolicy {
    /// Create the directory and the file (kimi, codex — the tool tolerates an
    /// aikey-authored file with only our keys).
    CreateFileAndDir,
    /// The parent directory must already exist; never conjure the tool's home
    /// (claude settings.json).
    RequireParentDir,
    /// The application must be installed (Claude Desktop); never create.
    RequireInstalled,
}

/// What `Merge` may do when the surface's EXCLUSIVE slot is held by someone else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForeignPolicy {
    /// Refuse (claude statusLine owned by starship/ccusage…).
    Refuse,
    /// Take over with the user's consent, never delete their file (Claude
    /// Desktop, 07-10 rule 4).
    ClaimWithConsent,
    /// The surface has no exclusive slot (kimi hooks / codex provider block
    /// are additive; codex's top-level lever is a facet, see `CodexLever`).
    NotApplicable,
}

// ───────────────────────────────── state ─────────────────────────────────────

/// Position + message of a strict parse failure. `line`/`col` are 1-based.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParseFailure {
    pub line: Option<usize>,
    pub col: Option<usize>,
    pub msg: String,
}

/// The unified state of a third-party config file.
///
/// spec: R-third-party-config-guard-1 — `Unparseable` is its own variant and
/// MUST NOT be reported as any of the others (DEC-third-party-config-guard-1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TpConfigState {
    /// File (or, for Desktop, the app) is absent.
    Missing,
    /// File exists but does not parse. DIAGNOSE ONLY — every automatic path
    /// refuses; only `hook repair` (with confirmation) may touch it.
    Unparseable {
        error: String,
        line: Option<usize>,
        col: Option<usize>,
    },
    /// Parses; none of our owned keys present.
    PresentNoAikey,
    /// Parses; our footprint present and current.
    OursActive,
    /// Parses; something of ours is present but stale / partial / legacy-marker
    /// only. Still `has_ours()` so `unuse` can strip it (07-07: readers must not
    /// go blind after a third party re-serialises the file).
    OurResidue,
    /// Parses; the surface's exclusive slot is held by someone else.
    Foreign { owner: String },
    /// Desktop only: the install probe itself failed (Windows MSIX query).
    DetectionFailed { error: String },
}

impl TpConfigState {
    /// "Would `Remove` change bytes" — the detect⇔remove lockstep predicate.
    pub(crate) fn has_ours(&self) -> bool {
        matches!(self, TpConfigState::OursActive | TpConfigState::OurResidue)
    }

    pub(crate) fn is_unparseable(&self) -> bool {
        matches!(self, TpConfigState::Unparseable { .. })
    }

    /// Wire label used by `status --json` projections and `hook repair --json`.
    pub(crate) fn label(&self) -> &'static str {
        match self {
            TpConfigState::Missing => "missing",
            TpConfigState::Unparseable { .. } => "unparseable",
            TpConfigState::PresentNoAikey => "present_no_aikey",
            TpConfigState::OursActive => "ours_active",
            TpConfigState::OurResidue => "our_residue",
            TpConfigState::Foreign { .. } => "foreign",
            TpConfigState::DetectionFailed { .. } => "detection_failed",
        }
    }
}

/// Codex's top-level `model_provider` line — the desktop/IDE lever
/// (measured 2026-08-18: the one variable that flips file-only clients).
/// A FACET of the codex detection, not a sub-state: the provider block is
/// additive and can never be foreign; only this slot is exclusive
/// (DEC-third-party-config-guard-3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "lever", rename_all = "snake_case")]
pub enum CodexLever {
    On,
    Off,
    Foreign { value: String },
}

/// Everything a surface can tell about its file from ONE parsed document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Detection {
    pub state: TpConfigState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codex_lever: Option<CodexLever>,
    /// Loopback port written into the file's base_url, when it points at the
    /// local proxy. `None` on unparseable files — port-drift healing never
    /// touches a file it cannot read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_baseurl_port: Option<u16>,
    /// kimi only: the command of OUR Stop hook when present (so status can
    /// tell "wired" from "wired to a stale binary path").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kimi_hook_command: Option<String>,
}

impl Detection {
    pub(crate) fn of(state: TpConfigState) -> Self {
        Detection {
            state,
            codex_lever: None,
            local_baseurl_port: None,
            kimi_hook_command: None,
        }
    }
}

// ───────────────────────────── strict parsers ────────────────────────────────

/// 1-based (line, col) of a byte offset in `text`.
fn line_col_at(text: &str, offset: usize) -> (usize, usize) {
    let offset = offset.min(text.len());
    let before = &text[..offset];
    let line = before.matches('\n').count() + 1;
    let col = before
        .rsplit('\n')
        .next()
        .map(|s| s.chars().count())
        .unwrap_or(0)
        + 1;
    (line, col)
}

/// Strict TOML parse. No healing, no marker stripping — a file aikey cannot
/// parse is the user's file and aikey has no business guessing which lines to
/// drop (that guess deleted user lines in the sandbox replay, DEC-1).
pub fn parse_toml_strict(text: &str) -> Result<toml_edit::Document, ParseFailure> {
    let text = crate::strip_bom(text);
    text.parse::<toml_edit::Document>().map_err(|e| {
        let (line, col) = match e.span() {
            Some(span) => {
                let (l, c) = line_col_at(text, span.start);
                (Some(l), Some(c))
            }
            None => (None, None),
        };
        ParseFailure {
            line,
            col,
            msg: e.message().trim().to_string(),
        }
    })
}

/// Strict JSON parse (BOM-stripped — `claude_desktop::read_json_object` did
/// this, `commands_statusline::read_settings` did not; one reader now).
pub fn parse_json_strict(text: &str) -> Result<serde_json::Value, ParseFailure> {
    let text = crate::strip_bom(text);
    serde_json::from_str::<serde_json::Value>(text).map_err(|e| ParseFailure {
        line: Some(e.line()),
        col: Some(e.column()),
        msg: e.to_string(),
    })
}

// ───────────────────────────── reason & sentence ─────────────────────────────

/// One code per reason a guard operation stops. UPPER_SNAKE on the wire
/// (logging-conventions); the CODE is the machine contract, the sentence is
/// for people (08-16 T7: "句子给人读，码给机器").
// The `Tp` prefix is the wire contract, not noise: each variant maps 1:1 to a
// TP_* code on the wire (TpConfigUnparseable → "TP_CONFIG_UNPARSEABLE").
// Renaming to satisfy the lint would break that mapping.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasonCode {
    TpConfigUnparseable,
    TpConfigForeign,
    TpLeverForeign,
    TpBlockMissing,
    TpNotApplicable,
    TpDetectionFailed,
    TpBackupFailed,
    TpVerifyFailed,
    TpWriteFailed,
    TpRepairInsufficient,
    TpNoBackup,
    TpNeedsConfirmation,
}

impl ReasonCode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            ReasonCode::TpConfigUnparseable => "TP_CONFIG_UNPARSEABLE",
            ReasonCode::TpConfigForeign => "TP_CONFIG_FOREIGN",
            ReasonCode::TpLeverForeign => "TP_LEVER_FOREIGN",
            ReasonCode::TpBlockMissing => "TP_BLOCK_MISSING",
            ReasonCode::TpNotApplicable => "TP_NOT_APPLICABLE",
            ReasonCode::TpDetectionFailed => "TP_DETECTION_FAILED",
            ReasonCode::TpBackupFailed => "TP_BACKUP_FAILED",
            ReasonCode::TpVerifyFailed => "TP_VERIFY_FAILED",
            ReasonCode::TpWriteFailed => "TP_WRITE_FAILED",
            ReasonCode::TpRepairInsufficient => "TP_REPAIR_INSUFFICIENT",
            ReasonCode::TpNoBackup => "TP_NO_BACKUP",
            ReasonCode::TpNeedsConfirmation => "TP_NEEDS_CONFIRMATION",
        }
    }
}

/// Everything a sentence may mention. Built by the guard from a `Detection`
/// plus the file it looked at; the SAME ctx yields the SAME sentence whether
/// the write guard, `status --json` or `hook repair` asks
/// (spec: R-third-party-config-guard-4, fenced byte-for-byte).
#[derive(Debug, Clone, Default)]
pub struct ReasonCtx {
    pub surface: Option<SurfaceId>,
    /// Already user-facing (`~/.codex/config.toml`, `%USERPROFILE%\...`).
    pub path_display: String,
    pub format: Option<Format>,
    pub line: Option<usize>,
    pub col: Option<usize>,
    pub parser_msg: Option<String>,
    /// Newest aikey backup for the file, user-facing path.
    pub backup_display: Option<String>,
    /// The foreign owner / value (TP_CONFIG_FOREIGN, TP_LEVER_FOREIGN).
    pub owner: Option<String>,
    /// Free detail for the IO-class codes (backup/verify/write failed).
    pub detail: Option<String>,
}

impl ReasonCode {
    /// THE sentence. Do not build these words anywhere else — the source-scan
    /// fence forbids the literals outside this function.
    pub(crate) fn sentence(self, ctx: &ReasonCtx) -> String {
        let tool = ctx.surface.map(|s| s.as_str()).unwrap_or("<tool>");
        let fmt = ctx.format.map(|f| f.name()).unwrap_or("config");
        match self {
            ReasonCode::TpConfigUnparseable => {
                let at = match (ctx.line, ctx.col) {
                    (Some(l), Some(c)) => format!(" at line {l}:{c}"),
                    (Some(l), None) => format!(" at line {l}"),
                    _ => String::new(),
                };
                let why = ctx
                    .parser_msg
                    .as_deref()
                    .filter(|m| !m.is_empty())
                    .map(|m| format!(" ({m})"))
                    .unwrap_or_default();
                let backup = match &ctx.backup_display {
                    Some(b) => format!("Latest aikey backup: {b}."),
                    None => "No aikey backup exists.".to_string(),
                };
                let restore_hint = if ctx.backup_display.is_some() {
                    ", or --from-backup to restore the backup"
                } else {
                    ""
                };
                // JSON surfaces have no line-level "ours" to strip: the only
                // repairs are a backup restore or a hand edit.
                let repair = if ctx.format == Some(Format::Json) {
                    if ctx.backup_display.is_some() {
                        format!("Repair: 'aikey hook repair {tool} --from-backup' (restore the newest aikey backup), or fix the file by hand.")
                    } else {
                        "Repair: fix the file by hand (aikey has no backup of it to restore).".to_string()
                    }
                } else {
                    format!("Repair: 'aikey hook repair {tool} --strip-ours' (remove only aikey's own keys{restore_hint}).")
                };
                format!(
                    "{path} is not valid {fmt}{at}{why}; aikey left it untouched. {backup} {repair}",
                    path = ctx.path_display,
                )
            }
            ReasonCode::TpConfigForeign => format!(
                "{path} is managed by another tool ({owner}) — AiKey will not overwrite it.",
                path = ctx.path_display,
                owner = ctx.owner.as_deref().unwrap_or("unknown"),
            ),
            // Verbatim the sentence `set_codex_top_level_provider` has emitted
            // since 2026-08-18 (restore-fidelity) — the tray already renders it.
            ReasonCode::TpLeverForeign => format!(
                "Codex's model_provider is set to '{v}' (by you or another tool) — AiKey won't overwrite it. \
                 Remove that line from ~/.codex/config.toml first if you want AiKey to take over.",
                v = ctx.owner.as_deref().unwrap_or("?"),
            ),
            // Verbatim the 2026-08-18 precondition sentence — but now it is only
            // ever produced for a file that PARSES and truly lacks the block.
            ReasonCode::TpBlockMissing => "activate an OpenAI key first".to_string(),
            ReasonCode::TpNotApplicable => format!(
                "{path}: {why}",
                path = ctx.path_display,
                why = ctx
                    .detail
                    .as_deref()
                    .unwrap_or("the tool is not set up on this machine — open it once first"),
            ),
            ReasonCode::TpDetectionFailed => format!(
                "could not detect {tool}: {why}",
                why = ctx.detail.as_deref().unwrap_or("install query failed"),
            ),
            ReasonCode::TpBackupFailed => format!(
                "could not back up {path} before changing it ({why}); nothing was written.",
                path = ctx.path_display,
                why = ctx.detail.as_deref().unwrap_or("io error"),
            ),
            ReasonCode::TpVerifyFailed => format!(
                "refusing to write {path}: the result would not read back as expected ({why}); nothing was written.",
                path = ctx.path_display,
                why = ctx.detail.as_deref().unwrap_or("verification failed"),
            ),
            ReasonCode::TpWriteFailed => format!(
                "could not write {path} ({why}). A backup was taken first{backup}.",
                path = ctx.path_display,
                why = ctx.detail.as_deref().unwrap_or("io error"),
                backup = ctx
                    .backup_display
                    .as_deref()
                    .map(|b| format!(": {b}"))
                    .unwrap_or_default(),
            ),
            ReasonCode::TpRepairInsufficient => format!(
                "{path} still does not parse after removing everything aikey wrote{at}{why}; \
                 the remaining problem is not aikey's — fix it by hand{backup}.",
                path = ctx.path_display,
                at = match (ctx.line, ctx.col) {
                    (Some(l), Some(c)) => format!(" (line {l}:{c}"),
                    _ => " (".to_string(),
                },
                why = ctx
                    .parser_msg
                    .as_deref()
                    .map(|m| format!(": {m})"))
                    .unwrap_or_else(|| ")".to_string()),
                backup = ctx
                    .backup_display
                    .as_deref()
                    .map(|b| format!(", or restore the backup {b} with --from-backup"))
                    .unwrap_or_default(),
            ),
            ReasonCode::TpNoBackup => format!(
                "no aikey backup exists for {path}; --from-backup has nothing to restore.",
                path = ctx.path_display
            ),
            ReasonCode::TpNeedsConfirmation => format!(
                "repairing {path} would change it; re-run with --yes to confirm (the listed lines are what aikey removes).",
                path = ctx.path_display
            ),
        }
    }
}

// ───────────────────────────────── outcome ───────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TpAction {
    Merged,
    Removed,
    Created,
    Deleted,
    Unchanged,
    Refused,
    Failed,
    Restored,
    Stripped,
}

/// What one guard operation did. Rides `ThirdPartyApplyOutcome.surfaces`,
/// `LifecycleOutcome.third_party` and the `hook repair --json` envelope, so
/// callers with a wire obligation report it without re-detecting anything.
#[derive(Debug, Clone, Serialize)]
pub struct SurfaceOutcome {
    pub surface: SurfaceId,
    pub path: PathBuf,
    pub action: TpAction,
    pub state_before: TpConfigState,
    pub state_after: TpConfigState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<ReasonCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sentence: Option<String>,
}

impl SurfaceOutcome {
    pub(crate) fn refused(self) -> bool {
        matches!(self.action, TpAction::Refused | TpAction::Failed)
    }
}

// ───────────────────────────────── surface ───────────────────────────────────

pub enum TpOp<I> {
    Merge(I),
    Remove,
}

/// One injection surface. Adapters wrap the existing pure cores
/// (`codex_merge` / `codex_remove`, …) — they do not re-implement them.
pub trait Surface {
    type Doc;
    type Input;

    const ID: SurfaceId;
    const FORMAT: Format;
    const CREATE: CreatePolicy;
    const FOREIGN: ForeignPolicy;
    /// What `hook repair --strip-ours` may remove from a file that does NOT
    /// parse. `None` (JSON surfaces) = text repair is not offered; only
    /// `--from-backup` or a hand edit can fix such a file.
    const OWNED_GRAMMAR: Option<&'static OwnedTomlGrammar> = None;

    /// The file this surface owns keys in (Phase 1–3: exactly one file;
    /// Claude Desktop's four-file profile lands in Phase 4 with a multi-file
    /// commit that keeps its existing snapshot rollback).
    fn path(&self) -> PathBuf;

    /// Strict parse. `None` text = file absent → the surface returns an empty
    /// document if `CREATE` allows creating one.
    fn load(&self, text: &str) -> Result<Self::Doc, ParseFailure>;
    fn empty_doc(&self) -> Self::Doc;

    fn detect(&self, doc: &Self::Doc) -> Detection;
    fn merge(&self, doc: Self::Doc, input: &Self::Input) -> Result<Self::Doc, String>;
    fn remove(&self, doc: Self::Doc) -> Self::Doc;
    fn render(&self, doc: &Self::Doc) -> String;

    /// Merge-specific policy refusal beyond the generic ones (e.g. codex lever
    /// on a foreign value, block missing). `None` = proceed.
    fn refuse_merge(
        &self,
        _det: &Detection,
        _input: &Self::Input,
    ) -> Option<(ReasonCode, ReasonCtx)> {
        None
    }

    /// The post-state `verify` demands after each op.
    fn expected_after_merge(&self, det: &Detection, input: &Self::Input) -> bool;
    fn expected_after_remove(&self, det: &Detection) -> bool {
        !det.state.has_ours()
    }
}

/// What `inspect` returns: the detection plus where the file and its backups
/// are, so status projections and `hook repair` share one read.
#[derive(Debug, Clone)]
pub struct Inspection {
    pub surface: SurfaceId,
    pub path: PathBuf,
    pub detection: Detection,
    pub format: Format,
    /// Newest first. Versioned backups, then legacy single-slot ones.
    pub backups: Vec<PathBuf>,
}

impl Inspection {
    /// The sentence the status projection puts in `blocked_reason` for an
    /// unparseable file — identical to what the write guard printed.
    pub(crate) fn unparseable_sentence(&self) -> Option<String> {
        match &self.detection.state {
            TpConfigState::Unparseable { error, line, col } => {
                Some(ReasonCode::TpConfigUnparseable.sentence(&self.reason_ctx(
                    Some(error),
                    *line,
                    *col,
                )))
            }
            _ => None,
        }
    }

    pub(crate) fn reason_ctx(
        &self,
        parser_msg: Option<&str>,
        line: Option<usize>,
        col: Option<usize>,
    ) -> ReasonCtx {
        ReasonCtx {
            surface: Some(self.surface),
            path_display: display_for(&self.path),
            format: Some(self.format),
            line,
            col,
            parser_msg: parser_msg.map(|s| s.to_string()),
            backup_display: self.backups.first().map(|b| display_for(b)),
            owner: None,
            detail: None,
        }
    }
}

/// User-facing form of an absolute path under the home directory
/// (`~/.codex/config.toml` on Unix, `%USERPROFILE%\.codex\config.toml` on
/// Windows). Falls back to the absolute path outside the home.
pub fn display_for(path: &Path) -> String {
    let home = super::resolve_user_home();
    match path.strip_prefix(&home) {
        Ok(rel) => super::display_path(&rel.to_string_lossy()),
        Err(_) => path.display().to_string(),
    }
}

fn read_text(path: &Path) -> Option<String> {
    match std::fs::read(path) {
        Ok(bytes) => Some(String::from_utf8_lossy(&bytes).into_owned()),
        Err(_) => None,
    }
}

/// Read + strictly classify. Never writes.
pub fn inspect<S: Surface>(s: &S) -> Inspection {
    let path = s.path();
    let detection = match read_text(&path) {
        None => Detection::of(TpConfigState::Missing),
        Some(text) => match s.load(&text) {
            Ok(doc) => s.detect(&doc),
            Err(pf) => Detection::of(TpConfigState::Unparseable {
                error: pf.msg,
                line: pf.line,
                col: pf.col,
            }),
        },
    };
    Inspection {
        surface: S::ID,
        path: path.clone(),
        detection,
        format: S::FORMAT,
        backups: list_backups(&path),
    }
}

/// Merge or remove through the guard. Every step that can stop returns a
/// `Refused`/`Failed` outcome with a code + sentence; nothing is written
/// unless backup and verify both passed.
pub fn apply<S: Surface>(s: &S, op: TpOp<S::Input>) -> SurfaceOutcome {
    let path = s.path();
    let existing = read_text(&path);
    let was_absent = existing.is_none();

    // 1. strict parse / absent handling
    let doc = match &existing {
        None => match (S::CREATE, &op) {
            (CreatePolicy::CreateFileAndDir, TpOp::Merge(_)) => s.empty_doc(),
            (CreatePolicy::RequireParentDir, TpOp::Merge(_)) => {
                let parent_ok = path.parent().map(|p| p.is_dir()).unwrap_or(false);
                if parent_ok {
                    s.empty_doc()
                } else {
                    return stop(
                        s,
                        &path,
                        TpAction::Refused,
                        TpConfigState::Missing,
                        ReasonCode::TpNotApplicable,
                        ReasonCtx {
                            detail: Some(
                                "its directory does not exist — the tool has never run here".into(),
                            ),
                            ..ctx_for::<S>(&path, None, None)
                        },
                        None,
                    );
                }
            }
            (CreatePolicy::RequireInstalled, TpOp::Merge(_)) => {
                return stop(
                    s,
                    &path,
                    TpAction::Refused,
                    TpConfigState::Missing,
                    ReasonCode::TpNotApplicable,
                    ctx_for::<S>(&path, None, None),
                    None,
                );
            }
            (_, TpOp::Remove) => {
                // Nothing of ours can be in a file that does not exist.
                return SurfaceOutcome {
                    surface: S::ID,
                    path,
                    action: TpAction::Unchanged,
                    state_before: TpConfigState::Missing,
                    state_after: TpConfigState::Missing,
                    backup_path: None,
                    reason_code: None,
                    sentence: None,
                };
            }
        },
        Some(text) => match s.load(text) {
            Ok(d) => d,
            Err(pf) => {
                // I3: an unparseable file is never touched by an automatic path.
                let state = TpConfigState::Unparseable {
                    error: pf.msg.clone(),
                    line: pf.line,
                    col: pf.col,
                };
                let backups = list_backups(&path);
                let ctx = ReasonCtx {
                    parser_msg: Some(pf.msg),
                    line: pf.line,
                    col: pf.col,
                    backup_display: backups.first().map(|b| display_for(b)),
                    ..ctx_for::<S>(&path, None, None)
                };
                return stop(
                    s,
                    &path,
                    TpAction::Refused,
                    state,
                    ReasonCode::TpConfigUnparseable,
                    ctx,
                    None,
                );
            }
        },
    };

    // 2. classify + policy
    let before = s.detect(&doc);
    if let TpOp::Merge(input) = &op {
        if let TpConfigState::Foreign { owner } = &before.state {
            if S::FOREIGN == ForeignPolicy::Refuse {
                return stop(
                    s,
                    &path,
                    TpAction::Refused,
                    before.state.clone(),
                    ReasonCode::TpConfigForeign,
                    ReasonCtx {
                        owner: Some(owner.clone()),
                        ..ctx_for::<S>(&path, None, None)
                    },
                    None,
                );
            }
        }
        if let Some((code, ctx)) = s.refuse_merge(&before, input) {
            return stop(
                s,
                &path,
                TpAction::Refused,
                before.state.clone(),
                code,
                ctx,
                None,
            );
        }
    }

    // 3. structural edit
    let rendered_before = s.render(&doc);
    let (new_doc, action_if_changed) = match op {
        TpOp::Merge(ref input) => match s.merge(doc, input) {
            Ok(d) => (
                d,
                if was_absent {
                    TpAction::Created
                } else {
                    TpAction::Merged
                },
            ),
            Err(e) => {
                return stop(
                    s,
                    &path,
                    TpAction::Failed,
                    before.state.clone(),
                    ReasonCode::TpVerifyFailed,
                    ReasonCtx {
                        detail: Some(e),
                        ..ctx_for::<S>(&path, None, None)
                    },
                    None,
                )
            }
        },
        TpOp::Remove => (s.remove(doc), TpAction::Removed),
    };
    let rendered = s.render(&new_doc);

    // 4. byte compare → idempotent no-op
    let unchanged = match &existing {
        Some(text) => crate::strip_bom(text) == rendered.as_str() || rendered_before == rendered,
        None => false,
    };
    if unchanged {
        return SurfaceOutcome {
            surface: S::ID,
            path,
            action: TpAction::Unchanged,
            state_before: before.state.clone(),
            state_after: before.state,
            backup_path: None,
            reason_code: None,
            sentence: None,
        };
    }

    // 5. verify BEFORE touching disk: re-parse + expected post-state
    let delete_file = matches!(action_if_changed, TpAction::Removed) && rendered.trim().is_empty();
    if !delete_file {
        match s.load(&rendered) {
            Ok(reparsed) => {
                let after = s.detect(&reparsed);
                let ok = match &op {
                    TpOp::Merge(input) => s.expected_after_merge(&after, input),
                    TpOp::Remove => s.expected_after_remove(&after),
                };
                if !ok {
                    return stop(
                        s,
                        &path,
                        TpAction::Failed,
                        before.state.clone(),
                        ReasonCode::TpVerifyFailed,
                        ReasonCtx {
                            detail: Some(format!(
                                "post-state {} does not match the operation",
                                after.state.label()
                            )),
                            ..ctx_for::<S>(&path, None, None)
                        },
                        None,
                    );
                }
            }
            Err(pf) => {
                return stop(
                    s,
                    &path,
                    TpAction::Failed,
                    before.state.clone(),
                    ReasonCode::TpVerifyFailed,
                    ReasonCtx {
                        detail: Some(format!("rendered output does not parse: {}", pf.msg)),
                        ..ctx_for::<S>(&path, None, None)
                    },
                    None,
                );
            }
        }
    }

    // 6. backup (only when a file exists to back up)
    let backup_path = if existing.is_some() {
        match backup_versioned(&path) {
            Ok(b) => Some(b),
            Err(e) => {
                return stop(
                    s,
                    &path,
                    TpAction::Failed,
                    before.state.clone(),
                    ReasonCode::TpBackupFailed,
                    ReasonCtx {
                        detail: Some(e.to_string()),
                        ..ctx_for::<S>(&path, None, None)
                    },
                    None,
                );
            }
        }
    } else {
        None
    };

    // 7. the ONE write door
    let write = if delete_file {
        commit(&path, None)
    } else {
        // Preserve a leading BOM the file already had (restore-fidelity: we
        // do not strip what the user's tool wrote).
        let had_bom = existing
            .as_deref()
            .map(|t| t.starts_with('\u{feff}'))
            .unwrap_or(false);
        let bytes = if had_bom {
            format!("\u{feff}{rendered}")
        } else {
            rendered.clone()
        };
        commit(&path, Some(bytes.as_bytes()))
    };
    if let Err(e) = write {
        return stop(
            s,
            &path,
            TpAction::Failed,
            before.state.clone(),
            ReasonCode::TpWriteFailed,
            ReasonCtx {
                detail: Some(e.to_string()),
                backup_display: backup_path.as_deref().map(display_for),
                ..ctx_for::<S>(&path, None, None)
            },
            backup_path.clone(),
        );
    }

    let state_after = if delete_file {
        TpConfigState::Missing
    } else {
        s.load(&rendered)
            .map(|d| s.detect(&d).state)
            .unwrap_or(TpConfigState::PresentNoAikey)
    };
    SurfaceOutcome {
        surface: S::ID,
        path,
        action: if delete_file {
            TpAction::Deleted
        } else {
            action_if_changed
        },
        state_before: before.state,
        state_after,
        backup_path,
        reason_code: None,
        sentence: None,
    }
}

fn ctx_for<S: Surface>(path: &Path, line: Option<usize>, col: Option<usize>) -> ReasonCtx {
    ReasonCtx {
        surface: Some(S::ID),
        path_display: display_for(path),
        format: Some(S::FORMAT),
        line,
        col,
        ..Default::default()
    }
}

/// Build a refused/failed outcome, print the sentence (stderr, never
/// TTY-gated — 04-20's TTY-gated warning was drowned and forgotten) and emit
/// the structured event so the outage is greppable later.
fn stop<S: Surface>(
    _s: &S,
    path: &Path,
    action: TpAction,
    state: TpConfigState,
    code: ReasonCode,
    ctx: ReasonCtx,
    backup_path: Option<PathBuf>,
) -> SurfaceOutcome {
    let sentence = code.sentence(&ctx);
    emit_refused(S::ID, path, &state, code, &ctx, &sentence);
    SurfaceOutcome {
        surface: S::ID,
        path: path.to_path_buf(),
        action,
        state_before: state.clone(),
        state_after: state,
        backup_path,
        reason_code: Some(code),
        sentence: Some(sentence),
    }
}

fn emit_refused(
    surface: SurfaceId,
    path: &Path,
    state: &TpConfigState,
    code: ReasonCode,
    ctx: &ReasonCtx,
    sentence: &str,
) {
    use colored::Colorize;
    eprintln!("  {} {sentence}", "!".yellow());
    let mut extra = std::collections::BTreeMap::new();
    extra.insert(
        "tool",
        serde_json::Value::String(surface.as_str().to_string()),
    );
    extra.insert(
        "path",
        serde_json::Value::String(path.display().to_string()),
    );
    extra.insert(
        "state",
        serde_json::Value::String(state.label().to_string()),
    );
    if let Some(l) = ctx.line {
        extra.insert("line", serde_json::Value::from(l as u64));
    }
    if let Some(c) = ctx.col {
        extra.insert("col", serde_json::Value::from(c as u64));
    }
    if let Some(b) = &ctx.backup_display {
        extra.insert("backup", serde_json::Value::String(b.clone()));
    }
    crate::observability::write_log(
        crate::observability::Level::Warn,
        sentence,
        Some(crate::observability::EVENT_CLI_TP_CONFIG_REFUSED),
        Some(code.as_str()),
        None,
        extra,
    );
}

// ───────────────────────────── the one write door ────────────────────────────

/// Runtime witness for the ratchet fence: behavioural suites assert this does
/// not move on refusals. Test-only so it costs nothing in production.
#[cfg(test)]
pub(crate) static TP_COMMITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// I1 — the only place product code writes (or deletes) a third-party
/// config file. `None` = delete. Goes through `profile_activation::atomic_write`
/// (temp + rename, with the Windows transient-rename retry budget).
pub(crate) fn commit(path: &Path, bytes: Option<&[u8]>) -> std::io::Result<()> {
    #[cfg(test)]
    TP_COMMITS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    match bytes {
        Some(b) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            crate::profile_activation::atomic_write(path, b)
        }
        None => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        },
    }
}

// ─────────────────────────────── backups ─────────────────────────────────────

/// Retention: keep the oldest (the pre-aikey original) plus the newest
/// `KEEP_NEWEST` per file (design.md 拍板默认，可推翻).
const KEEP_NEWEST: usize = 9;

/// Versioned copy: `<file>.aikey_backup_<unix_ts>[_NN]`. Generalised from the
/// shell-rc `backup_rc_file` (the one multi-slot backup this codebase had).
/// Never overwrites, never renames the original, prunes by retention.
pub fn backup_versioned(path: &Path) -> std::io::Result<PathBuf> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let base = format!("{}.aikey_backup_{}", path.display(), secs);
    let mut candidate = PathBuf::from(&base);
    let mut n: u32 = 0;
    while candidate.exists() {
        n += 1;
        candidate = PathBuf::from(format!("{}_{:02}", base, n));
    }
    std::fs::copy(path, &candidate)?;
    prune_backups(path);
    Ok(candidate)
}

/// Versioned backups for `path`, newest first, followed by the legacy
/// single-slot names (`config.aikey_backup.toml` / `settings.aikey_backup.json`)
/// which are kept only as `--from-backup` candidates.
pub fn list_backups(path: &Path) -> Vec<PathBuf> {
    let mut versioned = versioned_backups(path);
    versioned.reverse(); // newest first
    let legacy = legacy_single_slot(path);
    if let Some(l) = legacy {
        if l.exists() {
            versioned.push(l);
        }
    }
    versioned
}

/// Oldest first.
fn versioned_backups(path: &Path) -> Vec<PathBuf> {
    let Some(parent) = path.parent() else {
        return Vec::new();
    };
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return Vec::new();
    };
    let prefix = format!("{name}.aikey_backup_");
    let mut out: Vec<(u64, u32, PathBuf)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(parent) {
        for entry in rd.flatten() {
            let fname = entry.file_name();
            let Some(f) = fname.to_str() else { continue };
            let Some(rest) = f.strip_prefix(&prefix) else {
                continue;
            };
            let (ts, nn) = match rest.split_once('_') {
                Some((t, n)) => (t.parse::<u64>().ok(), n.parse::<u32>().ok()),
                None => (rest.parse::<u64>().ok(), Some(0)),
            };
            if let (Some(ts), Some(nn)) = (ts, nn) {
                out.push((ts, nn, entry.path()));
            }
        }
    }
    out.sort();
    out.into_iter().map(|(_, _, p)| p).collect()
}

fn legacy_single_slot(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?.to_str()?;
    let (stem, ext) = name.rsplit_once('.')?;
    Some(path.with_file_name(format!("{stem}.aikey_backup.{ext}")))
}

fn prune_backups(path: &Path) {
    let all = versioned_backups(path); // oldest first
    if all.len() <= KEEP_NEWEST + 1 {
        return;
    }
    // keep index 0 (oldest) and the last KEEP_NEWEST
    let drop_end = all.len() - KEEP_NEWEST;
    for p in &all[1..drop_end] {
        let _ = std::fs::remove_file(p);
    }
}

// ───────────────────────── repair: owned-text stripping ──────────────────────

/// The only text-level mutation in the codebase, and it runs only under
/// `hook repair --strip-ours` (backup first, confirmation, verify after).
/// Keyed on aikey's OWN key grammar — never on `# managed by aikey` literals,
/// which deleted user lines in the 2026-09-04 sandbox replay.
pub struct OwnedTomlGrammar {
    /// Top-level `key = "value"` lines that are ours when the value predicate
    /// holds (`model_provider` == "aikey"; `openai_base_url` ends with "/openai").
    pub top_level_scalars: &'static [(&'static str, fn(&str) -> bool)],
    /// `[table.header]` spans we own, header to next header/EOF.
    pub table_headers: &'static [&'static str],
    /// `[[hooks]]` blocks whose `command` contains this marker are ours.
    pub hooks_command_marker: Option<&'static str>,
    /// Legacy `# BEGIN aikey` … `# END aikey` region (pre-toml_edit installs).
    pub region: Option<(&'static str, &'static str)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StripPlan {
    /// 1-based line numbers removed, with their text (for the preview — never
    /// echoed with values redacted here because these are OUR lines only).
    pub removed: Vec<(usize, String)>,
    pub result: String,
}

fn is_header(line: &str) -> bool {
    line.trim_start().starts_with('[')
}

fn scalar_value(line: &str, key: &str) -> Option<String> {
    let t = line.trim_start();
    let rest = t.strip_prefix(key)?.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

pub fn strip_owned_text(text: &str, g: &OwnedTomlGrammar) -> StripPlan {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let mut drop = vec![false; lines.len()];

    // (c) legacy region span
    if let Some((begin, end)) = g.region {
        let mut inside = false;
        for (i, l) in lines.iter().enumerate() {
            if l.contains(begin) {
                inside = true;
            }
            if inside {
                drop[i] = true;
            }
            if inside && l.contains(end) {
                inside = false;
            }
        }
    }

    // (a) top-level scalars — only before the first header
    let first_header = lines
        .iter()
        .position(|l| is_header(l))
        .unwrap_or(lines.len());
    for (i, l) in lines.iter().enumerate().take(first_header) {
        for (key, pred) in g.top_level_scalars {
            if let Some(v) = scalar_value(l, key) {
                if pred(&v) {
                    drop[i] = true;
                }
            }
        }
    }

    // (b) table spans we own + (b') [[hooks]] blocks carrying our marker
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i];
        let t = l.trim();
        let owned_table = g.table_headers.iter().any(|h| t == format!("[{h}]"));
        let is_hooks = t == "[[hooks]]";
        if owned_table || is_hooks {
            let mut j = i + 1;
            while j < lines.len() && !is_header(lines[j]) {
                j += 1;
            }
            // Keep the blank line(s) that separate our table from the next
            // header — they are the user's layout, not our content.
            let span_end = j;
            while j > i + 1 && lines[j - 1].trim().is_empty() {
                j -= 1;
            }
            let span_is_ours = owned_table
                || g.hooks_command_marker
                    .map(|m| lines[i..j].iter().any(|x| x.contains(m)))
                    .unwrap_or(false);
            if span_is_ours {
                for k in i..j {
                    drop[k] = true;
                }
            }
            i = span_end;
        } else {
            i += 1;
        }
    }

    let mut removed = Vec::new();
    let mut result = String::with_capacity(text.len());
    for (i, l) in lines.iter().enumerate() {
        if drop[i] {
            removed.push((i + 1, l.trim_end_matches(['\r', '\n']).to_string()));
        } else {
            result.push_str(l);
        }
    }
    StripPlan { removed, result }
}

// ──────────────────────────────── repair ─────────────────────────────────────

/// `aikey hook repair <tool>` modes. spec: R-third-party-config-guard-3
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairMode {
    /// Report only. Never writes.
    Diagnose,
    /// Remove ONLY aikey's own keys. Parseable file → the structural `Remove`
    /// (same as `unuse`); unparseable file → `strip_owned_text` (the one
    /// text-level path), and only if the result parses.
    StripOurs,
    /// Copy the newest aikey backup (or the given file) over the config.
    /// Copies, never renames: backups are never consumed.
    FromBackup(Option<PathBuf>),
}

#[derive(Debug, Clone, Serialize)]
pub struct RepairReport {
    pub surface: SurfaceId,
    pub path: PathBuf,
    pub state: TpConfigState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codex_lever: Option<CodexLever>,
    pub backups: Vec<PathBuf>,
    /// Sentence for an unparseable file — byte-identical to the one the
    /// write guard printed and `status --json` carries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sentence: Option<String>,
    /// Lines a `--strip-ours` would remove (1-based, our lines only).
    pub preview: Vec<(usize, String)>,
    /// Set for every mode but `Diagnose`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<SurfaceOutcome>,
}

impl RepairReport {
    /// CLI exit code: 0 done / unchanged / diagnosed, 2 refused, 1 IO failure.
    pub fn exit_code(&self) -> i32 {
        match self.outcome.as_ref().map(|o| o.action) {
            Some(TpAction::Refused) => 2,
            Some(TpAction::Failed) => 1,
            _ => 0,
        }
    }
}

/// Diagnose / repair through the same door as `apply`. `confirmed = false`
/// runs everything up to (not including) the write and returns
/// `TP_NEEDS_CONFIRMATION` with the preview filled in — the CLI shows that
/// preview and asks; GUI callers pass `--yes` because their click is the
/// consent (same class as the tray takeover switch).
pub fn repair<S: Surface>(s: &S, mode: RepairMode, confirmed: bool) -> RepairReport {
    let insp = inspect(s);
    let mut report = RepairReport {
        surface: insp.surface,
        path: insp.path.clone(),
        state: insp.detection.state.clone(),
        codex_lever: insp.detection.codex_lever.clone(),
        backups: insp.backups.clone(),
        sentence: insp.unparseable_sentence(),
        preview: Vec::new(),
        outcome: None,
    };
    let path = insp.path.clone();
    let (parse_line, parse_col, parse_msg) = match &insp.detection.state {
        TpConfigState::Unparseable { error, line, col } => (*line, *col, Some(error.clone())),
        _ => (None, None, None),
    };
    let refuse = |code: ReasonCode, detail: Option<String>, state: TpConfigState| {
        let mut ctx = insp.reason_ctx(parse_msg.as_deref(), parse_line, parse_col);
        ctx.detail = detail;
        stop(s, &path, TpAction::Refused, state, code, ctx, None)
    };
    // The consent gate is not a refusal: nothing went wrong, the caller just
    // has not said yes. It is returned silently (no stderr, no WARN event) so
    // the CLI can show the preview FIRST and then ask; a GUI passes `--yes`.
    let consent_gate = |state: TpConfigState| SurfaceOutcome {
        surface: S::ID,
        path: path.clone(),
        action: TpAction::Refused,
        state_before: state.clone(),
        state_after: state,
        backup_path: None,
        reason_code: Some(ReasonCode::TpNeedsConfirmation),
        sentence: Some(
            ReasonCode::TpNeedsConfirmation.sentence(&insp.reason_ctx(None, None, None)),
        ),
    };

    match mode {
        RepairMode::Diagnose => report,
        RepairMode::StripOurs => {
            if insp.detection.state == TpConfigState::Missing {
                report.outcome = Some(refuse(
                    ReasonCode::TpNotApplicable,
                    Some("the file does not exist; nothing to repair".into()),
                    TpConfigState::Missing,
                ));
                return report;
            }
            if !insp.detection.state.is_unparseable() {
                // A file that reads fine has nothing to REPAIR. Removing
                // aikey's configuration from a healthy file is `hook
                // uninstall <tool>` / `unuse` — a different verb with its own
                // consent; doing it under "repair" would un-route the CLI
                // when the user only wanted a broken file fixed. Refused,
                // bytes untouched (tray: T_NOTHING_TO_REPAIR is the same rule).
                report.outcome = Some(refuse(
                    ReasonCode::TpNotApplicable,
                    Some(format!(
                        "the file reads fine — nothing to repair. To remove aikey's configuration from it run `aikey hook uninstall {}`",
                        S::ID.as_str()
                    )),
                    insp.detection.state.clone(),
                ));
                return report;
            }
            let Some(grammar) = S::OWNED_GRAMMAR else {
                report.outcome = Some(refuse(
                    ReasonCode::TpNotApplicable,
                    Some(format!(
                        "{} files cannot be repaired by removing text; restore an aikey backup with --from-backup or fix the file by hand",
                        S::FORMAT.name()
                    )),
                    insp.detection.state.clone(),
                ));
                return report;
            };
            let Some(text) = read_text(&path) else {
                report.outcome = Some(refuse(
                    ReasonCode::TpDetectionFailed,
                    Some("could not read the file".into()),
                    insp.detection.state.clone(),
                ));
                return report;
            };
            // Keep a leading BOM exactly as found (the file is "valid with BOM").
            let (bom, body) = match text.strip_prefix('\u{feff}') {
                Some(b) => ("\u{feff}", b),
                None => ("", text.as_str()),
            };
            let plan = strip_owned_text(body, grammar);
            report.preview = plan.removed.clone();
            let insufficient = |pf: Option<ParseFailure>, report: &mut RepairReport| {
                let mut ctx = insp.reason_ctx(parse_msg.as_deref(), parse_line, parse_col);
                if let Some(pf) = pf {
                    ctx.line = pf.line;
                    ctx.col = pf.col;
                    ctx.parser_msg = Some(pf.msg);
                }
                report.outcome = Some(stop(
                    s,
                    &path,
                    TpAction::Refused,
                    insp.detection.state.clone(),
                    ReasonCode::TpRepairInsufficient,
                    ctx,
                    None,
                ));
            };
            if plan.removed.is_empty() {
                insufficient(None, &mut report);
                return report;
            }
            let doc = match s.load(&plan.result) {
                Ok(d) => d,
                Err(pf) => {
                    insufficient(Some(pf), &mut report);
                    return report;
                }
            };
            let expected_after = s.detect(&doc);
            if !confirmed {
                report.outcome = Some(consent_gate(insp.detection.state.clone()));
                return report;
            }
            let backup = match backup_versioned(&path) {
                Ok(b) => b,
                Err(e) => {
                    report.outcome = Some(refuse(
                        ReasonCode::TpBackupFailed,
                        Some(e.to_string()),
                        insp.detection.state.clone(),
                    ));
                    return report;
                }
            };
            let bytes = format!("{bom}{}", plan.result);
            if let Err(e) = commit(&path, Some(bytes.as_bytes())) {
                let mut ctx = insp.reason_ctx(None, None, None);
                ctx.detail = Some(e.to_string());
                ctx.backup_display = Some(display_for(&backup));
                report.outcome = Some(stop(
                    s,
                    &path,
                    TpAction::Failed,
                    insp.detection.state.clone(),
                    ReasonCode::TpWriteFailed,
                    ctx,
                    Some(backup),
                ));
                return report;
            }
            report.outcome = Some(SurfaceOutcome {
                surface: S::ID,
                path,
                action: TpAction::Stripped,
                state_before: insp.detection.state.clone(),
                state_after: expected_after.state,
                backup_path: Some(backup),
                reason_code: None,
                sentence: None,
            });
            report
        }
        RepairMode::FromBackup(explicit) => {
            let candidate = explicit.or_else(|| insp.backups.first().cloned());
            let Some(candidate) = candidate else {
                report.outcome = Some(refuse(
                    ReasonCode::TpNoBackup,
                    None,
                    insp.detection.state.clone(),
                ));
                return report;
            };
            let Some(backup_text) = read_text(&candidate) else {
                report.outcome = Some(refuse(
                    ReasonCode::TpNoBackup,
                    Some(format!("{} cannot be read", candidate.display())),
                    insp.detection.state.clone(),
                ));
                return report;
            };
            let doc = match s.load(&backup_text) {
                Ok(d) => d,
                Err(pf) => {
                    report.outcome = Some(refuse(
                        ReasonCode::TpVerifyFailed,
                        Some(format!(
                            "the backup {} does not parse ({})",
                            display_for(&candidate),
                            pf.msg
                        )),
                        insp.detection.state.clone(),
                    ));
                    return report;
                }
            };
            let expected_after = s.detect(&doc);
            if read_text(&path).as_deref() == Some(backup_text.as_str()) {
                report.outcome = Some(SurfaceOutcome {
                    surface: S::ID,
                    path,
                    action: TpAction::Unchanged,
                    state_before: insp.detection.state.clone(),
                    state_after: insp.detection.state.clone(),
                    backup_path: None,
                    reason_code: None,
                    sentence: None,
                });
                return report;
            }
            if !confirmed {
                report.outcome = Some(consent_gate(insp.detection.state.clone()));
                return report;
            }
            let pre = if path.exists() {
                match backup_versioned(&path) {
                    Ok(b) => Some(b),
                    Err(e) => {
                        report.outcome = Some(refuse(
                            ReasonCode::TpBackupFailed,
                            Some(e.to_string()),
                            insp.detection.state.clone(),
                        ));
                        return report;
                    }
                }
            } else {
                None
            };
            if let Err(e) = commit(&path, Some(backup_text.as_bytes())) {
                let mut ctx = insp.reason_ctx(None, None, None);
                ctx.detail = Some(e.to_string());
                ctx.backup_display = pre.as_ref().map(|b| display_for(b));
                report.outcome = Some(stop(
                    s,
                    &path,
                    TpAction::Failed,
                    insp.detection.state.clone(),
                    ReasonCode::TpWriteFailed,
                    ctx,
                    pre,
                ));
                return report;
            }
            report.outcome = Some(SurfaceOutcome {
                surface: S::ID,
                path,
                action: TpAction::Restored,
                state_before: insp.detection.state.clone(),
                state_after: expected_after.state,
                backup_path: pre,
                reason_code: None,
                sentence: None,
            });
            report
        }
    }
}

// ────────────────────────────────── tests ────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_toml_reports_line_and_col_of_duplicate_key() {
        let text = "a = 1\nmodel_provider = \"aikey\"\nb = 2\nmodel_provider = \"pingtoken\"\n";
        let err = parse_toml_strict(text).expect_err("duplicate key must fail");
        assert_eq!(err.line, Some(4), "{err:?}");
        assert!(err.col.is_some());
        assert!(!err.msg.is_empty());
    }

    #[test]
    fn bom_is_stripped_before_parsing() {
        assert!(parse_toml_strict("\u{feff}a = 1\n").is_ok());
        assert!(parse_json_strict("\u{feff}{\"a\":1}").is_ok());
    }

    #[test]
    fn unparseable_sentence_names_path_position_backup_and_repair_command() {
        let ctx = ReasonCtx {
            surface: Some(SurfaceId::Codex),
            path_display: "~/.codex/config.toml".into(),
            format: Some(Format::Toml),
            line: Some(7),
            col: Some(1),
            parser_msg: Some("duplicate key `model_provider`".into()),
            backup_display: None,
            ..Default::default()
        };
        let s = ReasonCode::TpConfigUnparseable.sentence(&ctx);
        for needle in [
            "~/.codex/config.toml",
            "line 7:1",
            "duplicate key",
            "No aikey backup exists",
            "aikey hook repair codex --strip-ours",
        ] {
            assert!(s.contains(needle), "missing {needle:?} in {s}");
        }
    }

    #[test]
    fn strip_removes_only_owned_spans_and_keeps_user_provider() {
        const G: OwnedTomlGrammar = OwnedTomlGrammar {
            top_level_scalars: &[
                ("model_provider", |v| v == "aikey"),
                ("openai_base_url", |v| v.ends_with("/openai")),
            ],
            table_headers: &["model_providers.aikey"],
            hooks_command_marker: None,
            region: Some(("# BEGIN aikey", "# END aikey")),
        };
        let text = "model_provider = \"aikey\"\nopenai_base_url = \"http://127.0.0.1:27200/openai\"\n\
                    model_provider = \"pingtoken\"\n\n[model_providers.pingtoken]\nname = \"PingToken\"\n\n\
                    [model_providers.aikey]\nname = \"aikey\"\nbase_url = \"http://127.0.0.1:27200/openai\"\n\n\
                    [features]\nx = 1\n";
        let plan = strip_owned_text(text, &G);
        assert!(plan.result.contains("model_provider = \"pingtoken\""));
        assert!(plan.result.contains("[model_providers.pingtoken]"));
        assert!(plan.result.contains("[features]"));
        assert!(!plan.result.contains("model_providers.aikey"));
        assert!(!plan.result.contains("model_provider = \"aikey\""));
        assert!(!plan.result.contains("openai_base_url"));
        assert_eq!(plan.removed.len(), 5, "{:?}", plan.removed);
    }

    #[test]
    fn versioned_backup_never_overwrites_and_prunes_to_retention() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("config.toml");
        std::fs::write(&f, "a = 1\n").unwrap();
        let mut made = Vec::new();
        for _ in 0..(KEEP_NEWEST + 3) {
            made.push(backup_versioned(&f).unwrap());
        }
        let left = versioned_backups(&f);
        assert_eq!(left.len(), KEEP_NEWEST + 1, "oldest + newest {KEEP_NEWEST}");
        assert_eq!(
            left.first(),
            made.first(),
            "the oldest (pre-aikey) copy survives"
        );
        assert!(f.exists(), "the original is never renamed away");
    }
}
