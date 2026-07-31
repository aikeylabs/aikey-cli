//! Locating a chain by route group (openspec change
//! `aliyun-aigw-p0-upstream-fallback`, tasks 4.37 / 4.38, invariant I44).
//!
//! # 🔴 The problem templates created
//!
//! Before route groups became org-level templates, a group and a chain were 1:1 —
//! naming the group named the chain. A template can now be used by SEVERAL of this
//! employee's keys, so "use the main chain" may identify **two** chains: different
//! credentials, different quotas, and **different accounts to bill**.
//!
//! Picking one silently is the failure this module exists to prevent, and it is a
//! quiet one: the request succeeds. Nothing is logged, nothing errors — an entire
//! session's usage simply lands on another key, which usually means another team's
//! bill. Guessing wrong here does not fail; it just charges somebody else.
//!
//! # 🔴 Why the shorthand is kept anyway
//!
//! `--group <name>` alone resolves whenever exactly one key uses that group, which
//! is the overwhelming majority of cases. Forcing two coordinates on every user
//! forever would push our modelling complexity onto them (八级法则 第 3 级: UX
//! outranks maintenance convenience). The rule is not "always be explicit", it is
//! **never guess**: unambiguous resolves, ambiguous fails loudly with the exact
//! command that disambiguates.

/// One cached chain row, reduced to what selection needs.
///
/// Deliberately NOT the full vault entry: this module is pure so its rules can be
/// tested without a database, and the rules are where the mistakes live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainRow {
    pub virtual_key_id: String,
    /// What the user would type — the local alias if set, else the server alias.
    pub key_alias: String,
    pub protocol_type: String,
    pub route_group_name: String,
    pub provider_code: String,
    /// 1 = primary. Ordering decisions use this, never row order.
    pub priority: i64,
}

/// One key that uses the requested group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub virtual_key_id: String,
    pub key_alias: String,
    pub protocol_type: String,
    /// The chain in try order, e.g. `["anthropic", "zhipu"]`. Shown when a
    /// selection is ambiguous, because two chains from the same template can
    /// still differ in which credentials they hold.
    pub chain: Vec<String>,
}

/// What `--group` (with or without `--key`) resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// Exactly one key. Carries the alias so the caller runs its normal path.
    Resolved {
        key_alias: String,
        virtual_key_id: String,
    },
    /// No key on this machine uses that group.
    NoSuchGroup {
        requested: String,
        known: Vec<String>,
    },
    /// 🔴 Several keys use it. The caller must FAIL and print the candidates.
    Ambiguous {
        requested: String,
        candidates: Vec<Candidate>,
    },
    /// `--key` was given but that key does not use that group.
    KeyNotInGroup {
        key: String,
        requested: String,
        groups_of_key: Vec<String>,
    },
    /// `--key` was given and matches nothing on this machine.
    NoSuchKey { key: String },
}

/// Resolve a `(key, group)` selection.
///
/// `key` is the alias the user typed, or `None` for the one-coordinate shorthand.
/// Matching is case-insensitive on both coordinates: an operator reading a group
/// name off a console screen should not be defeated by capitalisation.
pub fn resolve(rows: &[ChainRow], key: Option<&str>, group: &str) -> Selection {
    let eq = |a: &str, b: &str| a.eq_ignore_ascii_case(b.trim());

    if let Some(k) = key {
        let key_rows: Vec<&ChainRow> = rows.iter().filter(|r| eq(&r.key_alias, k)).collect();
        if key_rows.is_empty() {
            return Selection::NoSuchKey { key: k.to_string() };
        }
        if !key_rows.iter().any(|r| eq(&r.route_group_name, group)) {
            let mut groups: Vec<String> = key_rows
                .iter()
                .filter(|r| !r.route_group_name.is_empty())
                .map(|r| r.route_group_name.clone())
                .collect();
            groups.sort();
            groups.dedup();
            return Selection::KeyNotInGroup {
                key: k.to_string(),
                requested: group.to_string(),
                groups_of_key: groups,
            };
        }
        let row = key_rows
            .iter()
            .find(|r| eq(&r.route_group_name, group))
            .expect("checked above");
        return Selection::Resolved {
            key_alias: row.key_alias.clone(),
            virtual_key_id: row.virtual_key_id.clone(),
        };
    }

    let candidates = candidates_for(rows, group);
    match candidates.len() {
        0 => Selection::NoSuchGroup {
            requested: group.to_string(),
            known: known_groups(rows),
        },
        1 => Selection::Resolved {
            key_alias: candidates[0].key_alias.clone(),
            virtual_key_id: candidates[0].virtual_key_id.clone(),
        },
        // 🔴 Two or more. 🚫 Never "take the first": the rows arrive in whatever
        // order the vault returned them, so "first" is not even a stable choice —
        // and the cost of choosing wrong is billing somebody else's team.
        _ => Selection::Ambiguous {
            requested: group.to_string(),
            candidates,
        },
    }
}

/// Every key using `group`, each with its chain in try order.
pub fn candidates_for(rows: &[ChainRow], group: &str) -> Vec<Candidate> {
    let mut keys: Vec<(String, String, String)> = rows
        .iter()
        .filter(|r| r.route_group_name.eq_ignore_ascii_case(group.trim()))
        .map(|r| {
            (
                r.virtual_key_id.clone(),
                r.key_alias.clone(),
                r.protocol_type.clone(),
            )
        })
        .collect();
    keys.sort();
    keys.dedup();

    keys.into_iter()
        .map(|(vk, alias, protocol)| {
            let mut hops: Vec<&ChainRow> = rows
                .iter()
                .filter(|r| r.virtual_key_id == vk && r.protocol_type == protocol)
                .collect();
            // Sort by priority, never by the order rows happened to come back in.
            hops.sort_by_key(|r| r.priority);
            Candidate {
                virtual_key_id: vk,
                key_alias: alias,
                protocol_type: protocol,
                chain: hops.iter().map(|r| r.provider_code.clone()).collect(),
            }
        })
        .collect()
}

/// Group names present on this machine, for the "no such group" message.
///
/// A bare "not found" leaves the user guessing whether they mistyped the name or
/// the key was never delivered here — two different next actions.
pub fn known_groups(rows: &[ChainRow]) -> Vec<String> {
    let mut names: Vec<String> = rows
        .iter()
        .filter(|r| !r.route_group_name.is_empty())
        .map(|r| r.route_group_name.clone())
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Render `Selection` as the error a user should see, or `None` when resolved.
///
/// Kept beside the rules so the message and the branch that produces it cannot
/// drift apart, and so the wording itself is testable.
pub fn failure_message(sel: &Selection) -> Option<String> {
    match sel {
        Selection::Resolved { .. } => None,
        Selection::NoSuchGroup { requested, known } => Some(if known.is_empty() {
            format!(
                "No route group named '{}' on this machine.\n  \
                 In fact no key here belongs to a route group yet — run `aikey key sync` \
                 first, or ask an administrator to issue a key from one.",
                requested
            )
        } else {
            format!(
                "No route group named '{}' on this machine.\n  Available: {}",
                requested,
                known.join(", ")
            )
        }),
        Selection::Ambiguous {
            requested,
            candidates,
        } => {
            let mut msg = format!(
                "Route group '{}' is used by {} of your keys, so the group name alone does not \
                 say which chain you mean.\n  \
                 {} These are DIFFERENT keys — different credentials, different quota, and usage \
                 is billed to different owners. Naming one is required:\n",
                requested,
                candidates.len(),
                // Through the symbols table, not inline: a bare emoji renders as a
                // box on the Win10 default console font, and the one line the user
                // MUST read would be the one that looks broken.
                crate::symbols::WARN.s()
            );
            for c in candidates {
                msg.push_str(&format!(
                    "    aikey use --key {} --group {}   ({}: {})\n",
                    shell_arg(&c.key_alias),
                    shell_arg(requested),
                    c.protocol_type,
                    if c.chain.is_empty() {
                        "no upstreams".to_string()
                    } else {
                        c.chain.join(" → ")
                    }
                ));
            }
            Some(msg)
        }
        Selection::KeyNotInGroup {
            key,
            requested,
            groups_of_key,
        } => Some(if groups_of_key.is_empty() {
            format!(
                "Key '{}' does not use route group '{}' — it belongs to no route group at all.",
                key, requested
            )
        } else {
            format!(
                "Key '{}' does not use route group '{}'.\n  It uses: {}",
                key,
                requested,
                groups_of_key.join(", ")
            )
        }),
        Selection::NoSuchKey { key } => Some(format!(
            "'{}' is not a key on this machine. Run `aikey key list` to see what is here.",
            key
        )),
    }
}

/// Render a chain as `P1 anthropic → F1 zhipu → F2 selfgw` (task 4.39).
///
/// 🔴 The role label is DERIVED from position (I19) and never read from a stored
/// field. Two independently writable sources can always be driven into "first in
/// line, labelled F1", and no reader could then say which one the runtime obeyed.
///
/// Input is sorted here rather than trusted: the vault returns rows in whatever
/// order SQLite chose, and the order IS the content of this feature.
pub fn chain_line(hops: &[ChainRow]) -> String {
    let mut sorted: Vec<&ChainRow> = hops.iter().collect();
    sorted.sort_by_key(|r| r.priority);
    sorted
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let role = if i == 0 {
                "P1".to_string()
            } else {
                format!("F{}", i)
            };
            format!("{} {}", role, r.provider_code)
        })
        .collect::<Vec<_>>()
        .join(" \u{2192} ")
}

/// Quote a value so the printed command is one the user can actually paste.
///
/// 🔴 Group names contain spaces routinely — "main chain" is the shape an admin
/// types. Printing `--group main chain` hands the user a command that parses
/// `chain` as a second positional argument and fails with a message about
/// something else entirely. An error whose remedy does not run is worse than one
/// that only describes the problem, because it costs the user a second round trip
/// to discover the remedy was wrong.
fn shell_arg(v: &str) -> String {
    if v.is_empty()
        || v.chars()
            .any(|c| c.is_whitespace() || "\"'\\$`".contains(c))
    {
        format!("'{}'", v.replace('\'', r"'\''"))
    } else {
        v.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(vk: &str, alias: &str, group: &str, provider: &str, priority: i64) -> ChainRow {
        ChainRow {
            virtual_key_id: vk.into(),
            key_alias: alias.into(),
            protocol_type: "anthropic".into(),
            route_group_name: group.into(),
            provider_code: provider.into(),
            priority,
        }
    }

    fn two_keys_one_template() -> Vec<ChainRow> {
        vec![
            row("vk-eng", "eng-key", "main chain", "anthropic", 1),
            row("vk-eng", "eng-key", "main chain", "zhipu", 2),
            row("vk-data", "data-key", "main chain", "anthropic", 1),
            row("vk-data", "data-key", "main chain", "zhipu", 2),
        ]
    }

    // 🔴 The whole reason this module exists (I44). Two keys share a template, so
    // the group name identifies two chains — and picking one would succeed, log
    // nothing, and bill another team for the session.
    #[test]
    fn shorthand_fails_loudly_when_two_keys_share_a_template() {
        let sel = resolve(&two_keys_one_template(), None, "main chain");
        match &sel {
            Selection::Ambiguous { candidates, .. } => {
                assert_eq!(candidates.len(), 2, "both keys must be listed");
            }
            other => panic!("expected Ambiguous, got {:?}", other),
        }
        let msg = failure_message(&sel).expect("ambiguity must produce an error");
        assert!(
            msg.contains("--key eng-key --group 'main chain'")
                && msg.contains("--key data-key --group 'main chain'"),
            "the message must hand the user the exact commands, not just say 'ambiguous':\n{}",
            msg
        );
        assert!(
            msg.contains("billed"),
            "the consequence has to be stated — the failure mode is a silent mis-bill:\n{}",
            msg
        );
    }

    // The shorthand is kept because it is right almost always; forcing two
    // coordinates forever would push our modelling complexity onto the user.
    #[test]
    fn shorthand_resolves_when_only_one_key_uses_the_group() {
        let rows = vec![
            row("vk-eng", "eng-key", "main chain", "anthropic", 1),
            row("vk-eng", "eng-key", "main chain", "zhipu", 2),
            row("vk-data", "data-key", "other chain", "anthropic", 1),
        ];
        assert_eq!(
            resolve(&rows, None, "main chain"),
            Selection::Resolved {
                key_alias: "eng-key".into(),
                virtual_key_id: "vk-eng".into()
            }
        );
    }

    // Two coordinates always work — that is the guarantee that makes the
    // shorthand safe to keep.
    #[test]
    fn two_coordinates_always_resolve() {
        let rows = two_keys_one_template();
        assert_eq!(
            resolve(&rows, Some("data-key"), "main chain"),
            Selection::Resolved {
                key_alias: "data-key".into(),
                virtual_key_id: "vk-data".into()
            }
        );
    }

    #[test]
    fn case_and_padding_do_not_defeat_a_name_read_off_a_screen() {
        let rows = two_keys_one_template();
        assert!(matches!(
            resolve(&rows, Some("ENG-KEY"), "  Main Chain "),
            Selection::Resolved { .. }
        ));
    }

    #[test]
    fn ambiguity_lists_each_chain_in_try_order() {
        // Rows deliberately supplied out of order: "first row wins" must never be
        // what decides anything here.
        let rows = vec![
            row("vk-a", "a-key", "g", "zhipu", 2),
            row("vk-a", "a-key", "g", "anthropic", 1),
            row("vk-b", "b-key", "g", "selfgw", 3),
            row("vk-b", "b-key", "g", "anthropic", 1),
            row("vk-b", "b-key", "g", "zhipu", 2),
        ];
        let cands = candidates_for(&rows, "g");
        assert_eq!(cands.len(), 2);
        let a = cands.iter().find(|c| c.key_alias == "a-key").unwrap();
        assert_eq!(a.chain, vec!["anthropic", "zhipu"]);
        let b = cands.iter().find(|c| c.key_alias == "b-key").unwrap();
        assert_eq!(b.chain, vec!["anthropic", "zhipu", "selfgw"]);
    }

    #[test]
    fn unknown_group_names_what_is_available() {
        let rows = two_keys_one_template();
        let sel = resolve(&rows, None, "nope");
        let msg = failure_message(&sel).unwrap();
        assert!(
            msg.contains("main chain"),
            "listing what IS here separates 'typo' from 'never delivered':\n{}",
            msg
        );
    }

    #[test]
    fn no_groups_at_all_says_so_rather_than_listing_nothing() {
        let rows = vec![row("vk", "k", "", "anthropic", 1)];
        let msg = failure_message(&resolve(&rows, None, "anything")).unwrap();
        assert!(
            msg.contains("aikey key sync"),
            "an empty 'Available:' list is a dead end; give the next action:\n{}",
            msg
        );
    }

    #[test]
    fn a_key_outside_the_group_is_told_which_groups_it_does_use() {
        let rows = vec![
            row("vk-a", "a-key", "alpha", "anthropic", 1),
            row("vk-b", "b-key", "beta", "anthropic", 1),
        ];
        let msg = failure_message(&resolve(&rows, Some("a-key"), "beta")).unwrap();
        assert!(msg.contains("alpha"), "{}", msg);
    }

    // 🔴 The remedy has to be runnable. A group called "main chain" printed bare
    // gives `--group main chain`, where the shell hands `chain` to the parser as a
    // stray positional and the user gets an error about something else — a second
    // wrong turn caused by the message that was supposed to fix the first.
    // 🔴 Task 4.39: the roles come from POSITION, so a chain handed over in the
    // wrong order still prints P1 first — and the labels cannot disagree with the
    // sequence, because there is only one source for both.
    #[test]
    fn chain_line_derives_roles_from_position_after_sorting() {
        let hops = vec![
            row("vk", "k", "g", "selfgw", 3),
            row("vk", "k", "g", "anthropic", 1),
            row("vk", "k", "g", "zhipu", 2),
        ];
        assert_eq!(
            chain_line(&hops),
            "P1 anthropic \u{2192} F1 zhipu \u{2192} F2 selfgw"
        );
    }

    #[test]
    fn chain_line_of_one_hop_is_just_the_primary() {
        assert_eq!(
            chain_line(&[row("vk", "k", "g", "anthropic", 1)]),
            "P1 anthropic"
        );
    }

    #[test]
    fn the_suggested_command_survives_a_group_name_with_spaces() {
        let sel = resolve(&two_keys_one_template(), None, "main chain");
        let msg = failure_message(&sel).unwrap();
        assert!(
            msg.contains("--group 'main chain'"),
            "the group name must be quoted so the printed command can be pasted:\n{}",
            msg
        );
    }

    #[test]
    fn a_name_needing_no_quotes_is_left_alone() {
        let rows = vec![
            row("vk-a", "a-key", "prod", "anthropic", 1),
            row("vk-b", "b-key", "prod", "anthropic", 1),
        ];
        let msg = failure_message(&resolve(&rows, None, "prod")).unwrap();
        assert!(msg.contains("--group prod"), "{}", msg);
        assert!(
            !msg.contains("--group 'prod'"),
            "no needless quoting:\n{}",
            msg
        );
    }

    #[test]
    fn an_unknown_key_is_not_reported_as_a_group_problem() {
        let rows = two_keys_one_template();
        assert_eq!(
            resolve(&rows, Some("ghost"), "main chain"),
            Selection::NoSuchKey {
                key: "ghost".into()
            }
        );
    }
}
