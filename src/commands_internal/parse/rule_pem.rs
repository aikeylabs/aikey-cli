//! PEM 多行块提取（Layer 3）
//!
//! 覆盖：
//! - `-----BEGIN OPENSSH PRIVATE KEY-----` ... `-----END OPENSSH PRIVATE KEY-----`
//! - `-----BEGIN RSA PRIVATE KEY-----` ...
//! - `-----BEGIN PRIVATE KEY-----` ...（PKCS#8）
//! - `-----BEGIN PGP PRIVATE KEY BLOCK-----` ...
//! - `-----BEGIN CERTIFICATE-----` / `DH PARAMETERS` / 任何 `[A-Z ]+`
//!
//! # 注意
//! - `[\s\S]+?` 非贪婪匹配避免跨 block 粘连
//! - 整个 BEGIN..END 作为单个 `secret_like` 候选（UI 需要原样导入）

use regex::Regex;

use super::candidate::Kind;
use super::rule::try_push;

pub fn extract(
    text: &str,
    cands: &mut Vec<super::candidate::Candidate>,
    seen: &mut std::collections::HashSet<String>,
) {
    // (?s) 让 `.` 匹配换行；但我们用 [\s\S] 显式跨行更稳
    let re = Regex::new(
        r"(-----BEGIN [A-Z ]+-----[\s\S]+?-----END [A-Z ]+-----)"
    ).unwrap();
    for m in re.find_iter(text) {
        try_push(cands, seen, Kind::SecretLike, m.as_str(), Some([m.start(), m.end()]));
    }
}

#[cfg(test)]
mod tests {
    use super::super::candidate::Kind;
    use std::collections::HashSet;

    #[test]
    fn extract_ssh_openssh_private_key_block() {
        let text = "prefix text\n\
-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAAB...\n\
-----END OPENSSH PRIVATE KEY-----\n\
suffix";
        let mut cands = Vec::new();
        let mut seen = HashSet::new();
        super::extract(text, &mut cands, &mut seen);
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].kind, Kind::SecretLike);
        assert!(cands[0].value.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(cands[0].value.ends_with("-----END OPENSSH PRIVATE KEY-----"));
    }

    #[test]
    fn extract_two_distinct_blocks() {
        let text = "\
-----BEGIN RSA PRIVATE KEY-----
line1
-----END RSA PRIVATE KEY-----

-----BEGIN CERTIFICATE-----
cert1
-----END CERTIFICATE-----";
        let mut cands = Vec::new();
        let mut seen = HashSet::new();
        super::extract(text, &mut cands, &mut seen);
        assert_eq!(cands.len(), 2);
    }
}
