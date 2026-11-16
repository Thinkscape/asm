//! Secret display names and lookup (plan step 4, "Secret names").
//!
//! 1. Within a vault, secrets sharing a name each become `name~<first 8 hex of sha256(key)>`.
//! 2. When any name occurs in two or more vaults, every secret is shown as `<vault>/<name>`.
//! 3. Lookup: `<vault>/<name>` always; a bare name when exactly one vault has it;
//!    otherwise `ambiguous` or `not_found`. Comparison is exact and case-sensitive;
//!    secrets with an empty name are skipped.

use crate::crypto::{hex_encode, sha256};
use crate::error::ApiError;
use std::collections::{HashMap, HashSet};

/// One secret as input to [`NameTable::build`].
#[derive(Debug, Clone, Copy)]
pub struct NameInput<'a> {
    /// Vault display name (unique, no `/`).
    pub vault: &'a str,
    /// Provider key of the secret (unique within its vault).
    pub key: &'a str,
    /// Name in the vault.
    pub name: &'a str,
}

/// A named secret in a [`NameTable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedSecret {
    /// Index into the input slice.
    pub index: usize,
    /// Vault display name.
    pub vault: String,
    /// Name inside its vault after rule 1 (`name` or `name~<hash>`).
    pub base: String,
    /// Display name: `base`, or `<vault>/<base>` while names are vault-prefixed.
    pub display: String,
}

/// Display names computed from the current vault contents.
#[derive(Debug, Clone, Default)]
pub struct NameTable {
    /// Named secrets, in input order (empty names omitted).
    pub entries: Vec<NamedSecret>,
    /// True when every name is shown as `<vault>/<name>` (rule 2).
    pub vault_prefixed: bool,
    raw_names: HashSet<String>,
}

/// The rule-1 suffix for a key: `~` + first 8 hex characters of `sha256(key)`.
pub fn duplicate_suffix(key: &str) -> String {
    format!("~{}", &hex_encode(&sha256(key.as_bytes()))[..8])
}

impl NameTable {
    /// Apply rules 1 and 2 to `items`.
    pub fn build(items: &[NameInput<'_>]) -> Self {
        let mut per_vault: HashMap<(&str, &str), usize> = HashMap::new();
        let mut vaults_of: HashMap<&str, HashSet<&str>> = HashMap::new();
        for it in items.iter().filter(|it| !it.name.is_empty()) {
            *per_vault.entry((it.vault, it.name)).or_default() += 1;
            vaults_of.entry(it.name).or_default().insert(it.vault);
        }
        let vault_prefixed = vaults_of.values().any(|v| v.len() >= 2);
        let entries = items
            .iter()
            .enumerate()
            .filter(|(_, it)| !it.name.is_empty())
            .map(|(index, it)| {
                let base = if per_vault[&(it.vault, it.name)] > 1 {
                    format!("{}{}", it.name, duplicate_suffix(it.key))
                } else {
                    it.name.to_owned()
                };
                let display = if vault_prefixed { format!("{}/{}", it.vault, base) } else { base.clone() };
                NamedSecret { index, vault: it.vault.to_owned(), base, display }
            })
            .collect();
        let raw_names = vaults_of.into_keys().map(str::to_owned).collect();
        NameTable { entries, vault_prefixed, raw_names }
    }

    /// Resolve a name given by an agent (rule 3).
    pub fn lookup(&self, query: &str) -> Result<&NamedSecret, ApiError> {
        if let Some((vault, rest)) = query.split_once('/')
            && let Some(e) = self.entries.iter().find(|e| e.vault == vault && e.base == rest)
        {
            return Ok(e);
        }
        let hits: Vec<&NamedSecret> = self.entries.iter().filter(|e| e.base == query).collect();
        match hits.as_slice() {
            [] => Err(ApiError::not_found(format!("no secret named {query:?}"))),
            [one] => Ok(one),
            many => {
                let list: Vec<String> = many.iter().map(|e| format!("{}/{}", e.vault, e.base)).collect();
                Err(ApiError::ambiguous(format!("{query:?} is ambiguous; use one of: {}", list.join(", "))))
            }
        }
    }

    /// True when any vault has a secret with this name (before rule-1 suffixes);
    /// `add` answers `exists` then.
    pub fn has_base_name(&self, name: &str) -> bool {
        self.raw_names.contains(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;

    fn n<'a>(vault: &'a str, key: &'a str, name: &'a str) -> NameInput<'a> {
        NameInput { vault, key, name }
    }

    #[test]
    fn unique_names_stay_bare() {
        let t = NameTable::build(&[n("env", "A", "A"), n("kc", "k1", "B"), n("kc", "k2", "")]);
        assert!(!t.vault_prefixed);
        assert_eq!(t.entries.len(), 2);
        assert_eq!(t.lookup("A").unwrap().display, "A");
        assert_eq!(t.lookup("kc/B").unwrap().index, 1);
        assert_eq!(t.lookup("missing").unwrap_err().code, ErrorCode::NotFound);
    }

    #[test]
    fn shared_name_across_vaults_prefixes_everything() {
        let t = NameTable::build(&[
            n("env1", "SOME_APP_TOKEN", "SOME_APP_TOKEN"),
            n("env2", "SOME_APP_TOKEN", "SOME_APP_TOKEN"),
            n("env2", "OTHER", "OTHER"),
        ]);
        assert!(t.vault_prefixed);
        let d: Vec<&str> = t.entries.iter().map(|e| e.display.as_str()).collect();
        assert_eq!(d, ["env1/SOME_APP_TOKEN", "env2/SOME_APP_TOKEN", "env2/OTHER"]);
        assert_eq!(t.lookup("OTHER").unwrap().index, 2);
        assert_eq!(t.lookup("env2/SOME_APP_TOKEN").unwrap().index, 1);
        let e = t.lookup("SOME_APP_TOKEN").unwrap_err();
        assert_eq!(e.code, ErrorCode::Ambiguous);
        assert!(e.message.contains("env1/SOME_APP_TOKEN"));
        assert!(t.has_base_name("SOME_APP_TOKEN"));
        assert!(!t.has_base_name("NEW"));
    }

    #[test]
    fn duplicate_within_vault_gets_hash() {
        let t = NameTable::build(&[n("bw", "id-1", "GitHub"), n("bw", "id-2", "GitHub")]);
        assert!(!t.vault_prefixed);
        assert_eq!(t.entries[0].display, format!("GitHub{}", duplicate_suffix("id-1")));
        assert_ne!(t.entries[0].display, t.entries[1].display);
        assert_eq!(duplicate_suffix("id-1").len(), 9);
        assert_eq!(t.lookup(&t.entries[1].display).unwrap().index, 1);
        assert_eq!(t.lookup("GitHub").unwrap_err().code, ErrorCode::NotFound);
        assert!(t.has_base_name("GitHub"));
    }

    #[test]
    fn slash_in_bare_name() {
        let t = NameTable::build(&[n("bw", "id", "a/b")]);
        assert_eq!(t.lookup("a/b").unwrap().index, 0);
        assert_eq!(t.lookup("bw/a/b").unwrap().index, 0);
    }
}
