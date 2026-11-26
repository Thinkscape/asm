//! Secret display names (plan step 4 "Secret names"): a thin adapter that feeds the
//! current vault listings into `asm_proto::names::NameTable` and maps results back.

use std::collections::HashMap;

use asm_proto::names::{NameInput, NameTable};

use super::SecretMeta;

/// The secrets of one `Ready` vault, as listed right now.
#[derive(Debug, Clone)]
pub struct VaultListing {
    pub vault_id: String,
    pub vault_name: String,
    pub secrets: Vec<SecretMeta>,
    /// Exposed collection id → name, filled only when the vault shares collection names
    /// with agents.
    pub shared_collection_names: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedSecret {
    /// What `asm list` shows and what lookup matches: "name", "name~1a2b3c4d", or "vault/name…".
    pub display: String,
    pub vault_id: String,
    pub vault_name: String,
    /// This name is vault-prefixed (affects `relative_path`).
    pub prefixed: bool,
    /// `meta.name` is the provider's raw name.
    pub meta: SecretMeta,
}

/// Every named secret, in listing order (secrets with an empty name are skipped).
pub fn compute_names(listings: &[VaultListing]) -> Vec<NamedSecret> {
    let mut inputs = Vec::new();
    let mut origin = Vec::new();
    for (li, l) in listings.iter().enumerate() {
        for (si, s) in l.secrets.iter().enumerate() {
            inputs.push(NameInput {
                vault: &l.vault_name,
                key: &s.key,
                name: &s.name,
            });
            origin.push((li, si));
        }
    }
    NameTable::build(&inputs)
        .entries
        .into_iter()
        .map(|e| {
            let (li, si) = origin[e.index];
            let l = &listings[li];
            NamedSecret {
                display: e.display,
                vault_id: l.vault_id.clone(),
                vault_name: l.vault_name.clone(),
                prefixed: e.prefixed,
                meta: l.secrets[si].clone(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::SecretKind;

    fn meta(key: &str, name: &str) -> SecretMeta {
        SecretMeta {
            key: key.into(),
            name: name.into(),
            kind: SecretKind::Single,
            fields: vec!["value".into()],
            uri_hosts: vec![],
            collections: vec![],
        }
    }
    fn listing(id: &str, name: &str, secrets: &[(&str, &str)]) -> VaultListing {
        VaultListing {
            vault_id: id.into(),
            vault_name: name.into(),
            secrets: secrets.iter().map(|(k, n)| meta(k, n)).collect(),
            shared_collection_names: HashMap::new(),
        }
    }

    #[test]
    fn a_shared_name_prefixes_only_its_own_secrets() {
        let ls = [
            listing("v1", "work", &[("SOME_APP_TOKEN", "SOME_APP_TOKEN"), ("ONLY_HERE", "ONLY_HERE")]),
            listing("v2", "home", &[("SOME_APP_TOKEN", "SOME_APP_TOKEN")]),
        ];
        let names = compute_names(&ls);
        let expected = [("work/SOME_APP_TOKEN", true), ("ONLY_HERE", false), ("home/SOME_APP_TOKEN", true)];
        assert_eq!(names.iter().map(|n| (n.display.as_str(), n.prefixed)).collect::<Vec<_>>(), expected);
    }

    #[test]
    fn duplicate_in_one_vault_gets_hash_suffix() {
        let ls = [listing("v1", "bw", &[("id-1", "GitHub"), ("id-2", "GitHub"), ("id-3", "")])];
        let names = compute_names(&ls);
        assert_eq!(names.len(), 2, "empty names are skipped");
        let suffix = &asm_proto::crypto::sha256_hex("id-1")[..8];
        assert_eq!(names[0].display, format!("GitHub~{suffix}"));
        assert!(!names[0].prefixed);
        assert_eq!(names[0].meta.name, "GitHub");
    }
}
