//! Secret display names (plan step 4 "Secret names"): a thin adapter that feeds the
//! current vault listings into `asm_proto::names::NameTable` and maps results back.

use asm_proto::names::{NameInput, NameTable};

use super::SecretMeta;
use crate::error::{CoreError, Result};

/// The secrets of one `Ready` vault, as listed right now.
#[derive(Debug, Clone)]
pub struct VaultListing {
    pub vault_id: String,
    pub vault_name: String,
    pub secrets: Vec<SecretMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedSecret {
    /// What `asm list` shows and what lookup matches: "name", "name~1a2b3c4d", or "vault/name…".
    pub display: String,
    pub vault_id: String,
    pub vault_name: String,
    /// Names are currently vault-prefixed (affects `relative_path`).
    pub prefixed: bool,
    /// `meta.name` is the provider's raw name.
    pub meta: SecretMeta,
}

fn table(listings: &[VaultListing]) -> (NameTable, Vec<(usize, usize)>) {
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
    (NameTable::build(&inputs), origin)
}

/// Every named secret, in listing order (secrets with an empty name are skipped).
pub fn compute_names(listings: &[VaultListing]) -> Vec<NamedSecret> {
    let (t, origin) = table(listings);
    t.entries
        .iter()
        .map(|e| {
            let (li, si) = origin[e.index];
            let l = &listings[li];
            NamedSecret {
                display: e.display.clone(),
                vault_id: l.vault_id.clone(),
                vault_name: l.vault_name.clone(),
                prefixed: t.vault_prefixed,
                meta: l.secrets[si].clone(),
            }
        })
        .collect()
}

/// Resolve `query` (`<vault>/<name>` or a bare name) against `compute_names` output.
pub fn lookup<'a>(names: &'a [NamedSecret], query: &str) -> Result<&'a NamedSecret> {
    // Rebuild the table from the named secrets so lookup uses the shared rules
    // (`<vault>/<base>` always; bare base when unique; else ambiguous / not_found).
    let bases: Vec<String> = names.iter().map(base_of).collect();
    let inputs: Vec<NameInput<'_>> = names
        .iter()
        .zip(&bases)
        .map(|(n, b)| NameInput {
            vault: &n.vault_name,
            key: &n.meta.key,
            name: b,
        })
        .collect();
    let t = NameTable::build(&inputs);
    let hit = t
        .lookup(query)
        .map_err(|e| CoreError::new(e.code, e.message))?;
    Ok(&names[hit.index])
}

/// `display` without the vault prefix (still carrying a `~<hash>` duplicate suffix).
fn base_of(n: &NamedSecret) -> String {
    if n.prefixed {
        n.display[n.vault_name.len() + 1..].to_owned()
    } else {
        n.display.clone()
    }
}

/// Whether any vault has a secret whose raw name is `name` (`add` → `exists`).
pub fn base_name_exists(listings: &[VaultListing], name: &str) -> bool {
    table(listings).0.has_base_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::SecretKind;
    use asm_proto::error::ErrorCode;

    fn meta(key: &str, name: &str) -> SecretMeta {
        SecretMeta {
            key: key.into(),
            name: name.into(),
            kind: SecretKind::Single,
            fields: vec!["value".into()],
            uri_hosts: vec![],
        }
    }
    fn listing(id: &str, name: &str, secrets: &[(&str, &str)]) -> VaultListing {
        VaultListing {
            vault_id: id.into(),
            vault_name: name.into(),
            secrets: secrets.iter().map(|(k, n)| meta(k, n)).collect(),
        }
    }

    #[test]
    fn shared_name_prefixes_everything_and_unique_bare_name_resolves() {
        let ls = [
            listing(
                "v1",
                "work",
                &[
                    ("SOME_APP_TOKEN", "SOME_APP_TOKEN"),
                    ("ONLY_HERE", "ONLY_HERE"),
                ],
            ),
            listing("v2", "home", &[("SOME_APP_TOKEN", "SOME_APP_TOKEN")]),
        ];
        let names = compute_names(&ls);
        let d: Vec<&str> = names.iter().map(|n| n.display.as_str()).collect();
        assert_eq!(
            d,
            [
                "work/SOME_APP_TOKEN",
                "work/ONLY_HERE",
                "home/SOME_APP_TOKEN"
            ]
        );
        assert!(names.iter().all(|n| n.prefixed));

        let hit = lookup(&names, "ONLY_HERE").unwrap();
        assert_eq!(
            (hit.vault_id.as_str(), hit.meta.key.as_str()),
            ("v1", "ONLY_HERE")
        );
        assert_eq!(
            lookup(&names, "home/SOME_APP_TOKEN").unwrap().vault_id,
            "v2"
        );
        let e = lookup(&names, "SOME_APP_TOKEN").unwrap_err();
        assert_eq!(e.code, ErrorCode::Ambiguous);
        assert!(
            e.message.contains("work/SOME_APP_TOKEN") && e.message.contains("home/SOME_APP_TOKEN")
        );
        assert_eq!(
            lookup(&names, "NOPE").unwrap_err().code,
            ErrorCode::NotFound
        );
        assert!(base_name_exists(&ls, "SOME_APP_TOKEN"));
        assert!(!base_name_exists(&ls, "NEW_ONE"));
    }

    #[test]
    fn duplicate_in_one_vault_gets_hash_suffix() {
        let ls = [listing(
            "v1",
            "bw",
            &[("id-1", "GitHub"), ("id-2", "GitHub"), ("id-3", "")],
        )];
        let names = compute_names(&ls);
        assert_eq!(names.len(), 2, "empty names are skipped");
        let suffix = &asm_proto::crypto::sha256_hex("id-1")[..8];
        assert_eq!(names[0].display, format!("GitHub~{suffix}"));
        assert!(!names[0].prefixed);
        assert_eq!(lookup(&names, &names[1].display).unwrap().meta.key, "id-2");
        assert_eq!(
            lookup(&names, &format!("bw/{}", names[0].display))
                .unwrap()
                .meta
                .key,
            "id-1"
        );
        assert_eq!(
            lookup(&names, "GitHub").unwrap_err().code,
            ErrorCode::NotFound
        );
        assert!(base_name_exists(&ls, "GitHub"));
    }

    #[test]
    fn prefixed_duplicates_resolve() {
        let ls = [
            listing("v1", "a", &[("k1", "X"), ("k2", "X")]),
            listing("v2", "b", &[("k3", "X")]),
        ];
        let names = compute_names(&ls);
        for n in &names {
            assert!(n.display.starts_with(&format!("{}/", n.vault_name)));
            assert_eq!(lookup(&names, &n.display).unwrap().meta.key, n.meta.key);
        }
    }
}
