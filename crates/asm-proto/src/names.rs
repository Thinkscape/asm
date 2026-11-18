//! Secret display names and lookup (plan step 4, "Secret names").
//!
//! 1. Within a vault, secrets sharing a name each become `name~<first 8 hex of sha256(key)>`.
//! 2. When any name occurs in two or more vaults, every secret is shown as `<vault>/<name>`.
//! 3. Lookup: `<vault>/<name>` always; a bare name when exactly one vault has it;
//!    otherwise `ambiguous` or `not_found`. Comparison is exact and case-sensitive;
//!    secrets with an empty name are skipped.

use crate::crypto::{hex_encode, sha256};
use crate::error::ApiError;
use crate::generators::{SourceKind, generated_output_names};
use crate::wire::SecretEntry;
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

/// A public catalog lookup. Request spelling and authority/dedup identity are
/// deliberately separate: an unambiguous GITHUB_TOKEN must not be posted as a
/// colliding GH_TOKEN, and a source-qualified lookup pins that source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCatalogName {
    pub entry_index: usize,
    pub request_name: String,
    pub canonical_key: String,
    pub pinned_generator_id: Option<String>,
    pub generated_output: Option<&'static str>,
}

fn static_base(entry: &SecretEntry) -> &str {
    fn unqualify<'a>(source: &str, name: &'a str) -> Option<&'a str> {
        name.strip_prefix(source).and_then(|rest| rest.strip_prefix('/'))
    }
    // A capable manager always includes the actual source-qualified spelling,
    // even when it equals the display name. This disambiguates literal slashes.
    entry.aliases.iter().find_map(|name| unqualify(&entry.vault, name)).unwrap_or_else(|| {
        unqualify(&entry.vault, &entry.name).unwrap_or(&entry.name)
    })
}

/// Map an unqualified generated spelling to its provider's canonical output.
pub fn canonical_generated_output(name: &str) -> Option<&'static str> {
    generated_output_names(name).map(|names| names[0])
}

/// The public catalog uses the same output leaf on logical and qualified rows.
pub fn generated_output(entry: &SecretEntry) -> Option<&'static str> {
    if entry.source_kind != SourceKind::Generator || entry.generators.is_empty() {
        return None;
    }
    entry.name.rsplit('/').next().and_then(canonical_generated_output)
}

#[derive(Clone, Copy)]
struct CatalogMatch<'a> {
    index: usize,
    generator: Option<(&'a str, &'a str)>,
}

fn add_catalog_match<'a>(matches: &mut Vec<CatalogMatch<'a>>, candidate: CatalogMatch<'a>, entries: &[SecretEntry]) {
    let same_identity = |existing: &CatalogMatch<'_>| {
        match (existing.generator, candidate.generator) {
            (Some((left, _)), Some((right, _))) => left == right
                && generated_output(&entries[existing.index]) == generated_output(&entries[candidate.index]),
            (None, None) => {
                existing.index == candidate.index
                    || generated_output(&entries[existing.index])
                        .is_some_and(|output| generated_output(&entries[candidate.index]) == Some(output))
            }
            _ => false,
        }
    };
    if !matches.iter().any(same_identity) {
        matches.push(candidate);
    }
}

fn finish_catalog_lookup(query: &str, matches: &[CatalogMatch<'_>], entries: &[SecretEntry]) -> Result<ResolvedCatalogName, ApiError> {
    match matches {
        [] => Err(ApiError::not_found(format!("no secret named {query:?}"))),
        [found] => {
            let entry = &entries[found.index];
            let output = generated_output(entry);
            let (canonical_key, pinned_generator_id) = if let Some(output) = output {
                match found.generator {
                    Some((id, name)) => (format!("{name}/{output}"), Some(id.to_owned())),
                    None => (output.to_owned(), None),
                }
            } else {
                (format!("{}/{}", entry.vault, static_base(entry)), None)
            };
            Ok(ResolvedCatalogName {
                entry_index: found.index,
                request_name: query.to_owned(),
                canonical_key,
                pinned_generator_id,
                generated_output: output,
            })
        }
        _ => {
            let mut choices = Vec::new();
            for found in matches {
                let entry = &entries[found.index];
                if let Some(output) = generated_output(entry) {
                    if let Some((_, name)) = found.generator {
                        choices.push(format!("{name}/{output}"));
                    } else {
                        choices.extend(entry.generators.iter().map(|g| format!("{}/{output}", g.name)));
                    }
                } else {
                    choices.push(format!("{}/{}", entry.vault, static_base(entry)));
                }
            }
            choices.sort();
            choices.dedup();
            Err(ApiError::ambiguous(format!("{query:?} is ambiguous; use one of: {}", choices.join(", "))))
        }
    }
}

/// Resolve the current shared public catalog, without the manager's historical
/// static-lease fallback. Qualified generator options are addressable even when
/// discovery emits just one logical group row. Options never create bare aliases.
pub fn resolve_catalog_name(query: &str, entries: &[SecretEntry]) -> Result<ResolvedCatalogName, ApiError> {
    let mut matches = Vec::new();
    // Current source qualification wins over a literal slash-containing name.
    if let Some((source, rest)) = query.split_once('/') {
        let requested_output = canonical_generated_output(rest);
        for (index, entry) in entries.iter().enumerate() {
            match entry.source_kind {
                SourceKind::Vault if entry.vault == source => {
                    if static_base(entry) == rest || entry.aliases.iter().any(|alias| alias == query) {
                        add_catalog_match(&mut matches, CatalogMatch { index, generator: None }, entries);
                    }
                }
                SourceKind::Generator if requested_output.is_some() && generated_output(entry) == requested_output => {
                    for generator in entry.generators.iter().filter(|g| g.name == source) {
                        add_catalog_match(&mut matches, CatalogMatch { index, generator: Some((&generator.generator_id, &generator.name)) }, entries);
                    }
                }
                _ => {}
            }
        }
        if !matches.is_empty() {
            return finish_catalog_lookup(query, &matches, entries);
        }
    }
    // A colliding bare spelling is ambiguous even when it was intentionally
    // omitted from the logical generated row's public aliases.
    let requested_output = canonical_generated_output(query);
    if let Some(output) = requested_output {
        for (index, entry) in entries.iter().enumerate() {
            if entry.source_kind == SourceKind::Vault
                && static_base(entry) == query
            {
                add_catalog_match(&mut matches, CatalogMatch { index, generator: None }, entries);
            }
        }
        if !matches.is_empty() {
            let static_count = matches.len();
            for (index, entry) in entries.iter().enumerate().filter(|(_, entry)| generated_output(entry) == Some(output)) {
                for generator in &entry.generators {
                    add_catalog_match(&mut matches, CatalogMatch { index, generator: Some((&generator.generator_id, &generator.name)) }, entries);
                }
            }
            if matches.len() > static_count {
                return finish_catalog_lookup(query, &matches, entries);
            }
            matches.clear();
        }
    }
    for (index, entry) in entries.iter().enumerate() {
        let matched = match entry.source_kind {
            SourceKind::Vault => entry.name == query || static_base(entry) == query || entry.aliases.iter().any(|alias| alias == query),
            SourceKind::Generator => requested_output.is_some() && generated_output(entry) == requested_output
                && (entry.name == query || entry.aliases.iter().any(|alias| alias == query)),
        };
        if matched {
            add_catalog_match(&mut matches, CatalogMatch { index, generator: None }, entries);
        }
    }
    finish_catalog_lookup(query, &matches, entries)
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

    fn vault_entry(vault: &str, base: &str, display: &str) -> SecretEntry {
        SecretEntry {
            name: display.into(), vault: vault.into(), kind: crate::wire::SecretKind::Single,
            fields: vec!["value".into()], lease: None, source_kind: SourceKind::Vault,
            generators: vec![], aliases: vec![format!("{vault}/{base}")],
        }
    }

    fn generator_entry(display: &str, aliases: &[&str], sources: &[(&str, &str)]) -> SecretEntry {
        SecretEntry {
            name: display.into(), vault: "GitHub Apps".into(), kind: crate::wire::SecretKind::Single,
            fields: vec!["value".into()], lease: None, source_kind: SourceKind::Generator,
            generators: sources.iter().map(|(id, name)| crate::wire::GeneratorOption {
                generator_id: (*id).into(), name: (*name).into(), available: true,
            }).collect(),
            aliases: aliases.iter().map(|s| (*s).into()).collect(),
        }
    }

    #[test]
    fn catalog_generated_aliases_share_identity_but_preserve_request_spelling() {
        let entries = [generator_entry("GH_TOKEN", &["GITHUB_TOKEN"], &[("a", "release-bot"), ("b", "review-bot")])];
        for query in ["GH_TOKEN", "GITHUB_TOKEN"] {
            let found = resolve_catalog_name(query, &entries).unwrap();
            assert_eq!(found.entry_index, 0);
            assert_eq!(found.request_name, query);
            assert_eq!(found.canonical_key, "GH_TOKEN");
            assert_eq!(found.pinned_generator_id, None);
        }
        for alias in ["GH_TOKEN", "GITHUB_TOKEN"] {
            let found = resolve_catalog_name(&format!("review-bot/{alias}"), &entries).unwrap();
            assert_eq!(found.canonical_key, "review-bot/GH_TOKEN");
            assert_eq!(found.pinned_generator_id.as_deref(), Some("b"));
        }
        let a = resolve_catalog_name("release-bot/GH_TOKEN", &entries).unwrap();
        let b = resolve_catalog_name("review-bot/GH_TOKEN", &entries).unwrap();
        assert_ne!(a.canonical_key, b.canonical_key);
        assert_eq!(resolve_catalog_name("removed/GH_TOKEN", &entries).unwrap_err().code, ErrorCode::NotFound);
    }

    #[test]
    fn catalog_collisions_are_per_spelling_and_options_do_not_add_bare_aliases() {
        let entries = [
            vault_entry("work", "GH_TOKEN", "work/GH_TOKEN"),
            vault_entry("work", "OTHER", "OTHER"),
            generator_entry("GITHUB_TOKEN", &[], &[("a", "release-bot"), ("b", "review-bot")]),
            generator_entry("release-bot/GH_TOKEN", &["release-bot/GITHUB_TOKEN"], &[("a", "release-bot")]),
            generator_entry("review-bot/GH_TOKEN", &["review-bot/GITHUB_TOKEN"], &[("b", "review-bot")]),
        ];
        let error = resolve_catalog_name("GH_TOKEN", &entries).unwrap_err();
        assert_eq!(error.code, ErrorCode::Ambiguous);
        assert!(error.message.contains("work/GH_TOKEN"));
        assert!(error.message.contains("release-bot/GH_TOKEN"));
        assert!(error.message.contains("review-bot/GH_TOKEN"));
        let found = resolve_catalog_name("GITHUB_TOKEN", &entries).unwrap();
        assert_eq!(found.request_name, "GITHUB_TOKEN");
        assert_eq!(found.canonical_key, "GH_TOKEN");
        assert_eq!(resolve_catalog_name("OTHER", &entries).unwrap().canonical_key, "work/OTHER");
        assert_eq!(resolve_catalog_name("work/OTHER", &entries).unwrap().entry_index, 1);
        assert_eq!(resolve_catalog_name("work/GH_TOKEN", &entries).unwrap().entry_index, 0);
        assert_eq!(resolve_catalog_name("release-bot/GITHUB_TOKEN", &entries).unwrap().pinned_generator_id.as_deref(), Some("a"));
        let not_advertised = [generator_entry("release-bot/GH_TOKEN", &[], &[("a", "release-bot")])];
        assert_eq!(resolve_catalog_name("GITHUB_TOKEN", &not_advertised).unwrap_err().code, ErrorCode::NotFound);
    }

    #[test]
    fn catalog_collision_on_the_other_or_both_aliases_never_rebinds_static_items() {
        let mut entries = vec![
            vault_entry("work", "GITHUB_TOKEN", "work/GITHUB_TOKEN"),
            generator_entry("GH_TOKEN", &[], &[("a", "bot")]),
        ];
        assert_eq!(resolve_catalog_name("GITHUB_TOKEN", &entries).unwrap_err().code, ErrorCode::Ambiguous);
        assert_eq!(resolve_catalog_name("GH_TOKEN", &entries).unwrap().canonical_key, "GH_TOKEN");
        entries.push(vault_entry("other", "GH_TOKEN", "other/GH_TOKEN"));
        entries[1] = generator_entry("bot/GH_TOKEN", &["bot/GITHUB_TOKEN"], &[("a", "bot")]);
        for alias in ["GH_TOKEN", "GITHUB_TOKEN"] {
            assert_eq!(resolve_catalog_name(alias, &entries).unwrap_err().code, ErrorCode::Ambiguous);
            assert_eq!(resolve_catalog_name(&format!("bot/{alias}"), &entries).unwrap().pinned_generator_id.as_deref(), Some("a"));
        }
        entries.remove(1);
        assert_eq!(resolve_catalog_name("GH_TOKEN", &entries).unwrap().canonical_key, "other/GH_TOKEN");
        assert_eq!(resolve_catalog_name("GITHUB_TOKEN", &entries).unwrap().canonical_key, "work/GITHUB_TOKEN");
    }

    #[test]
    fn catalog_static_lookup_keeps_nametable_rules_and_literal_slash_identity() {
        let entries = [
            vault_entry("one", "DUP", "one/DUP"),
            vault_entry("two", "DUP", "two/DUP"),
            vault_entry("one", "OTHER", "one/OTHER"),
            vault_entry("work", "work/X", "work/X"),
        ];
        assert_eq!(resolve_catalog_name("DUP", &entries).unwrap_err().code, ErrorCode::Ambiguous);
        assert_eq!(resolve_catalog_name("OTHER", &entries).unwrap().entry_index, 2);
        assert_eq!(resolve_catalog_name("one/OTHER", &entries).unwrap().canonical_key, "one/OTHER");
        for query in ["work/X", "work/work/X"] {
            assert_eq!(resolve_catalog_name(query, &entries).unwrap().canonical_key, "work/work/X");
        }
        assert_eq!(resolve_catalog_name("X", &entries).unwrap_err().code, ErrorCode::NotFound);
        let mut old = vault_entry("old", "X", "old/X");
        old.aliases.clear();
        assert_eq!(resolve_catalog_name("X", &[old]).unwrap().canonical_key, "old/X");
    }

    #[test]
    fn catalog_qualified_source_precedes_literal_name_and_unavailable_is_addressable() {
        let mut generated = generator_entry("GH_TOKEN", &["GITHUB_TOKEN"], &[("a", "bot")]);
        generated.generators[0].available = false;
        let entries = [vault_entry("work", "bot/GH_TOKEN", "bot/GH_TOKEN"), generated];
        let found = resolve_catalog_name("bot/GH_TOKEN", &entries).unwrap();
        assert_eq!(found.entry_index, 1);
        assert_eq!(found.pinned_generator_id.as_deref(), Some("a"));
        assert_eq!(resolve_catalog_name("work/bot/GH_TOKEN", &entries).unwrap().entry_index, 0);
    }

    #[test]
    fn both_colliding_aliases_list_all_qualified_generator_choices() {
        let entries = [
            vault_entry("work", "GH_TOKEN", "work/GH_TOKEN"),
            vault_entry("work", "GITHUB_TOKEN", "work/GITHUB_TOKEN"),
            generator_entry("release-bot/GH_TOKEN", &["release-bot/GITHUB_TOKEN"], &[("a", "release-bot")]),
            generator_entry("review-bot/GH_TOKEN", &["review-bot/GITHUB_TOKEN"], &[("b", "review-bot")]),
        ];
        for alias in ["GH_TOKEN", "GITHUB_TOKEN"] {
            let error = resolve_catalog_name(alias, &entries).unwrap_err();
            assert_eq!(error.code, ErrorCode::Ambiguous);
            assert!(error.message.contains("release-bot/GH_TOKEN"));
            assert!(error.message.contains("review-bot/GH_TOKEN"));
        }
        let stale = [generator_entry("old/GH_TOKEN", &["old/GITHUB_TOKEN"], &[("a", "renamed")])];
        assert_eq!(resolve_catalog_name("old/GH_TOKEN", &stale).unwrap_err().code, ErrorCode::NotFound);
        assert_eq!(resolve_catalog_name("renamed/GH_TOKEN", &stale).unwrap().pinned_generator_id.as_deref(), Some("a"));
    }

    #[test]
    fn generated_names_route_only_to_the_matching_output_group() {
        let entries = [
            generator_entry("GH_TOKEN", &["GITHUB_TOKEN"], &[("gh", "github-bot")]),
            generator_entry("CLOUDSDK_AUTH_ACCESS_TOKEN", &[], &[("gcp", "gcloud-dev")]),
        ];
        let gh = resolve_catalog_name("GITHUB_TOKEN", &entries).unwrap();
        let gcp = resolve_catalog_name("CLOUDSDK_AUTH_ACCESS_TOKEN", &entries).unwrap();
        assert_ne!(gh.entry_index, gcp.entry_index);
        assert_eq!(gh.canonical_key, "GH_TOKEN");
        assert_eq!(gcp.canonical_key, "CLOUDSDK_AUTH_ACCESS_TOKEN");
        let pinned = resolve_catalog_name("gcloud-dev/CLOUDSDK_AUTH_ACCESS_TOKEN", &entries).unwrap();
        assert_eq!(pinned.canonical_key, "gcloud-dev/CLOUDSDK_AUTH_ACCESS_TOKEN");
        assert_eq!(pinned.pinned_generator_id.as_deref(), Some("gcp"));
        for wrong in ["gcloud-dev/GH_TOKEN", "gcloud-dev/GITHUB_TOKEN", "github-bot/CLOUDSDK_AUTH_ACCESS_TOKEN"] {
            assert_eq!(resolve_catalog_name(wrong, &entries).unwrap_err().code, ErrorCode::NotFound);
        }
    }

    #[test]
    fn generated_collisions_list_only_the_matching_provider() {
        let entries = [
            vault_entry("work", "GH_TOKEN", "work/GH_TOKEN"),
            vault_entry("work", "CLOUDSDK_AUTH_ACCESS_TOKEN", "work/CLOUDSDK_AUTH_ACCESS_TOKEN"),
            generator_entry("GITHUB_TOKEN", &[], &[("gh", "github-bot")]),
            generator_entry("github-bot/GH_TOKEN", &["github-bot/GITHUB_TOKEN"], &[("gh", "github-bot")]),
            generator_entry("gcloud-dev/CLOUDSDK_AUTH_ACCESS_TOKEN", &[], &[("gcp", "gcloud-dev")]),
        ];
        for (query, matching, unrelated) in [
            ("GH_TOKEN", "github-bot/GH_TOKEN", "gcloud-dev"),
            ("CLOUDSDK_AUTH_ACCESS_TOKEN", "gcloud-dev/CLOUDSDK_AUTH_ACCESS_TOKEN", "github-bot"),
        ] {
            let error = resolve_catalog_name(query, &entries).unwrap_err();
            assert_eq!(error.code, ErrorCode::Ambiguous);
            assert!(error.message.contains(&format!("work/{query}")));
            assert!(error.message.contains(matching));
            assert!(!error.message.contains(unrelated));
            assert_eq!(resolve_catalog_name(&format!("work/{query}"), &entries).unwrap().canonical_key, format!("work/{query}"));
        }
        let bare = resolve_catalog_name("GITHUB_TOKEN", &entries).unwrap();
        assert_eq!(bare.canonical_key, "GH_TOKEN");
    }
}
