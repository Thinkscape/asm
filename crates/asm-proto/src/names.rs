//! Secret display names and lookup (plan step 4, "Secret names").
//!
//! 1. Within a vault, secrets sharing a name each become `name~<first 8 hex of sha256(key)>`.
//! 2. A name that occurs in two or more vaults is shown as `<vault>/<name>` for those
//!    secrets only; every other secret keeps its bare name.
//! 3. Lookup: `<vault>/<name>` always; a bare name (or a duplicate's `name~<hash>`) when it
//!    identifies one secret; otherwise `ambiguous` (listing the qualified choices, also for
//!    a bare name whose copies carry `~<hash>` suffixes) or `not_found`. Comparison is exact
//!    and case-sensitive; secrets with an empty name are skipped.

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
    /// Display name: `base`, or `<vault>/<base>` when `prefixed`.
    pub display: String,
    /// The name occurs in another vault too (rule 2).
    pub prefixed: bool,
}

/// Display names computed from the current vault contents.
#[derive(Debug, Clone, Default)]
pub struct NameTable {
    /// Named secrets, in input order (empty names omitted).
    pub entries: Vec<NamedSecret>,
}

/// The rule-1 suffix for a key: `~` + first 8 hex characters of `sha256(key)`.
pub fn duplicate_suffix(key: &str) -> String {
    format!("~{}", &hex_encode(&sha256(key.as_bytes()))[..8])
}

/// Suffix lengths a rule-1 duplicate tries in turn, shortest first.
const SUFFIX_HEX_LENGTHS: [usize; 4] = [8, 16, 32, 64];

impl NameTable {
    /// Apply rules 1 and 2 to `items`.
    pub fn build(items: &[NameInput<'_>]) -> Self {
        let mut per_vault: HashMap<(&str, &str), usize> = HashMap::new();
        let mut vaults_of: HashMap<&str, HashSet<&str>> = HashMap::new();
        for it in items.iter().filter(|it| !it.name.is_empty()) {
            *per_vault.entry((it.vault, it.name)).or_default() += 1;
            vaults_of.entry(it.name).or_default().insert(it.vault);
        }
        let named: Vec<(usize, &NameInput<'_>)> =
            items.iter().enumerate().filter(|(_, it)| !it.name.is_empty()).collect();
        let bases = duplicate_bases(&named, &per_vault);
        let entries = named.into_iter().zip(bases).map(|((index, it), base)| {
            let prefixed = vaults_of[it.name].len() >= 2;
            let display = if prefixed { format!("{}/{}", it.vault, base) } else { base.clone() };
            NamedSecret { index, vault: it.vault.to_owned(), base, display, prefixed }
        }).collect();
        NameTable { entries }
    }
}

/// Rule 1 with `<vault>/<base>` naming one secret: a duplicate's suffix grows (8, 16, 32,
/// 64 hex) while its base equals a name in its vault (every item name there is a lookup
/// key) or another duplicate's base, then takes a counter.
fn duplicate_bases(named: &[(usize, &NameInput<'_>)], per_vault: &HashMap<(&str, &str), usize>) -> Vec<String> {
    let raw: HashSet<(&str, &str)> = named.iter().map(|(_, it)| (it.vault, it.name)).collect();
    let hashes: Vec<Option<String>> = named.iter()
        .map(|(_, it)| (per_vault[&(it.vault, it.name)] > 1).then(|| hex_encode(&sha256(it.key.as_bytes()))))
        .collect();
    let mut level = vec![0; named.len()];
    loop {
        let bases: Vec<String> = named.iter().zip(&hashes).zip(&level).map(|(((_, it), hash), &l)| match hash {
            Some(hash) => format!("{}~{}", it.name, &hash[..SUFFIX_HEX_LENGTHS[l]]),
            None => it.name.to_owned(),
        }).collect();
        let mut count: HashMap<(&str, &str), usize> = HashMap::new();
        for ((_, it), base) in named.iter().zip(&bases) {
            *count.entry((it.vault, base.as_str())).or_default() += 1;
        }
        let clashes = |i: usize| {
            let key = (named[i].1.vault, bases[i].as_str());
            hashes[i].is_some() && (raw.contains(&key) || count[&key] > 1)
        };
        let grow: Vec<usize> = (0..named.len())
            .filter(|&i| clashes(i) && level[i] + 1 < SUFFIX_HEX_LENGTHS.len())
            .collect();
        if grow.is_empty() {
            // Distinct keys have distinct whole hashes: only a literal spelled like one is left.
            let mut taken: HashSet<(String, String)> = named.iter().zip(&bases)
                .map(|((_, it), base)| (it.vault.to_owned(), base.clone()))
                .chain(raw.iter().map(|(vault, name)| ((*vault).to_owned(), (*name).to_owned())))
                .collect();
            let stuck: Vec<usize> = (0..named.len()).filter(|&i| clashes(i)).collect();
            let mut bases = bases.clone();
            for i in stuck {
                let vault = named[i].1.vault.to_owned();
                let base = (2..).map(|n| format!("{}~{n}", bases[i]))
                    .find(|b| !taken.contains(&(vault.clone(), b.clone())))
                    .expect("an unused counter");
                taken.insert((vault, base.clone()));
                bases[i] = base;
            }
            return bases;
        }
        for i in grow {
            level[i] += 1;
        }
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

/// The vault item's own name: differs from [`static_base`] only for a rule-1 duplicate.
fn item_name(entry: &SecretEntry) -> &str {
    entry.item_name.as_deref().unwrap_or_else(|| static_base(entry))
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
                    if static_base(entry) == rest || item_name(entry) == rest || entry.aliases.iter().any(|alias| alias == query) {
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
                && item_name(entry) == query
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
            SourceKind::Vault => entry.name == query || static_base(entry) == query || item_name(entry) == query
                || entry.aliases.iter().any(|alias| alias == query),
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

    /// Wire rows as the manager builds them from a name table.
    fn catalog(items: &[NameInput<'_>]) -> Vec<SecretEntry> {
        NameTable::build(items).entries.into_iter().map(|e| {
            let raw = items[e.index].name;
            let mut entry = vault_entry(&e.vault, &e.base, &e.display);
            entry.item_name = (raw != e.base).then(|| raw.to_owned());
            entry
        }).collect()
    }

    #[test]
    fn unique_names_stay_bare() {
        let items = [n("env", "A", "A"), n("kc", "k1", "B"), n("kc", "k2", "")];
        let t = NameTable::build(&items);
        assert_eq!(t.entries.len(), 2);
        assert!(t.entries.iter().all(|e| !e.prefixed && e.display == e.base));
        let entries = catalog(&items);
        assert_eq!(resolve_catalog_name("A", &entries).unwrap().entry_index, 0);
        assert_eq!(resolve_catalog_name("kc/B", &entries).unwrap().entry_index, 1);
        assert_eq!(resolve_catalog_name("missing", &entries).unwrap_err().code, ErrorCode::NotFound);
    }

    #[test]
    fn shared_name_across_vaults_prefixes_only_that_name() {
        let items = [
            n("env1", "SOME_APP_TOKEN", "SOME_APP_TOKEN"),
            n("env2", "SOME_APP_TOKEN", "SOME_APP_TOKEN"),
            n("env2", "OTHER", "OTHER"),
        ];
        let t = NameTable::build(&items);
        let d: Vec<(&str, bool)> = t.entries.iter().map(|e| (e.display.as_str(), e.prefixed)).collect();
        assert_eq!(d, [("env1/SOME_APP_TOKEN", true), ("env2/SOME_APP_TOKEN", true), ("OTHER", false)]);
        let entries = catalog(&items);
        assert_eq!(resolve_catalog_name("OTHER", &entries).unwrap().entry_index, 2);
        assert_eq!(resolve_catalog_name("env2/OTHER", &entries).unwrap().entry_index, 2);
        assert_eq!(resolve_catalog_name("env2/SOME_APP_TOKEN", &entries).unwrap().entry_index, 1);
        let e = resolve_catalog_name("SOME_APP_TOKEN", &entries).unwrap_err();
        assert_eq!(e.code, ErrorCode::Ambiguous);
        assert!(e.message.contains("env1/SOME_APP_TOKEN") && e.message.contains("env2/SOME_APP_TOKEN"));
    }

    #[test]
    fn bare_name_of_duplicates_within_a_vault_is_ambiguous() {
        let items = [n("bw", "id-1", "GitHub"), n("bw", "id-2", "GitHub")];
        let t = NameTable::build(&items);
        assert!(t.entries.iter().all(|e| !e.prefixed));
        assert_eq!(t.entries[0].display, format!("GitHub{}", duplicate_suffix("id-1")));
        assert_ne!(t.entries[0].display, t.entries[1].display);
        assert_eq!(duplicate_suffix("id-1").len(), 9);
        let entries = catalog(&items);
        assert_eq!(resolve_catalog_name(&t.entries[1].display, &entries).unwrap().entry_index, 1);
        for query in ["GitHub", "bw/GitHub"] {
            let e = resolve_catalog_name(query, &entries).unwrap_err();
            assert_eq!(e.code, ErrorCode::Ambiguous, "{query}");
            for entry in &t.entries {
                assert!(e.message.contains(&format!("bw/{}", entry.base)), "{}", e.message);
            }
        }
        // Without the item name (an older manager) the bare name matches nothing.
        let legacy: Vec<_> = entries.into_iter().map(|e| SecretEntry { item_name: None, ..e }).collect();
        assert_eq!(resolve_catalog_name("GitHub", &legacy).unwrap_err().code, ErrorCode::NotFound);
    }

    #[test]
    fn a_bare_name_never_resolves_past_duplicates_in_another_vault() {
        let items = [n("a", "k1", "X"), n("a", "k2", "X"), n("b", "k3", "X")];
        let entries = catalog(&items);
        let e = resolve_catalog_name("X", &entries).unwrap_err();
        assert_eq!(e.code, ErrorCode::Ambiguous);
        assert_eq!(e.message.matches("a/X~").count(), 2, "{}", e.message);
        assert!(e.message.contains("b/X"));
        assert_eq!(resolve_catalog_name("b/X", &entries).unwrap().entry_index, 2);
    }

    #[test]
    fn slash_in_bare_name() {
        let entries = catalog(&[n("bw", "id", "a/b")]);
        assert_eq!(resolve_catalog_name("a/b", &entries).unwrap().entry_index, 0);
        assert_eq!(resolve_catalog_name("bw/a/b", &entries).unwrap().entry_index, 0);
    }

    #[test]
    fn a_duplicate_suffix_grows_past_every_name_in_its_vault() {
        let hash = hex_encode(&sha256(b"k1"));
        let short = format!("X~{}", &hash[..8]);
        let longer = format!("X~{}", &hash[..16]);
        // Literal names spelled like k1's 8- and 16-hex suffixes, and a second duplicate
        // group named like the 32-hex one.
        let thirty_two = format!("X~{}", &hash[..32]);
        let items = [
            n("bw", "k1", "X"), n("bw", "k2", "X"), n("bw", "k3", &short), n("bw", "k4", &longer),
            n("bw", "k5", &thirty_two), n("bw", "k6", &thirty_two),
        ];
        let t = NameTable::build(&items);
        let bases: Vec<&str> = t.entries.iter().map(|e| e.base.as_str()).collect();
        assert_eq!(bases[0], format!("X~{hash}"), "{bases:?}");
        assert_eq!(bases[1], format!("X{}", duplicate_suffix("k2")));
        assert_eq!((bases[2], bases[3]), (short.as_str(), longer.as_str()));
        let entries = catalog(&items);
        for (index, base) in bases.iter().enumerate() {
            assert_eq!(resolve_catalog_name(&format!("bw/{base}"), &entries).unwrap().entry_index, index, "{base}");
        }
    }

    fn vault_entry(vault: &str, base: &str, display: &str) -> SecretEntry {
        SecretEntry {
            name: display.into(), vault: vault.into(), kind: crate::wire::SecretKind::Single,
            fields: vec!["value".into()], lease: None, source_kind: SourceKind::Vault,
            generators: vec![], aliases: vec![format!("{vault}/{base}")], item_name: None,
            collections: vec![],
        }
    }

    fn generator_entry(display: &str, aliases: &[&str], sources: &[(&str, &str)]) -> SecretEntry {
        SecretEntry {
            name: display.into(), vault: "GitHub Apps".into(), kind: crate::wire::SecretKind::Single,
            fields: vec!["value".into()], lease: None, source_kind: SourceKind::Generator,
            generators: sources.iter().map(|(id, name)| {
                crate::wire::GeneratorOption::listed((*id).into(), (*name).into())
            }).collect(),
            aliases: aliases.iter().map(|s| (*s).into()).collect(), item_name: None, collections: vec![],
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
    fn catalog_qualified_generator_precedes_literal_name() {
        let generated = generator_entry("GH_TOKEN", &["GITHUB_TOKEN"], &[("a", "bot")]);
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
