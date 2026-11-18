//! Overlay dynamic outputs on the static-only name table without renaming unrelated items.

use std::collections::BTreeSet;

use asm_proto::generators::{GITHUB_TOKEN_ALIAS, GITHUB_TOKEN_NAME, GenerationChoice, SourceKind};
use asm_proto::names::resolve_catalog_name;
use asm_proto::wire::{GeneratorOption, SecretEntry, SecretKind};

use super::Core;
use crate::error::{CoreError, Result};
use crate::vault::names::{NamedSecret, VaultListing, compute_names};
use crate::vault::VaultStatus;

const GITHUB_NAMES: [&str; 2] = [GITHUB_TOKEN_NAME, GITHUB_TOKEN_ALIAS];

#[derive(Debug, Clone)]
pub(crate) struct GeneratedOutput {
    pub canonical_name: String,
    pub aliases: Vec<String>,
    pub choices: Vec<GenerationChoice>,
    pub static_collisions: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct CatalogGeneratedTarget {
    pub requested_name: String,
    pub pinned_generator_id: Option<String>,
    pub candidates: Vec<GenerationChoice>,
}

#[derive(Debug, Clone)]
pub(crate) enum CatalogMatch {
    Vault(NamedSecret),
    Generated(CatalogGeneratedTarget),
}

pub(crate) struct SecretCatalog {
    pub static_entries: Vec<NamedSecret>,
    pub generated: Vec<GeneratedOutput>,
    pub wire_entries: Vec<SecretEntry>,
    pub warnings: Vec<String>,
    base_names: BTreeSet<String>,
}

fn static_base(n: &NamedSecret) -> &str {
    if n.prefixed {
        n.display.strip_prefix(&n.vault_name)
            .and_then(|suffix| suffix.strip_prefix('/')).unwrap_or(&n.display)
    } else {
        &n.display
    }
}

impl SecretCatalog {
    pub fn has_base_name(&self, name: &str) -> bool {
        self.base_names.contains(name)
    }

    pub fn resolve(&self, query: &str) -> Result<CatalogMatch> {
        let resolved = resolve_catalog_name(query, &self.wire_entries)?;
        if let Some(n) = self.static_entries.get(resolved.entry_index) {
            return Ok(CatalogMatch::Vault(n.clone()));
        }
        let output = self.generated.first().ok_or_else(|| CoreError::not_found("secret not found"))?;
        let candidates = output.choices.iter().filter(|c| {
            resolved.pinned_generator_id.as_ref().is_none_or(|id| id == &c.generator_id)
        }).cloned().collect();
        Ok(CatalogMatch::Generated(CatalogGeneratedTarget {
            requested_name: resolved.canonical_key,
            pinned_generator_id: resolved.pinned_generator_id,
            candidates,
        }))
    }

    #[cfg(test)]
    fn resolve_generated(&self, query: &str) -> Result<Option<CatalogGeneratedTarget>> {
        match self.resolve(query) {
            Ok(CatalogMatch::Generated(target)) => Ok(Some(target)),
            Ok(CatalogMatch::Vault(_)) => Ok(None),
            Err(e) if e.code == asm_proto::ErrorCode::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

fn generated_row(name: String, aliases: Vec<String>, choices: &[GenerationChoice]) -> SecretEntry {
    let mut seen = BTreeSet::new();
    let generators: Vec<_> = choices.iter().filter(|c| seen.insert(c.generator_id.as_str()))
        .map(|c| GeneratorOption { generator_id: c.generator_id.clone(), name: c.name.clone(), available: c.available })
        .collect();
    SecretEntry {
        name,
        vault: if generators.len() == 1 { generators[0].name.clone() } else { "GitHub Apps".into() },
        kind: SecretKind::Single,
        fields: vec!["value".into()],
        lease: None,
        source_kind: SourceKind::Generator,
        generators,
        aliases,
    }
}

/// The static name table is computed before applying the two fixed generated aliases.
fn build_catalog(listings: &[VaultListing], choices: Vec<GenerationChoice>, warnings: Vec<String>) -> SecretCatalog {
    let mut static_entries = compute_names(listings);
    let mut base_names: BTreeSet<_> = listings.iter().flat_map(|l| l.secrets.iter().map(|s| s.name.clone())).collect();
    let collisions: Vec<String> = if choices.is_empty() { Vec::new() } else {
        GITHUB_NAMES.iter().filter(|name| static_entries.iter().any(|n| static_base(n) == **name))
            .map(|n| (*n).to_string()).collect()
    };
    for n in &mut static_entries {
        if collisions.iter().any(|name| name == static_base(n)) && !n.prefixed {
            n.display = format!("{}/{}", n.vault_name, n.display);
            n.prefixed = true;
        }
    }
    let mut wire_entries: Vec<_> = static_entries.iter().map(|n| SecretEntry {
        name: n.display.clone(), vault: n.vault_name.clone(), kind: n.meta.kind,
        fields: n.meta.fields.clone(), lease: None, source_kind: SourceKind::Vault,
        generators: Vec::new(), aliases: vec![format!("{}/{}", n.vault_name, static_base(n))],
    }).collect();
    let mut generated = Vec::new();
    if !choices.is_empty() {
        let output = GeneratedOutput {
            canonical_name: GITHUB_NAMES[0].into(),
            aliases: vec![GITHUB_NAMES[1].into()],
            choices,
            static_collisions: collisions,
        };
        base_names.insert(output.canonical_name.clone());
        base_names.extend(output.aliases.iter().cloned());
        let mut bare = std::iter::once(output.canonical_name.as_str())
            .chain(output.aliases.iter().map(String::as_str))
            .filter(|name| !output.static_collisions.iter().any(|c| c == name));
        if let Some(name) = bare.next() {
            wire_entries.push(generated_row(name.into(), bare.map(str::to_owned).collect(), &output.choices));
        }
        if !output.static_collisions.is_empty() {
            let mut seen = BTreeSet::new();
            for choice in output.choices.iter().filter(|c| seen.insert(c.generator_id.as_str())) {
                wire_entries.push(generated_row(
                    format!("{}/{}", choice.name, output.canonical_name),
                    output.aliases.iter().map(|alias| format!("{}/{alias}", choice.name)).collect(),
                    std::slice::from_ref(choice),
                ));
            }
        }
        generated.push(output);
    }
    SecretCatalog { static_entries, generated, wire_entries, warnings, base_names }
}

impl Core {
    pub(crate) fn secret_catalog(&self) -> Result<SecretCatalog> {
        let (listings, mut warnings) = self.registry.listings();
        for v in self.registry.all() {
            match v.provider.status() {
                VaultStatus::Ready => {},
                VaultStatus::Locked => warnings.push(format!("{}: vault is locked", v.name)),
                VaultStatus::Error(e) => warnings.push(format!("{}: {e}", v.name)),
            }
        }
        let mut choices = Vec::new();
        for entry in self.generators.entries() {
            choices.extend(entry.record.config.ceilings().map(|ceiling| GenerationChoice {
                generator_id: entry.record.id.clone(), name: entry.record.name.clone(), revision: entry.record.revision,
                ceiling,
                available: entry.generator.is_some(), unavailable_reason: entry.unavailable_reason.clone(),
            }));
        }
        warnings.sort();
        warnings.dedup();
        Ok(build_catalog(&listings, choices, warnings))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asm_proto::generators::{GenerationGrant, GithubGrant, GithubPermission, GithubRepository};
    use crate::vault::SecretMeta;

    fn listing(names: &[&str]) -> Vec<VaultListing> {
        vec![VaultListing { vault_id: "vault-id".into(), vault_name: "vault".into(), secrets: names.iter().map(|name| SecretMeta {
            key: (*name).into(), name: (*name).into(), kind: SecretKind::Single, fields: vec!["value".into()], uri_hosts: vec![],
        }).collect() }]
    }
    fn choice(name: &str) -> GenerationChoice {
        GenerationChoice { generator_id: format!("id-{name}"), name: name.into(), revision: 1,
            ceiling: GenerationGrant::GithubApp(GithubGrant { installation_id: 10, repositories: vec![GithubRepository { id: 1, full_name: "acme/web".into() }], permissions: [("metadata".into(), GithubPermission::Read)].into() }), available: true, unavailable_reason: None }
    }
    #[test]
    fn catalog_aliases_share_identity_and_pin_only_qualified_requests() {
        let c = build_catalog(&listing(&["OTHER"]), vec![choice("release-bot"), choice("review-bot")], vec![]);
        assert_eq!(c.wire_entries.len(), 2);
        let a = c.resolve_generated("GH_TOKEN").unwrap().unwrap();
        let b = c.resolve_generated("GITHUB_TOKEN").unwrap().unwrap();
        assert_eq!(a.requested_name, b.requested_name);
        assert_eq!(a.candidates.len(), 2);
        let pinned = c.resolve_generated("review-bot/GITHUB_TOKEN").unwrap().unwrap();
        assert_eq!(pinned.requested_name, "review-bot/GH_TOKEN");
        assert_eq!(pinned.candidates[0].generator_id, "id-review-bot");
    }
    #[test]
    fn catalog_advertises_an_app_once_but_routes_all_its_installations() {
        let first = choice("bot");
        let mut second = first.clone();
        let GenerationGrant::GithubApp(installation) = &mut second.ceiling;
        installation.installation_id = 20;
        let catalog = build_catalog(&listing(&["GH_TOKEN", "GITHUB_TOKEN"]), vec![first, second], vec![]);
        let generated: Vec<_> = catalog.wire_entries.iter().filter(|entry| entry.source_kind == SourceKind::Generator).collect();
        assert_eq!(generated.len(), 1);
        assert_eq!(generated[0].generators.len(), 1);
        assert_eq!(generated[0].vault, "bot");
        let pinned = catalog.resolve_generated("bot/GITHUB_TOKEN").unwrap().unwrap();
        assert_eq!(pinned.pinned_generator_id.as_deref(), Some("id-bot"));
        assert_eq!(pinned.candidates.len(), 2);
    }
    #[test]
    fn catalog_collision_changes_only_colliding_static_spelling() {
        let c = build_catalog(&listing(&["GITHUB_TOKEN", "OTHER"]), vec![choice("bot")], vec![]);
        assert_eq!(c.static_entries[0].display, "vault/GITHUB_TOKEN");
        assert_eq!(c.static_entries[1].display, "OTHER");
        assert!(!c.static_entries[1].prefixed);
        assert!(matches!(c.resolve("GITHUB_TOKEN"), Err(e) if e.code == asm_proto::ErrorCode::Ambiguous));
        assert!(matches!(c.resolve("vault/GITHUB_TOKEN"), Ok(CatalogMatch::Vault(_))));
        assert_eq!(c.resolve_generated("GH_TOKEN").unwrap().unwrap().requested_name, "GH_TOKEN");
    }
    #[test]
    fn catalog_unavailable_choices_remain_visible_without_reserving_absent_aliases() {
        let empty = build_catalog(&listing(&["OTHER"]), vec![], vec![]);
        assert!(!empty.has_base_name("GH_TOKEN"));
        let mut unavailable = choice("bot"); unavailable.available = false; unavailable.unavailable_reason = Some("key unavailable".into());
        let c = build_catalog(&[], vec![unavailable], vec![]);
        assert!(c.has_base_name("GITHUB_TOKEN"));
        assert!(!c.wire_entries[0].generators[0].available);
    }
    #[test]
    fn catalog_both_collisions_require_source_qualification() {
        let c = build_catalog(&listing(&["GH_TOKEN", "GITHUB_TOKEN", "OTHER"]), vec![choice("one"), choice("two")], vec![]);
        for name in GITHUB_NAMES {
            assert!(matches!(c.resolve(name), Err(e) if e.code == asm_proto::ErrorCode::Ambiguous));
            assert!(matches!(c.resolve(&format!("vault/{name}")), Ok(CatalogMatch::Vault(_))));
            let generated = c.resolve_generated(&format!("two/{name}")).unwrap().unwrap();
            assert_eq!(generated.pinned_generator_id.as_deref(), Some("id-two"));
            assert_eq!(generated.requested_name, "two/GH_TOKEN");
        }
        assert_eq!(c.static_entries[2].display, "OTHER");
        assert!(c.wire_entries.iter().filter(|e| e.source_kind == SourceKind::Generator).all(|e| e.name.contains('/')));
    }

    #[test]
    fn catalog_static_aliases_remain_independent_without_generators() {
        let c = build_catalog(&listing(&["GH_TOKEN", "GITHUB_TOKEN"]), vec![], vec![]);
        let CatalogMatch::Vault(a) = c.resolve("GH_TOKEN").unwrap() else { panic!("static origin lost") };
        let CatalogMatch::Vault(b) = c.resolve("GITHUB_TOKEN").unwrap() else { panic!("static origin lost") };
        assert_ne!(a.meta.key, b.meta.key);
        assert_eq!(a.display, "GH_TOKEN");
        assert_eq!(b.display, "GITHUB_TOKEN");
    }

    #[test]
    fn catalog_literal_source_prefix_has_its_own_static_identity() {
        let c = build_catalog(&listing(&["vault/X", "X"]), vec![], vec![]);
        let literal = resolve_catalog_name("vault/vault/X", &c.wire_entries).unwrap();
        let ordinary = resolve_catalog_name("vault/X", &c.wire_entries).unwrap();
        assert_ne!(literal.canonical_key, ordinary.canonical_key);
        assert_eq!(literal.canonical_key, "vault/vault/X");
        assert_eq!(ordinary.canonical_key, "vault/X");
    }
}
