//! Overlay dynamic outputs on the static-only name table without renaming unrelated items.

use std::collections::BTreeSet;

use asm_proto::generators::{GenerationChoice, GenerationGrant, SourceKind};
use asm_proto::names::resolve_catalog_name;
use asm_proto::wire::{GeneratorOption, SecretEntry, SecretKind};

use super::Core;
use crate::error::{CoreError, Result};
use crate::vault::names::{NamedSecret, VaultListing, compute_names};
use crate::vault::VaultStatus;

#[cfg(test)]
use asm_proto::generators::GITHUB_TOKEN_NAMES;

#[derive(Debug, Clone)]
pub(crate) struct GeneratedOutput {
    pub canonical_name: &'static str,
    aliases: &'static [&'static str],
    pub choices: Vec<GenerationChoice>,
    pub static_collisions: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct CatalogGeneratedTarget {
    pub requested_name: String,
    pub output_name: String,
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
    generated_group_by_wire_row: Vec<Option<usize>>,
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
        let group = self.generated_group_by_wire_row.get(resolved.entry_index)
            .ok_or_else(|| CoreError::internal("missing secret catalog row mapping"))?;
        let Some(group) = group else {
            if resolved.generated_output.is_some() {
                return Err(CoreError::internal("missing generated secret catalog row mapping"));
            }
            let entry = self.static_entries.get(resolved.entry_index)
                .ok_or_else(|| CoreError::internal("invalid static secret catalog row mapping"))?;
            return Ok(CatalogMatch::Vault(entry.clone()));
        };
        let output = self.generated.get(*group)
            .ok_or_else(|| CoreError::internal("invalid generated secret catalog row mapping"))?;
        if resolved.generated_output != Some(output.canonical_name) {
            return Err(CoreError::internal("incorrect generated secret catalog row mapping"));
        }
        let candidates = output.choices.iter().filter(|c| {
            resolved.pinned_generator_id.as_ref().is_none_or(|id| id == &c.generator_id)
        }).cloned().collect();
        Ok(CatalogMatch::Generated(CatalogGeneratedTarget {
            requested_name: resolved.canonical_key,
            output_name: output.canonical_name.to_owned(),
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
    let source = if generators.len() == 1 {
        generators[0].name.as_str()
    } else {
        match &choices[0].ceiling {
            GenerationGrant::GithubApp(_) => "GitHub Apps",
            GenerationGrant::Gcloud(_) | GenerationGrant::GcloudAccess(_) => "Google Cloud",
        }
    };
    SecretEntry {
        name,
        vault: source.to_owned(),
        kind: SecretKind::Single,
        fields: vec!["value".into()],
        lease: None,
        source_kind: SourceKind::Generator,
        generators,
        aliases,
    }
}

/// The static name table is computed before overlaying generated output groups.
fn build_catalog(listings: &[VaultListing], choices: Vec<GenerationChoice>, warnings: Vec<String>) -> SecretCatalog {
    let mut static_entries = compute_names(listings);
    let mut base_names: BTreeSet<_> = listings.iter().flat_map(|l| l.secrets.iter().map(|s| s.name.clone())).collect();
    let mut generated: Vec<GeneratedOutput> = Vec::new();
    for choice in choices {
        let names = choice.ceiling.output_names();
        if let Some(output) = generated.iter_mut().find(|output| output.canonical_name == names[0]) {
            output.choices.push(choice);
        } else {
            let static_collisions = names.iter().copied()
                .filter(|name| static_entries.iter().any(|n| static_base(n) == *name))
                .map(str::to_owned)
                .collect();
            base_names.extend(names.iter().map(|name| (*name).to_owned()));
            generated.push(GeneratedOutput {
                canonical_name: names[0], aliases: &names[1..], choices: vec![choice], static_collisions,
            });
        }
    }
    for n in &mut static_entries {
        if generated.iter().any(|output| output.static_collisions.iter().any(|name| name == static_base(n))) && !n.prefixed {
            n.display = format!("{}/{}", n.vault_name, n.display);
            n.prefixed = true;
        }
    }
    let mut wire_entries: Vec<_> = static_entries.iter().map(|n| SecretEntry {
        name: n.display.clone(), vault: n.vault_name.clone(), kind: n.meta.kind,
        fields: n.meta.fields.clone(), lease: None, source_kind: SourceKind::Vault,
        generators: Vec::new(), aliases: vec![format!("{}/{}", n.vault_name, static_base(n))],
    }).collect();
    let mut generated_group_by_wire_row = vec![None; wire_entries.len()];
    for (index, output) in generated.iter().enumerate() {
        let mut bare = std::iter::once(output.canonical_name)
            .chain(output.aliases.iter().copied())
            .filter(|name| !output.static_collisions.iter().any(|c| c.as_str() == *name));
        let mut push = |row| {
            wire_entries.push(row);
            generated_group_by_wire_row.push(Some(index));
        };
        if let Some(name) = bare.next() {
            push(generated_row(name.to_owned(), bare.map(str::to_owned).collect(), &output.choices));
        }
        if !output.static_collisions.is_empty() {
            let mut seen = BTreeSet::new();
            for choice in output.choices.iter().filter(|c| seen.insert(c.generator_id.as_str())) {
                push(generated_row(
                    format!("{}/{}", choice.name, output.canonical_name),
                    output.aliases.iter().map(|alias| format!("{}/{alias}", choice.name)).collect(),
                    std::slice::from_ref(choice),
                ));
            }
        }
    }
    SecretCatalog { static_entries, generated, wire_entries, warnings, generated_group_by_wire_row, base_names }
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
    use asm_proto::generators::{GCLOUD_TOKEN_NAME, GcloudAccessGrant, GcloudGrant, GithubGrant, GithubPermission, GithubRepository};
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

    fn gcloud_choice(name: &str) -> GenerationChoice {
        GenerationChoice {
            generator_id: format!("id-{name}"), name: name.into(), revision: 1,
            ceiling: GenerationGrant::Gcloud(GcloudGrant {
                service_account_unique_id: "123456789".into(),
                service_account_email: "bot@dev-project.iam.gserviceaccount.com".into(),
                scopes: vec!["https://www.googleapis.com/auth/devstorage.read_only".into()],
                project_id: None,
            }),
            available: true, unavailable_reason: None,
        }
    }

    fn connection_choice(name: &str) -> GenerationChoice {
        GenerationChoice { ceiling: GenerationGrant::GcloudAccess(GcloudAccessGrant::Connection),
            ..gcloud_choice(name) }
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
        let GenerationGrant::GithubApp(installation) = &mut second.ceiling else { unreachable!() };
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
        for &name in GITHUB_TOKEN_NAMES {
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

    #[test]
    fn catalog_resolves_bare_and_qualified_outputs_in_both_provider_orders() {
        let mut choices = vec![choice("gh-bot"), gcloud_choice("gcloud-dev")];
        for _ in 0..2 {
            let catalog = build_catalog(&listing(&["OTHER"]), choices.clone(), vec![]);
            for (bare, output, name) in [
                ("GITHUB_TOKEN", "GH_TOKEN", "gh-bot"),
                (GCLOUD_TOKEN_NAME, GCLOUD_TOKEN_NAME, "gcloud-dev"),
            ] {
                let target = catalog.resolve_generated(bare).unwrap().unwrap();
                assert_eq!(target.output_name, output);
                assert_eq!(target.requested_name, output);
                assert_eq!(target.pinned_generator_id, None);
                assert_eq!(target.candidates.len(), 1);
                assert_eq!(target.candidates[0].name, name);

                let qualified = format!("{name}/{bare}");
                let target = catalog.resolve_generated(&qualified).unwrap().unwrap();
                assert_eq!(target.requested_name, format!("{name}/{output}"));
                assert_eq!(target.pinned_generator_id, Some(format!("id-{name}")));
                assert_eq!(target.candidates.len(), 1);
                assert_eq!(target.candidates[0].name, name);
            }
            for wrong in ["gcloud-dev/GH_TOKEN", "gh-bot/CLOUDSDK_AUTH_ACCESS_TOKEN"] {
                assert_eq!(catalog.resolve(wrong).unwrap_err().code, asm_proto::ErrorCode::NotFound);
            }
            choices.reverse();
        }
    }

    #[test]
    fn catalog_maps_collision_qualified_rows_to_their_own_groups() {
        let mut choices = vec![
            choice("gh-first"), gcloud_choice("google-first"),
            choice("gh-second"), connection_choice("google-second"),
        ];
        for _ in 0..2 {
            let catalog = build_catalog(&listing(&["GH_TOKEN", GCLOUD_TOKEN_NAME, "OTHER"]), choices.clone(), vec![]);
            for (output, expected, unrelated) in [
                ("GH_TOKEN", ["gh-first", "gh-second"], "google-"),
                (GCLOUD_TOKEN_NAME, ["google-first", "google-second"], "gh-"),
            ] {
                let error = catalog.resolve(output).unwrap_err();
                assert_eq!(error.code, asm_proto::ErrorCode::Ambiguous);
                assert!(!error.message.contains(unrelated));
                assert!(matches!(catalog.resolve(&format!("vault/{output}")), Ok(CatalogMatch::Vault(_))));
                for name in expected {
                    let qualified = format!("{name}/{output}");
                    assert!(error.message.contains(&qualified));
                    let target = catalog.resolve_generated(&qualified).unwrap().unwrap();
                    assert_eq!(target.output_name, output);
                    assert_eq!(target.requested_name, qualified);
                    assert_eq!(target.candidates.len(), 1);
                    assert_eq!(target.candidates[0].name, name);
                }
            }
            let github = catalog.resolve_generated("GITHUB_TOKEN").unwrap().unwrap();
            assert_eq!(github.candidates.len(), 2);
            assert!(github.candidates.iter().all(|candidate| candidate.name.starts_with("gh-")));
            assert!(matches!(catalog.resolve("OTHER"), Ok(CatalogMatch::Vault(entry)) if entry.display == "OTHER"));
            choices.reverse();
        }
    }
}
