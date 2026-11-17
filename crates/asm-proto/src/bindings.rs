//! File/environment bindings: `[DEST=]SOURCE[::FIELD]`. A backslash escapes
//! the next character; only unescaped outer whitespace is trimmed. Shell users
//! should single-quote bindings so these escapes reach ASM unchanged.

use crate::ApiError;
use crate::names::resolve_catalog_name;
use crate::wire::SecretEntry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretBinding {
    pub destination: Option<String>,
    pub source: String,
    pub field: Option<String>,
}

#[derive(Clone, Copy)]
struct Token {
    character: char,
    escaped: bool,
}

fn tokenize(input: &str) -> Result<Vec<Token>, ApiError> {
    let mut tokens = Vec::with_capacity(input.len());
    let mut characters = input.chars();
    while let Some(character) = characters.next() {
        if character == '\\' {
            let character = characters.next().ok_or_else(|| ApiError::invalid("binding has a dangling escape"))?;
            tokens.push(Token { character, escaped: true });
        } else {
            tokens.push(Token { character, escaped: false });
        }
    }
    Ok(tokens)
}

/// Environment-variable destination grammar, shared by get and exec.
pub fn valid_destination(destination: &str) -> bool {
    let mut bytes = destination.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn decode(tokens: &[Token]) -> String {
    tokens.iter().map(|t| t.character).collect()
}

fn parse_tokens(mut tokens: &[Token]) -> Result<SecretBinding, ApiError> {
    let outer_space = |t: &Token| !t.escaped && t.character.is_whitespace();
    while tokens.first().is_some_and(outer_space) {
        tokens = &tokens[1..];
    }
    while tokens.last().is_some_and(outer_space) {
        tokens = &tokens[..tokens.len() - 1];
    }
    if tokens.is_empty() {
        return Err(ApiError::invalid("binding must not be empty"));
    }
    let mut destination_separator = None;
    let mut field_separator = None;
    let mut i = 0;
    while i < tokens.len() {
        let token = tokens[i];
        if !token.escaped {
            match token.character {
                ',' => return Err(ApiError::invalid("get accepts one binding; escape a literal comma with a backslash")),
                '=' => {
                    if destination_separator.is_some() || field_separator.is_some() {
                        return Err(ApiError::invalid("a binding accepts at most one =, before ::; escape literal delimiters"));
                    }
                    destination_separator = Some(i);
                }
                ':' if tokens.get(i + 1).is_some_and(|next| !next.escaped && next.character == ':') => {
                    if field_separator.replace(i).is_some() {
                        return Err(ApiError::invalid("a binding accepts at most one ::; escape literal delimiters"));
                    }
                    i += 1;
                }
                _ => {}
            }
        }
        i += 1;
    }
    let destination = destination_separator.map(|end| decode(&tokens[..end]));
    if destination.as_deref().is_some_and(|value| !valid_destination(value)) {
        return Err(ApiError::invalid("binding destination must match [A-Za-z_][A-Za-z0-9_]*"));
    }
    let start = destination_separator.map_or(0, |i| i + 1);
    let end = field_separator.unwrap_or(tokens.len());
    if start == end {
        return Err(ApiError::invalid("binding source must not be empty"));
    }
    let field = if let Some(separator) = field_separator {
        if separator + 2 == tokens.len() {
            return Err(ApiError::invalid("binding field must not be empty"));
        }
        Some(decode(&tokens[separator + 2..]))
    } else {
        None
    };
    Ok(SecretBinding { destination, source: decode(&tokens[start..end]), field })
}

/// Parse exactly one binding, without catalog lookup. Dots and individual
/// colons are literal. Escaped separators never become grammar delimiters.
pub fn parse_binding(input: &str) -> Result<SecretBinding, ApiError> {
    parse_tokens(&tokenize(input)?)
}

/// Parse an exec list, preserving input order and leaving identity/destination
/// deduplication to the caller after catalog resolution.
pub fn parse_bindings(input: &str) -> Result<Vec<SecretBinding>, ApiError> {
    let tokens = tokenize(input)?;
    tokens.split(|t| !t.escaped && t.character == ',').map(parse_tokens).collect()
}

/// Get's legacy-name guard. A literal item such as `A=b` must not silently
/// become destination A/source b. Exec deliberately always uses the grammar.
/// Unknown plain names still parse, allowing the manager's static fallback.
pub fn parse_get_binding(input: &str, entries: &[SecretEntry]) -> Result<SecretBinding, ApiError> {
    let parsed = parse_binding(input);
    let changes_interpretation = match &parsed {
        Ok(binding) => binding.destination.is_some() || binding.field.is_some() || binding.source != input.trim(),
        Err(_) => true,
    };
    if changes_interpretation && resolve_catalog_name(input, entries).is_ok() {
        return Err(ApiError::ambiguous("binding also names a literal secret; escape literal delimiters (A\\=b, item\\:\\:literal, or \\\\ for a backslash), or qualify the source"));
    }
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generators::SourceKind;
    use crate::wire::SecretKind;

    #[test]
    fn binding_grammar_preserves_names_fields_and_escapes() {
        let binding = parse_binding(" NAME=Vaultwarden/google::username ").unwrap();
        assert_eq!(binding, SecretBinding { destination: Some("NAME".into()), source: "Vaultwarden/google".into(), field: Some("username".into()) });
        let binding = parse_binding(r"NAME=work/item\,with\,commas::field").unwrap();
        assert_eq!(binding.source, "work/item,with,commas");
        assert_eq!(binding.field.as_deref(), Some("field"));
        let binding = parse_binding(r"NAME=work/item\:\:literal::value").unwrap();
        assert_eq!(binding.source, "work/item::literal");
        assert_eq!(binding.field.as_deref(), Some("value"));
        assert_eq!(parse_binding(r"A\=b").unwrap().source, "A=b");
        assert_eq!(parse_binding(r"item\\name").unwrap().source, "item\\name");
        assert_eq!(parse_binding("a.b::field.name").unwrap().field.as_deref(), Some("field.name"));
        assert_eq!(parse_binding("a:b").unwrap().source, "a:b");
        assert_eq!(parse_binding(r"\ item\ ").unwrap().source, " item ");
        assert_eq!(parse_binding(r"X=a\=b::field\:\:name").unwrap().field.as_deref(), Some("field::name"));
    }

    #[test]
    fn comma_lists_only_split_unescaped_delimiters() {
        let bindings = parse_bindings(r"GH_TOKEN, NAME=work/a\,b::password,NAME=work/a\,b::password").unwrap();
        assert_eq!(bindings.len(), 3);
        assert_eq!(bindings[0].source, "GH_TOKEN");
        assert_eq!(bindings[1].source, "work/a,b");
        assert_eq!(bindings[1], bindings[2]);
        assert_eq!(parse_bindings(r"a\,b").unwrap().len(), 1);
    }

    #[test]
    fn malformed_bindings_are_invalid() {
        for input in ["", " ", "=item", "DEST=", "::field", "item::", "A=B=C", "A::B=C", "A::B::C", "9X=item", "X-Y=item", "é=item", "X =item", "a,b", "item\\"] {
            assert!(parse_binding(input).is_err(), "{input:?}");
        }
        for input in ["", ",", "a,", ",a", "a, ,b", "a,b\\"] {
            assert!(parse_bindings(input).is_err(), "{input:?}");
        }
        for destination in ["A", "_", "_A0", "abc_123"] {
            assert!(valid_destination(destination));
        }
    }

    #[test]
    fn get_rejects_literal_name_reinterpretation_but_accepts_escaping() {
        let entries = ["A=b", "item::literal", "A=B=C", "item\\name", "item,with,commas"].map(|name| SecretEntry {
            name: name.into(), vault: "work".into(), kind: SecretKind::Single,
            fields: vec!["value".into()], lease: None, source_kind: SourceKind::Vault,
            generators: vec![], aliases: vec![],
        });
        for name in ["A=b", "item::literal", "A=B=C", "item\\name", "item,with,commas"] {
            assert_eq!(parse_get_binding(name, &entries).unwrap_err().code, crate::ErrorCode::Ambiguous);
        }
        assert_eq!(parse_get_binding(r"A\=b", &entries).unwrap().source, "A=b");
        assert_eq!(parse_get_binding(r"item\:\:literal", &entries).unwrap().source, "item::literal");
        assert_eq!(parse_get_binding(r"item\\name", &entries).unwrap().source, "item\\name");
        assert_eq!(parse_get_binding(r"item\,with\,commas", &entries).unwrap().source, "item,with,commas");
        assert_eq!(parse_get_binding("unknown", &entries).unwrap().source, "unknown");
        assert_eq!(parse_get_binding("DEST=unknown::field", &entries).unwrap().destination.as_deref(), Some("DEST"));
    }
}
