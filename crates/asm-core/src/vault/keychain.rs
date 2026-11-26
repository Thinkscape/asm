//! macOS login keychain vault (plan step 4): every generic-password and internet-password
//! item of the default keychain search list, except asm's own credentials (service
//! `net.thinkscape.asm`). Secure notes are generic passwords (`type` = `note` or
//! `desc` = `secure note`) and are exposed like any other generic password.
//!
//! Listing uses `ItemSearchOptions` with attributes only (no data, so no consent prompt)
//! and reads the raw `CFDictionary`. Reads and writes look the item up again by its
//! attributes, keep the exact match and address it through its item reference
//! (`kSecValueRef`); values are therefore only touched for the one approved item, and
//! macOS may show its own consent prompt for it.
//!
//! Internet-password attributes (`ptcl`, `atyp`) come back from the file keychain as
//! four-character strings, and `security_framework::passwords::get_internet_password`
//! queries them as numbers, which does not match such items; hence the raw `SecItem`
//! queries with the attribute values exactly as listed.

use std::collections::HashSet;

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::{CFString, CFStringRef};
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, SearchResult};
use security_framework::passwords::{self, PasswordOptions};
use security_framework_sys::base::{errSecItemNotFound, errSecSuccess};
use security_framework_sys::item::{
    kSecAttrAccount, kSecAttrAuthenticationType, kSecAttrPath, kSecAttrPort, kSecAttrProtocol,
    kSecAttrSecurityDomain, kSecAttrServer, kSecAttrService, kSecClass, kSecClassGenericPassword,
    kSecClassInternetPassword, kSecMatchLimit, kSecMatchLimitAll, kSecReturnAttributes,
    kSecReturnData, kSecReturnRef, kSecValueData, kSecValueRef,
};
use security_framework_sys::keychain_item::{SecItemCopyMatching, SecItemUpdate};

use super::{AddTarget, LoginMeta, SecretKind, SecretMeta, VaultProvider, VaultStatus, creds};
use crate::error::{CoreError, Result};

const SEP: char = '\u{1f}';
const ERR_USER_CANCELED: i32 = -128;
const ERR_INTERACTION_NOT_ALLOWED: i32 = -25308;
const ERR_AUTH_FAILED: i32 = -25293;

#[derive(Debug, Clone, PartialEq, Eq)]
enum ItemKey {
    Generic {
        svce: String,
        acct: String,
    },
    Internet {
        srvr: String,
        acct: String,
        ptcl: String,
        port: i64,
        path: String,
        atyp: String,
        sdmn: String,
    },
}

impl ItemKey {
    fn encode(&self) -> String {
        match self {
            ItemKey::Generic { svce, acct } => ["genp", svce, acct].join(&SEP.to_string()),
            ItemKey::Internet {
                srvr,
                acct,
                ptcl,
                port,
                path,
                atyp,
                sdmn,
            } => [
                "inet",
                srvr,
                acct,
                ptcl,
                &port.to_string(),
                path,
                atyp,
                sdmn,
            ]
            .join(&SEP.to_string()),
        }
    }

    fn decode(key: &str) -> Result<Self> {
        let parts: Vec<&str> = key.split(SEP).collect();
        let bad = || CoreError::not_found("unknown keychain item key");
        match parts.as_slice() {
            ["genp", svce, acct] => Ok(ItemKey::Generic {
                svce: (*svce).into(),
                acct: (*acct).into(),
            }),
            ["inet", srvr, acct, ptcl, port, path, atyp, sdmn] => Ok(ItemKey::Internet {
                srvr: (*srvr).into(),
                acct: (*acct).into(),
                ptcl: (*ptcl).into(),
                port: port.parse().map_err(|_| bad())?,
                path: (*path).into(),
                atyp: (*atyp).into(),
                sdmn: (*sdmn).into(),
            }),
            _ => Err(bad()),
        }
    }

    fn from_attrs(class: Class, a: &Attrs) -> Self {
        match class {
            Class::Generic => ItemKey::Generic {
                svce: a.string("svce"),
                acct: a.string("acct"),
            },
            Class::Internet => ItemKey::Internet {
                srvr: a.string("srvr"),
                acct: a.string("acct"),
                ptcl: a.fourcc("ptcl"),
                port: a.number("port").unwrap_or(0),
                path: a.string("path"),
                atyp: a.fourcc("atyp"),
                sdmn: a.string("sdmn"),
            },
        }
    }

    fn class(&self) -> Class {
        match self {
            ItemKey::Generic { .. } => Class::Generic,
            ItemKey::Internet { .. } => Class::Internet,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Generic,
    Internet,
}

impl Class {
    fn item_class(self) -> ItemClass {
        match self {
            Class::Generic => ItemClass::generic_password(),
            Class::Internet => ItemClass::internet_password(),
        }
    }
    fn sec_class(self) -> CFStringRef {
        unsafe {
            match self {
                Class::Generic => kSecClassGenericPassword,
                Class::Internet => kSecClassInternetPassword,
            }
        }
    }
}

/// Raw attribute dictionary of one keychain item.
struct Attrs(CFDictionary<CFString, CFType>);

impl Attrs {
    fn get(&self, key: &str) -> Option<CFType> {
        self.0.find(CFString::new(key)).map(|v| v.clone())
    }

    /// String attribute (CFString, or UTF-8 CFData); absent = "".
    fn string(&self, key: &str) -> String {
        let Some(v) = self.get(key) else {
            return String::new();
        };
        if let Some(s) = v.downcast::<CFString>() {
            return s.to_string();
        }
        if let Some(d) = v.downcast::<CFData>() {
            return String::from_utf8_lossy(d.bytes()).into_owned();
        }
        String::new()
    }

    fn number(&self, key: &str) -> Option<i64> {
        self.get(key)?.downcast::<CFNumber>()?.to_i64()
    }

    /// FourCharCode attribute as its four characters (CFString, CFNumber or CFData); absent = "".
    fn fourcc(&self, key: &str) -> String {
        let Some(v) = self.get(key) else {
            return String::new();
        };
        if let Some(s) = v.downcast::<CFString>() {
            return s.to_string();
        }
        let bytes: Vec<u8> = if let Some(n) = v.downcast::<CFNumber>() {
            match n.to_i64() {
                Some(0) | None => return String::new(),
                Some(x) => (x as u32).to_be_bytes().to_vec(),
            }
        } else if let Some(d) = v.downcast::<CFData>() {
            d.bytes().to_vec()
        } else {
            return String::new();
        };
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

fn key_str(k: CFStringRef) -> CFString {
    unsafe { CFString::wrap_under_get_rule(k) }
}

fn os_err(op: &str, status: i32) -> CoreError {
    match status {
        s if s == errSecItemNotFound => CoreError::not_found("the keychain item no longer exists"),
        ERR_USER_CANCELED | ERR_AUTH_FAILED => {
            CoreError::vault_unavailable(format!("macOS denied keychain {op}"))
        }
        ERR_INTERACTION_NOT_ALLOWED => CoreError::vault_unavailable("the login keychain is locked"),
        s => CoreError::vault_unavailable(format!("keychain {op} failed (OSStatus {s})")),
    }
}

fn search_attrs(class: Class, limit: Limit) -> Result<Vec<Attrs>> {
    let res = ItemSearchOptions::new()
        .class(class.item_class())
        .load_attributes(true)
        .load_data(false)
        .limit(limit)
        .search();
    let items = match res {
        Ok(items) => items,
        Err(e) if e.code() == errSecItemNotFound => return Ok(Vec::new()),
        Err(e) => return Err(os_err("listing", e.code())),
    };
    Ok(items
        .into_iter()
        .filter_map(|r| match r {
            SearchResult::Dict(d) => Some(Attrs(unsafe {
                CFDictionary::wrap_under_get_rule(d.as_concrete_TypeRef() as _)
            })),
            _ => None,
        })
        .collect())
}

fn meta_for(class: Class, a: &Attrs) -> Option<(SecretMeta, Option<String>)> {
    let key = ItemKey::from_attrs(class, a);
    let encoded = key.encode();
    // A separator inside an attribute would make the key ambiguous.
    if ItemKey::decode(&encoded).ok().as_ref() != Some(&key) {
        return None;
    }
    let label = a.string("labl");
    match key {
        ItemKey::Generic { svce, .. } => {
            if svce == creds::SERVICE {
                return None;
            }
            let name = if label.is_empty() {
                svce
            } else {
                label
            };
            Some((SecretMeta {
                key: encoded,
                name,
                kind: SecretKind::Single,
                fields: vec!["value".into()],
                uri_hosts: vec![],
                collections: vec![],
            }, None))
        }
        ItemKey::Internet { srvr, acct, .. } => {
            let uri_hosts = asm_proto::rules::normalize_host_pattern(&srvr)
                .map(|h| vec![h])
                .unwrap_or_default();
            let name = if label.is_empty() { srvr } else { label };
            Some((SecretMeta {
                key: encoded,
                name,
                kind: SecretKind::Login,
                fields: vec!["username".into(), "password".into()],
                uri_hosts,
                collections: vec![],
            }, (!acct.is_empty()).then_some(acct)))
        }
    }
}

fn list_attributes<T>(classes: &[Class], project: impl Fn(SecretMeta, Option<String>) -> T) -> Result<Vec<T>> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for &class in classes {
        for attrs in search_attrs(class, Limit::All)? {
            if let Some((meta, username)) = meta_for(class, &attrs)
                && !meta.name.is_empty() && seen.insert(meta.key.clone())
            {
                out.push(project(meta, username));
            }
        }
    }
    Ok(out)
}

/// Find the item reference (`kSecValueRef`) of the item whose attributes match `key` exactly.
fn find_ref(key: &ItemKey) -> Result<CFType> {
    let class = key.class();
    let mut q: Vec<(CFString, CFType)> = vec![
        (
            key_str(unsafe { kSecClass }),
            key_str(class.sec_class()).into_CFType(),
        ),
        (
            key_str(unsafe { kSecReturnAttributes }),
            CFBoolean::true_value().into_CFType(),
        ),
        (
            key_str(unsafe { kSecReturnRef }),
            CFBoolean::true_value().into_CFType(),
        ),
        (
            key_str(unsafe { kSecMatchLimit }),
            key_str(unsafe { kSecMatchLimitAll }).into_CFType(),
        ),
    ];
    let mut push_str = |k: CFStringRef, v: &str| {
        if !v.is_empty() {
            q.push((key_str(k), CFString::new(v).into_CFType()));
        }
    };
    unsafe {
        match key {
            ItemKey::Generic { svce, acct } => {
                push_str(kSecAttrService, svce);
                push_str(kSecAttrAccount, acct);
            }
            ItemKey::Internet {
                srvr,
                acct,
                ptcl,
                port: _,
                path,
                atyp,
                sdmn,
            } => {
                push_str(kSecAttrServer, srvr);
                push_str(kSecAttrAccount, acct);
                push_str(kSecAttrProtocol, ptcl);
                push_str(kSecAttrPath, path);
                push_str(kSecAttrAuthenticationType, atyp);
                push_str(kSecAttrSecurityDomain, sdmn);
            }
        }
    }
    if let ItemKey::Internet { port, .. } = key
        && *port != 0
    {
        q.push((
            key_str(unsafe { kSecAttrPort }),
            CFNumber::from(*port).into_CFType(),
        ));
    }
    let query = CFDictionary::from_CFType_pairs(&q);
    let mut ret = std::ptr::null();
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut ret) };
    if status != errSecSuccess {
        return Err(os_err("lookup", status));
    }
    if ret.is_null() {
        return Err(os_err("lookup", errSecItemNotFound));
    }
    let ret = unsafe { CFType::wrap_under_create_rule(ret) };
    let as_dict = |v: CFType| -> Option<CFDictionary<CFString, CFType>> {
        let d = v.downcast::<CFDictionary>()?;
        Some(unsafe { CFDictionary::wrap_under_get_rule(d.as_concrete_TypeRef() as _) })
    };
    let dicts: Vec<CFDictionary<CFString, CFType>> = if let Some(arr) = ret.downcast::<CFArray>() {
        arr.iter()
            .filter_map(|p| as_dict(unsafe { CFType::wrap_under_get_rule(*p) }))
            .collect()
    } else if let Some(d) = as_dict(ret) {
        vec![d]
    } else {
        vec![]
    };
    for d in dicts {
        let attrs = Attrs(d);
        if ItemKey::from_attrs(class, &attrs) == *key
            && let Some(r) = attrs.0.find(key_str(unsafe { kSecValueRef }))
        {
            return Ok(r.clone());
        }
    }
    Err(os_err("lookup", errSecItemNotFound))
}

fn ref_query(
    class: Class,
    item: &CFType,
    extra: Option<(CFStringRef, CFType)>,
) -> CFDictionary<CFString, CFType> {
    let mut q = vec![
        (
            key_str(unsafe { kSecClass }),
            key_str(class.sec_class()).into_CFType(),
        ),
        (key_str(unsafe { kSecValueRef }), item.clone()),
    ];
    if let Some((k, v)) = extra {
        q.push((key_str(k), v));
    }
    CFDictionary::from_CFType_pairs(&q)
}

fn read_value(key: &ItemKey) -> Result<String> {
    let item = find_ref(key)?;
    let q = ref_query(
        key.class(),
        &item,
        Some((
            unsafe { kSecReturnData },
            CFBoolean::true_value().into_CFType(),
        )),
    );
    let mut ret = std::ptr::null();
    let status = unsafe { SecItemCopyMatching(q.as_concrete_TypeRef(), &mut ret) };
    if status != errSecSuccess {
        return Err(os_err("read", status));
    }
    if ret.is_null() {
        return Err(os_err("read", errSecItemNotFound));
    }
    let ret = unsafe { CFType::wrap_under_create_rule(ret) };
    let data = ret
        .downcast::<CFData>()
        .ok_or_else(|| CoreError::vault_unavailable("keychain returned no data"))?;
    String::from_utf8(data.bytes().to_vec())
        .map_err(|_| CoreError::invalid("value is not UTF-8 text"))
}

fn write_value(key: &ItemKey, value: &str) -> Result<()> {
    let item = find_ref(key)?;
    let q = ref_query(key.class(), &item, None);
    let upd = CFDictionary::from_CFType_pairs(&[(
        key_str(unsafe { kSecValueData }),
        CFData::from_buffer(value.as_bytes()).into_CFType(),
    )]);
    let status = unsafe { SecItemUpdate(q.as_concrete_TypeRef(), upd.as_concrete_TypeRef()) };
    if status != errSecSuccess {
        return Err(os_err("update", status));
    }
    Ok(())
}

pub struct KeychainVault;

impl KeychainVault {
    pub fn new() -> Self {
        KeychainVault
    }
}

impl Default for KeychainVault {
    fn default() -> Self {
        Self::new()
    }
}

fn key_for(key: &str) -> Result<ItemKey> {
    let k = ItemKey::decode(key)?;
    if let ItemKey::Generic { svce, .. } = &k
        && svce == creds::SERVICE
    {
        return Err(CoreError::not_found("unknown keychain item key"));
    }
    Ok(k)
}

impl VaultProvider for KeychainVault {
    fn status(&self) -> VaultStatus {
        match search_attrs(Class::Generic, Limit::Max(1)) {
            Ok(_) => VaultStatus::Ready,
            Err(e) if e.message.contains("locked") => VaultStatus::Locked,
            Err(e) => VaultStatus::Error(e.message),
        }
    }

    fn list(&self) -> Result<Vec<SecretMeta>> {
        list_attributes(&[Class::Generic, Class::Internet], |meta, _| meta)
    }

    fn list_logins(&self) -> Result<Vec<LoginMeta>> {
        list_attributes(&[Class::Internet], |meta, username| LoginMeta { meta, username })
    }

    fn read_totp(&self, _key: &str) -> Result<zeroize::Zeroizing<String>> {
        Err(CoreError::not_found("keychain passwords have no authenticator"))
    }

    fn read(&self, key: &str) -> Result<Vec<(String, String)>> {
        let k = key_for(key)?;
        let value = read_value(&k)?;
        Ok(match &k {
            ItemKey::Generic { .. } => vec![("value".into(), value)],
            ItemKey::Internet { acct, .. } => vec![
                ("username".into(), acct.clone()),
                ("password".into(), value),
            ],
        })
    }

    fn update(&self, key: &str, field: &str, value: &str) -> Result<()> {
        let k = key_for(key)?;
        let expected = match k {
            ItemKey::Generic { .. } => "value",
            ItemKey::Internet { .. } => "password",
        };
        if field != expected {
            return Err(CoreError::invalid(format!(
                "this keychain item can only update the field \"{expected}\", not {field:?}"
            )));
        }
        write_value(&k, value)
    }

    fn add(&self, name: &str, value: &str, _target: &AddTarget) -> Result<()> {
        if name == creds::SERVICE {
            return Err(CoreError::invalid("reserved name"));
        }
        let mut opts = PasswordOptions::new_generic_password(name, "asm");
        opts.set_label(name);
        passwords::set_generic_password_options(value.as_bytes(), opts)
            .map_err(|e| os_err("add", e.code()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internet_login_label_comes_from_attributes_alone() {
        let pair = |k, v| (CFString::new(k), CFString::new(v).as_CFType());
        let attrs = Attrs(CFDictionary::from_CFType_pairs(&[
            pair("srvr", "EXAMPLE.COM"), pair("acct", "UserAccount"), pair("labl", "Social"),
        ]));
        let (meta, username) = meta_for(Class::Internet, &attrs).unwrap();
        assert_eq!(username.as_deref(), Some("UserAccount"));
        assert_eq!(meta.name, "Social");
        assert_eq!(meta.uri_hosts, ["example.com"]);
        let (_, username) = meta_for(Class::Generic, &attrs).unwrap();
        assert!(username.is_none());
    }

    #[test]
    fn key_round_trip() {
        let g = ItemKey::Generic {
            svce: "svc".into(),
            acct: "".into(),
        };
        assert_eq!(g.encode(), "genp\u{1f}svc\u{1f}");
        assert_eq!(ItemKey::decode(&g.encode()).unwrap(), g);
        let i = ItemKey::Internet {
            srvr: "example.com".into(),
            acct: "me".into(),
            ptcl: "htps".into(),
            port: 443,
            path: "".into(),
            atyp: "form".into(),
            sdmn: "".into(),
        };
        assert_eq!(ItemKey::decode(&i.encode()).unwrap(), i);
        assert!(ItemKey::decode("genp\u{1f}only").is_err());
        assert!(
            key_for(
                &ItemKey::Generic {
                    svce: creds::SERVICE.into(),
                    acct: "x:client_secret".into()
                }
                .encode()
            )
            .is_err()
        );
    }

    /// Lists the real login keychain (attributes only, no values) and round-trips a
    /// throwaway generic and internet password created by the test. Run with `--ignored`.
    #[test]
    #[ignore]
    fn live_login_keychain() {
        let v = KeychainVault::new();
        assert_eq!(v.status(), VaultStatus::Ready);
        let all = v.list().unwrap();
        let generic = all.iter().filter(|m| m.kind == SecretKind::Single).count();
        let internet = all.iter().filter(|m| m.kind == SecretKind::Login).count();
        println!("keychain: {generic} generic, {internet} internet passwords listed");
        assert!(
            all.iter()
                .all(|m| !m.key.starts_with(&format!("genp{SEP}{}", creds::SERVICE)))
        );

        // Generic: add → list → read → update → read.
        let name = format!("asm-test-{}", asm_proto::crypto::new_uuid_v4());
        v.add(&name, "first-value", &AddTarget::default()).unwrap();
        let m = v
            .list()
            .unwrap()
            .into_iter()
            .find(|m| m.name == name)
            .expect("added item listed");
        assert_eq!(
            v.read(&m.key).unwrap(),
            [("value".to_owned(), "first-value".to_owned())]
        );
        v.update(&m.key, "value", "second-value").unwrap();
        assert_eq!(v.read(&m.key).unwrap()[0].1, "second-value");
        passwords::delete_generic_password(&name, "asm").unwrap();
        assert_eq!(
            v.read(&m.key).unwrap_err().code,
            asm_proto::ErrorCode::NotFound
        );

        // Internet password with string protocol/auth attributes, as Safari and others store them.
        let server = format!("{name}.invalid");
        let add = CFDictionary::from_CFType_pairs(&[
            (
                key_str(unsafe { kSecClass }),
                key_str(unsafe { kSecClassInternetPassword }).into_CFType(),
            ),
            (
                key_str(unsafe { kSecAttrServer }),
                CFString::new(&server).into_CFType(),
            ),
            (
                key_str(unsafe { kSecAttrAccount }),
                CFString::new("probe-user").into_CFType(),
            ),
            (
                key_str(unsafe { kSecAttrProtocol }),
                CFString::new("htps").into_CFType(),
            ),
            (
                key_str(unsafe { kSecAttrAuthenticationType }),
                CFString::new("form").into_CFType(),
            ),
            (
                key_str(unsafe { kSecValueData }),
                CFData::from_buffer(b"inet-value").into_CFType(),
            ),
        ]);
        let st = unsafe {
            security_framework_sys::keychain_item::SecItemAdd(
                add.as_concrete_TypeRef(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(st, errSecSuccess);
        let m = v
            .list()
            .unwrap()
            .into_iter()
            .find(|m| m.name == server)
            .expect("internet item listed");
        assert_eq!(m.kind, SecretKind::Login);
        assert_eq!(m.uri_hosts, std::slice::from_ref(&server));
        assert_eq!(
            v.read(&m.key).unwrap(),
            [
                ("username".to_owned(), "probe-user".to_owned()),
                ("password".to_owned(), "inet-value".to_owned())
            ]
        );
        v.update(&m.key, "password", "inet-value-2").unwrap();
        assert_eq!(v.read(&m.key).unwrap()[1].1, "inet-value-2");
        assert_eq!(
            v.update(&m.key, "username", "x").unwrap_err().code,
            asm_proto::ErrorCode::Invalid
        );
        let item = find_ref(&ItemKey::decode(&m.key).unwrap()).unwrap();
        let q = ref_query(Class::Internet, &item, None);
        assert_eq!(
            unsafe {
                security_framework_sys::keychain_item::SecItemDelete(q.as_concrete_TypeRef())
            },
            errSecSuccess
        );
    }
}
