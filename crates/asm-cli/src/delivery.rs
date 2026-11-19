use asm_proto::wire::LeaseMode;
use serde::Serialize;

/// Describe the delivered field, not the requested mode or the value's spelling.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Delivery {
    Raw,
    Sentinel,
    /// Older managers reported the lease mode but not which fields were substituted.
    UnspecifiedSentinelField,
}

impl Delivery {
    pub(crate) fn from_field(mode: LeaseMode, substituted: Option<bool>) -> Self {
        match (mode, substituted) {
            (LeaseMode::Raw, _) | (_, Some(false)) => Self::Raw,
            (LeaseMode::Sentinel, Some(true)) => Self::Sentinel,
            (LeaseMode::Sentinel, None) => Self::UnspecifiedSentinelField,
        }
    }

    pub(crate) fn report(self, destination: &str) {
        let description = match self {
            Self::Raw => "raw (real value; no ASM proxy required)",
            Self::Sentinel => "sentinel (requires the ASM proxy)",
            Self::UnspecifiedSentinelField => "sentinel lease (manager did not identify individual substituted fields; use the ASM proxy)",
        };
        eprintln!("delivery: {destination}: {description}");
    }
}

pub(crate) fn proxy_hint() {
    eprintln!("Use sentinels through the ASM proxy for approved HTTPS hosts.\n  Current shell: eval \"$(asm proxy-env)\"\n  Automatic proxy and CA setup for static secrets: asm exec --sentinel BINDINGS -- COMMAND [ARG...]");
}
