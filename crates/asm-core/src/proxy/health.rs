//! Proxy health model: the cause of a failure taken from iron-proxy's log, and the
//! Running / Starting / Down / Unhealthy state machine with its timing rules.

use std::time::{Duration, Instant, SystemTime};

/// An outage counts as Down after this long (restarts that recover sooner are transient).
pub const DOWN_AFTER: Duration = Duration::from_secs(5);
/// A running child whose `/healthz` keeps failing is Unhealthy after this long.
pub const UNHEALTHY_AFTER: Duration = Duration::from_secs(10);

/// The failure cause in one (already redacted) log line: for a JSON line with level
/// `ERROR`, `msg: error` (either alone when the other is missing); for a plain
/// `error: …` line (iron-proxy's start-up errors), the text after the prefix.
pub fn error_cause(line: &str) -> Option<String> {
    let line = line.trim();
    if let Some(rest) = line.strip_prefix("error: ") {
        return Some(rest.trim().to_string()).filter(|s| !s.is_empty());
    }
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    if !v.get("level")?.as_str()?.eq_ignore_ascii_case("ERROR") {
        return None;
    }
    let msg = v
        .get("msg")
        .and_then(|m| m.as_str())
        .filter(|s| !s.is_empty());
    let err = v
        .get("error")
        .and_then(|m| m.as_str())
        .filter(|s| !s.is_empty());
    match (msg, err) {
        (Some(m), Some(e)) => Some(format!("{m}: {e}")),
        (Some(s), None) | (None, Some(s)) => Some(s.to_string()),
        (None, None) => None,
    }
}

/// A shutdown that iron-proxy logged without an error (someone signalled it), as a cause:
/// `iron-proxy was stopped by a signal (terminated)`. Errors take precedence.
pub fn stop_cause(line: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    if v.get("msg")?.as_str()? != "received signal, shutting down" {
        return None;
    }
    let sig = v
        .get("signal")
        .and_then(|s| s.as_str())
        .unwrap_or("unknown");
    Some(format!("iron-proxy was stopped by a signal ({sig})"))
}

/// The port of a `listen tcp <addr>:<port>: bind: address already in use` error.
pub fn port_in_use(cause: &str) -> Option<u16> {
    if !cause.contains("address already in use") {
        return None;
    }
    let (_, after) = cause.split_once("listen tcp")?;
    let addr = after.split_whitespace().next()?.trim_end_matches(':');
    addr.rsplit_once(':')?.1.parse().ok()
}

/// `port 7416 is in use by python3 (pid 123)`, or without a known holder
/// `port 7416 is already in use by another process`.
pub fn port_conflict_message(port: u16, holder: Option<(&str, i32)>) -> String {
    match holder {
        Some((name, pid)) => format!("port {port} is in use by {name} (pid {pid})"),
        None => format!("port {port} is already in use by another process"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    Running,
    /// Spawned and not healthy yet, or restarting after a failure (not Down yet).
    Starting,
    Down {
        reason: String,
        since: SystemTime,
    },
    /// Running, but `/healthz` has failed for longer than [`UNHEALTHY_AFTER`].
    Unhealthy {
        since: SystemTime,
    },
}

#[derive(Debug, Clone, Copy)]
struct Stamp {
    at: Instant,
    wall: SystemTime,
}

/// Something the activity log should record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    Down {
        reason: String,
    },
    Unhealthy,
    /// The incident ended (it had been Down or Unhealthy).
    Recovered {
        downtime: Duration,
        failures: u32,
    },
}

/// Health of the supervised child. Callers pass `now` (monotonic) and `wall` so timing
/// is testable.
#[derive(Debug, Default)]
pub struct Health {
    /// First failed exit or spawn since the proxy was last healthy.
    outage: Option<Stamp>,
    /// Since the running child is not healthy (spawned, or a health check failed).
    failing: Option<Stamp>,
    reason: Option<String>,
    failures: u32,
    /// The current incident was reported as Down / Unhealthy.
    reported_down: bool,
    reported_unhealthy: bool,
    /// Cause of the last `crashed`/`start_failed` row of this outage.
    logged_cause: Option<String>,
}

impl Health {
    /// The child exited or could not be started.
    pub fn failed(&mut self, reason: String, now: Instant, wall: SystemTime) {
        self.outage.get_or_insert(Stamp { at: now, wall });
        self.failing = None;
        self.failures += 1;
        self.reason = Some(reason);
    }

    /// A child was spawned (not healthy until a check passes).
    pub fn spawned(&mut self, now: Instant, wall: SystemTime) {
        self.failing = Some(Stamp { at: now, wall });
    }

    /// The child was stopped on purpose (restart, settings change, shutdown).
    pub fn stopped(&mut self) {
        self.failing = None;
    }

    /// Result of one `/healthz` check of the running child.
    pub fn checked(&mut self, ok: bool, now: Instant, wall: SystemTime) -> Option<Transition> {
        if !ok {
            self.failing.get_or_insert(Stamp { at: now, wall });
            return None;
        }
        let start = [self.outage, self.failing]
            .into_iter()
            .flatten()
            .map(|s| s.at)
            .min();
        let reported = self.reported_down || self.reported_unhealthy;
        let failures = self.failures;
        *self = Self::default();
        match (reported, start) {
            (true, Some(start)) => Some(Transition::Recovered {
                downtime: now.saturating_duration_since(start),
                failures,
            }),
            _ => None,
        }
    }

    pub fn healthy(&self, running: bool) -> bool {
        running && self.failing.is_none()
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Whether the current outage was already reported as Down.
    pub fn reported_down(&self) -> bool {
        self.reported_down
    }

    /// True once per distinct failure cause within an outage (crash rows are collapsed).
    pub fn should_log_failure(&mut self, cause: &str) -> bool {
        if self.logged_cause.as_deref() == Some(cause) {
            return false;
        }
        self.logged_cause = Some(cause.to_string());
        true
    }

    pub fn phase(&self, running: bool, now: Instant) -> Phase {
        if running && self.failing.is_none() {
            return Phase::Running;
        }
        if let Some(o) = self.outage
            && now.saturating_duration_since(o.at) >= DOWN_AFTER
        {
            return Phase::Down {
                reason: self
                    .reason
                    .clone()
                    .unwrap_or_else(|| "iron-proxy is not running".into()),
                since: o.wall,
            };
        }
        if running
            && let Some(f) = self.failing
            && now.saturating_duration_since(f.at) > UNHEALTHY_AFTER
        {
            return Phase::Unhealthy { since: f.wall };
        }
        Phase::Starting
    }

    /// Activity transitions due at `now` (each reported once per incident).
    pub fn transitions(&mut self, running: bool, now: Instant) -> Option<Transition> {
        match self.phase(running, now) {
            Phase::Down { reason, .. } if !self.reported_down => {
                self.reported_down = true;
                Some(Transition::Down { reason })
            }
            Phase::Unhealthy { .. } if !self.reported_unhealthy && !self.reported_down => {
                self.reported_unhealthy = true;
                Some(Transition::Unhealthy)
            }
            _ => None,
        }
    }
}

/// `"45 s"`, `"3 min 5 s"`, `"2 h 4 min"`.
pub fn fmt_downtime(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0..60 => format!("{s} s"),
        60..3600 if s % 60 == 0 => format!("{} min", s / 60),
        60..3600 => format!("{} min {} s", s / 60, s % 60),
        _ => format!("{} h {} min", s / 3600, (s % 3600) / 60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_error_lines() {
        let fatal = r#"{"time":"2026-11-17T10:00:00Z","level":"ERROR","msg":"fatal error","error":"metrics: listen tcp 127.0.0.1:7416: bind: address already in use"}"#;
        assert_eq!(
            error_cause(fatal).unwrap(),
            "fatal error: metrics: listen tcp 127.0.0.1:7416: bind: address already in use"
        );
        assert_eq!(
            error_cause(r#"{"level":"ERROR","msg":"initializing cert cache"}"#).unwrap(),
            "initializing cert cache"
        );
        assert_eq!(
            error_cause(r#"{"level":"INFO","msg":"iron-proxy stopped"}"#),
            None
        );
        assert_eq!(
            error_cause(r#"{"level":"WARN","msg":"x","error":"y"}"#),
            None
        );
        assert_eq!(
            error_cause("error: config: unknown field \"bogus\"\n").unwrap(),
            "config: unknown field \"bogus\""
        );
        assert_eq!(error_cause("asm: started iron-proxy pid 1"), None);
        assert_eq!(error_cause("not json {"), None);
    }

    #[test]
    fn extracts_signal_stops() {
        let l = r#"{"time":"t","level":"INFO","msg":"received signal, shutting down","signal":"terminated"}"#;
        assert_eq!(
            stop_cause(l).unwrap(),
            "iron-proxy was stopped by a signal (terminated)"
        );
        assert_eq!(
            stop_cause(r#"{"level":"INFO","msg":"iron-proxy stopped"}"#),
            None
        );
        assert_eq!(error_cause(l), None);
    }

    #[test]
    fn finds_conflicting_port() {
        let c = "fatal error: metrics: listen tcp 127.0.0.1:7416: bind: address already in use";
        assert_eq!(port_in_use(c), Some(7416));
        assert_eq!(
            port_in_use("proxy: listen tcp [::]:7412: bind: address already in use"),
            Some(7412)
        );
        assert_eq!(
            port_in_use("proxy: listen tcp :7413: bind: address already in use"),
            Some(7413)
        );
        assert_eq!(
            port_in_use("metrics: listen tcp 127.0.0.1:7416: bind: permission denied"),
            None
        );
        assert_eq!(port_in_use("address already in use"), None);
    }

    #[test]
    fn formats_port_conflicts() {
        assert_eq!(
            port_conflict_message(7416, Some(("python3", 4242))),
            "port 7416 is in use by python3 (pid 4242)"
        );
        assert_eq!(
            port_conflict_message(7416, None),
            "port 7416 is already in use by another process"
        );
    }

    fn at(t0: Instant, ms: u64) -> Instant {
        t0 + Duration::from_millis(ms)
    }

    #[test]
    fn fresh_start_becomes_running() {
        let (t0, w) = (Instant::now(), SystemTime::now());
        let mut h = Health::default();
        h.spawned(t0, w);
        assert_eq!(h.phase(true, at(t0, 500)), Phase::Starting);
        assert_eq!(h.checked(true, at(t0, 600), w), None);
        assert_eq!(h.phase(true, at(t0, 700)), Phase::Running);
        assert!(h.healthy(true));
    }

    #[test]
    fn transient_restart_is_never_down() {
        let (t0, w) = (Instant::now(), SystemTime::now());
        let mut h = Health::default();
        h.spawned(t0, w);
        h.checked(true, t0, w);
        h.failed("crashed".into(), at(t0, 1000), w);
        assert_eq!(h.phase(false, at(t0, 2000)), Phase::Starting);
        h.spawned(at(t0, 2000), w);
        assert_eq!(h.transitions(true, at(t0, 4000)), None);
        assert_eq!(h.checked(true, at(t0, 4500), w), None);
        assert_eq!(h.phase(true, at(t0, 9000)), Phase::Running);
        assert_eq!(h.failures(), 0);
    }

    #[test]
    fn crash_loop_is_down_after_five_seconds_then_recovers() {
        let (t0, w) = (Instant::now(), SystemTime::now());
        let mut h = Health::default();
        h.failed("port 7416 is in use".into(), t0, w);
        assert_eq!(h.phase(false, at(t0, 4999)), Phase::Starting);
        assert_eq!(h.transitions(false, at(t0, 4999)), None);
        let down = Phase::Down {
            reason: "port 7416 is in use".into(),
            since: w,
        };
        assert_eq!(h.phase(false, at(t0, 5000)), down);
        assert_eq!(
            h.transitions(false, at(t0, 5000)),
            Some(Transition::Down {
                reason: "port 7416 is in use".into()
            })
        );
        assert_eq!(h.transitions(false, at(t0, 6000)), None, "reported once");
        // A restarted child that is not healthy yet keeps the incident Down.
        h.spawned(at(t0, 7000), w);
        assert_eq!(h.phase(true, at(t0, 7100)), down);
        h.failed("port 7416 is in use".into(), at(t0, 7200), w);
        assert_eq!(h.failures(), 2);
        h.spawned(at(t0, 20_000), w);
        assert_eq!(
            h.checked(true, at(t0, 21_000), w),
            Some(Transition::Recovered {
                downtime: Duration::from_secs(21),
                failures: 2
            })
        );
        assert_eq!(h.phase(true, at(t0, 21_000)), Phase::Running);
    }

    #[test]
    fn failing_health_checks_become_unhealthy_after_ten_seconds() {
        let (t0, w) = (Instant::now(), SystemTime::now());
        let mut h = Health::default();
        h.spawned(t0, w);
        h.checked(true, at(t0, 500), w);
        h.checked(false, at(t0, 1000), w);
        h.checked(false, at(t0, 5000), w);
        assert!(!h.healthy(true));
        assert_eq!(h.phase(true, at(t0, 11_000)), Phase::Starting);
        assert_eq!(h.phase(true, at(t0, 11_001)), Phase::Unhealthy { since: w });
        assert_eq!(
            h.transitions(true, at(t0, 11_001)),
            Some(Transition::Unhealthy)
        );
        assert_eq!(h.transitions(true, at(t0, 12_000)), None);
        assert!(matches!(
            h.checked(true, at(t0, 13_000), w),
            Some(Transition::Recovered { failures: 0, .. })
        ));
    }

    #[test]
    fn manual_restart_clears_the_failing_mark() {
        let (t0, w) = (Instant::now(), SystemTime::now());
        let mut h = Health::default();
        h.spawned(t0, w);
        h.stopped();
        assert_eq!(h.phase(false, at(t0, 60_000)), Phase::Starting);
    }

    #[test]
    fn collapses_repeated_failure_causes() {
        let mut h = Health::default();
        assert!(h.should_log_failure("a"));
        assert!(!h.should_log_failure("a"));
        assert!(h.should_log_failure("b"));
        h.checked(true, Instant::now(), SystemTime::now());
        assert!(h.should_log_failure("b"));
    }

    #[test]
    fn formats_downtime() {
        assert_eq!(fmt_downtime(Duration::from_secs(45)), "45 s");
        assert_eq!(fmt_downtime(Duration::from_secs(120)), "2 min");
        assert_eq!(fmt_downtime(Duration::from_secs(185)), "3 min 5 s");
        assert_eq!(fmt_downtime(Duration::from_secs(7440)), "2 h 4 min");
    }
}
