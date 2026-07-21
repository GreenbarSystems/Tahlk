//! Lockout for repeated credential-verification failures.
//!
//! No credential path had any rate limiting: `lock_pin_verify`,
//! `auth_unlock_password`, `auth_unlock_recovery` and
//! `auth_nuke_and_reinstall` each verified and returned immediately, so the
//! only brake was PBKDF2 cost.
//!
//! That is thin where it matters most. The idle-lock PIN has a 4-character
//! minimum, so a numeric PIN is a 10^4 keyspace; at roughly 100 ms per
//! 210k-iteration verification an unattended attacker exhausts it in under 20
//! minutes — well inside the "someone picks up the laptop between patients"
//! threat the idle lock exists for. `auth_nuke_and_reinstall` is the other
//! sharp case: unlimited guesses against an irreversible destruction.
//!
//! Policy: the first few failures are free (fat fingers), then a doubling
//! cooldown, capped. A successful verification clears the counter.
//!
//! State is per-process and in memory. That is a deliberate limit rather than
//! an oversight: restarting the app to reset the PIN counter drops the
//! attacker back to the master-password screen, which is the stronger gate, so
//! a restart is not a bypass. It does mean a determined attacker who can
//! relaunch repeatedly is not slowed on the password path itself — the 12-char
//! minimum and common-password rejection in `auth` are what carry that case.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::errors::AppError;

/// Failures allowed before any cooldown applies.
const FREE_ATTEMPTS: u32 = 4;
/// Cooldown after the first non-free failure; doubles with each subsequent one.
const BASE_COOLDOWN: Duration = Duration::from_secs(5);
/// Ceiling on the doubling.
const MAX_COOLDOWN: Duration = Duration::from_secs(15 * 60);

#[derive(Default)]
struct Attempts {
    failures: u32,
    locked_until: Option<Instant>,
}

static STATE: Mutex<Option<HashMap<&'static str, Attempts>>> = Mutex::new(None);

fn with_state<T>(f: impl FnOnce(&mut HashMap<&'static str, Attempts>) -> T) -> Option<T> {
    // A poisoned lock means another thread panicked mid-update. Recover the
    // guard rather than propagating: refusing to check the throttle would fail
    // OPEN on a security control, which is the wrong direction.
    let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
    Some(f(guard.get_or_insert_with(HashMap::new)))
}

/// Refuse if `scope` is currently cooling down. Call BEFORE verifying.
pub(crate) fn check(scope: &'static str) -> Result<(), AppError> {
    let remaining = with_state(|m| {
        let entry = m.entry(scope).or_default();
        match entry.locked_until {
            Some(until) if until > Instant::now() => Some(until - Instant::now()),
            Some(_) => {
                // Cooldown elapsed; allow one more try without resetting the
                // failure count, so the next failure escalates rather than
                // restarting the ladder.
                entry.locked_until = None;
                None
            }
            None => None,
        }
    })
    .flatten();

    match remaining {
        None => Ok(()),
        Some(d) => {
            let secs = d.as_secs().max(1);
            Err(AppError::precondition(format!(
                "Too many incorrect attempts. Try again in {secs} second{}.",
                if secs == 1 { "" } else { "s" }
            )))
        }
    }
}

/// Record a failed verification and start or extend the cooldown.
pub(crate) fn record_failure(scope: &'static str) {
    with_state(|m| {
        let entry = m.entry(scope).or_default();
        entry.failures = entry.failures.saturating_add(1);
        if entry.failures > FREE_ATTEMPTS {
            let steps = entry.failures - FREE_ATTEMPTS - 1;
            let cooldown = BASE_COOLDOWN
                .checked_mul(1u32.checked_shl(steps.min(20)).unwrap_or(u32::MAX))
                .unwrap_or(MAX_COOLDOWN)
                .min(MAX_COOLDOWN);
            entry.locked_until = Some(Instant::now() + cooldown);
        }
    });
}

/// Clear the counter after a successful verification.
pub(crate) fn record_success(scope: &'static str) {
    with_state(|m| {
        m.remove(scope);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each test uses its own scope string so the shared static cannot make
    // them order-dependent — the harness runs tests in parallel.

    #[test]
    fn the_first_failures_are_free() {
        let s = "test::free";
        for _ in 0..FREE_ATTEMPTS {
            assert!(check(s).is_ok());
            record_failure(s);
        }
        assert!(check(s).is_ok(), "a fat-fingered PIN must not lock immediately");
    }

    #[test]
    fn a_cooldown_starts_after_the_free_attempts() {
        let s = "test::cooldown";
        for _ in 0..=FREE_ATTEMPTS {
            record_failure(s);
        }
        let err = check(s).unwrap_err();
        assert!(format!("{err}").contains("Too many incorrect attempts"));
    }

    #[test]
    fn success_clears_the_counter() {
        let s = "test::success";
        for _ in 0..=FREE_ATTEMPTS {
            record_failure(s);
        }
        assert!(check(s).is_err());
        record_success(s);
        assert!(check(s).is_ok(), "a correct credential must clear the lockout");
    }

    #[test]
    fn cooldowns_are_scoped_independently() {
        // Locking the PIN must not lock the master password, and vice versa.
        let a = "test::scope-a";
        let b = "test::scope-b";
        for _ in 0..=FREE_ATTEMPTS {
            record_failure(a);
        }
        assert!(check(a).is_err());
        assert!(check(b).is_ok());
    }

    #[test]
    fn the_cooldown_is_capped() {
        // Doubling without a ceiling would overflow into an effectively
        // permanent lockout, which is a denial of service against the
        // legitimate provider rather than a defence.
        let s = "test::cap";
        for _ in 0..40 {
            record_failure(s);
        }
        let err = check(s).unwrap_err();
        let text = format!("{err}");
        let secs: u64 = text
            .split_whitespace()
            .find_map(|w| w.parse().ok())
            .expect("message should carry a seconds figure");
        assert!(
            secs <= MAX_COOLDOWN.as_secs(),
            "cooldown {secs}s exceeded the {}s cap",
            MAX_COOLDOWN.as_secs()
        );
    }
}
