use log::{debug, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Ceiling on connections that have been accepted but are not yet authenticated.
pub(crate) const MAX_UNAUTHENTICATED_CONNS: usize = 512;
/// Rate limit for the "budget exhausted" warning, so a flood cannot spam the log.
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(5);
/// Budget for the domain and identity-signature steps, including the DNS TXT check.
pub(crate) const AUTH_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);
/// Budget for the key-auth step, which the client answers only once its ACME order is prepared.
pub(crate) const KEY_AUTH_TIMEOUT: Duration = Duration::from_secs(120);

/// Admission control for one listener: bounds the connections that have been
/// accepted but not yet authenticated, and logs refusals at a throttled rate.
pub(crate) struct Admission {
    proto: &'static str,
    permits: Arc<Semaphore>,
    last_refusal_log: Option<Instant>,
}

impl Admission {
    pub(crate) fn new(proto: &'static str) -> Self {
        Self {
            proto,
            permits: Arc::new(Semaphore::new(MAX_UNAUTHENTICATED_CONNS)),
            last_refusal_log: None,
        }
    }

    /// Takes a permit for `remote`, or logs the refusal and returns `None`. Never
    /// awaits: parking the accept loop behind stalled peers would lock out everyone.
    pub(crate) fn try_admit(&mut self, remote: SocketAddr) -> Option<OwnedSemaphorePermit> {
        if let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() {
            return Some(permit);
        }
        if self
            .last_refusal_log
            .is_none_or(|t| t.elapsed() >= REFUSAL_LOG_INTERVAL)
        {
            warn!(
                "{}: refusing {} — {} unauthenticated connections already in flight",
                self.proto, remote, MAX_UNAUTHENTICATED_CONNS
            );
            self.last_refusal_log = Some(Instant::now());
        } else {
            debug!(
                "{}: refusing {} (unauthenticated connection budget exhausted)",
                self.proto, remote
            );
        }
        None
    }
}
