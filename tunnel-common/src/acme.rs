use anyhow::{Result, bail};
use instant_acme::{Order, OrderStatus};
use std::time::Duration;

/// Rounds of the order-readiness poll before giving up (~2s doubling to 15s).
pub const ORDER_READY_ROUNDS: u32 = 12;
/// Rounds of the certificate-download poll after finalize.
pub const CERT_POLL_ROUNDS: u32 = 30;
/// Interval between certificate-download polls.
pub const CERT_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Why an invalid order failed: the first failed challenge's problem, else the order's own.
async fn invalid_reason(order: &mut Order) -> String {
    let mut authorizations = order.authorizations();
    while let Some(Ok(authz)) = authorizations.next().await {
        if let Some(problem) = authz.challenges.iter().find_map(|c| c.error.as_ref()) {
            return problem.to_string();
        }
    }
    match &order.state().error {
        Some(problem) => problem.to_string(),
        None => "no reason given".to_string(),
    }
}

/// Waits for the order to become ready, finalizes the CSR and downloads the
/// certificate chain PEM. Both polls are bounded.
pub async fn finalize_order(order: &mut Order, domain: &str, csr_der: &[u8]) -> Result<String> {
    let mut ready = false;
    let mut delay = Duration::from_secs(2);
    for _ in 0..ORDER_READY_ROUNDS {
        tokio::time::sleep(delay).await;
        match order.refresh().await?.status {
            OrderStatus::Ready | OrderStatus::Valid => {
                ready = true;
                break;
            }
            OrderStatus::Invalid => {
                bail!(
                    "ACME order invalid for {domain}: {}",
                    invalid_reason(order).await
                )
            }
            _ => {}
        }
        delay = delay.saturating_mul(2).min(Duration::from_secs(15));
    }
    if !ready {
        bail!(
            "ACME order for {} never became ready after {} polls",
            domain,
            ORDER_READY_ROUNDS
        );
    }

    order.finalize_csr(csr_der).await?;

    for _ in 0..CERT_POLL_ROUNDS {
        tokio::time::sleep(CERT_POLL_INTERVAL).await;
        if let Some(pem) = order.certificate().await? {
            return Ok(pem);
        }
    }
    bail!(
        "ACME certificate for {} not issued after {:?}",
        domain,
        CERT_POLL_INTERVAL * CERT_POLL_ROUNDS
    )
}
