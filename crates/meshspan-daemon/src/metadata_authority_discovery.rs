// SPDX-License-Identifier: GPL-2.0-only

//! Deadline-owned authority discovery, separate from transport and metadata receipt validation.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::NodeId;
use std::{future::Future, time::Duration};
use tokio::task::JoinSet;

type Outcome<T> = Result<T, MetadataAuthorityRequestError>;
const DEADLINE: Duration = Duration::from_secs(30);
const HINT_GRACE: Duration = Duration::from_millis(250);
const RETRY_INITIAL: Duration = Duration::from_millis(250);
const RETRY_MAX: Duration = Duration::from_secs(1);

pub(crate) async fn discover<T, Query, Request>(
    candidates: Vec<NodeId>,
    hint: Option<NodeId>,
    query: Query,
) -> Outcome<T>
where
    T: Send + 'static,
    Query: Fn(NodeId) -> Request + Clone + Send + 'static,
    Request: Future<Output = Outcome<T>> + Send + 'static,
{
    let mut requests = JoinSet::new();
    let result = tokio::time::timeout(DEADLINE, async {
        let mut remaining = candidates.into_iter();
        if let Some(hint) = hint {
            if remaining.next() != Some(hint) {
                return Err(MetadataAuthorityRequestError::Failed);
            }
            spawn(&mut requests, hint, query.clone());
            if let Ok(Some(result)) = tokio::time::timeout(HINT_GRACE, requests.join_next()).await {
                return completed(result);
            }
        }
        for candidate in remaining {
            spawn(&mut requests, candidate, query.clone());
        }
        if let Some(result) = requests.join_next().await {
            return completed(result);
        }
        Err(MetadataAuthorityRequestError::Unavailable)
    })
    .await
    .unwrap_or(Err(MetadataAuthorityRequestError::Unavailable));
    requests.abort_all();
    let mut task_failed = false;
    while let Some(ended) = requests.join_next().await {
        if let Err(error) = ended {
            task_failed |= !error.is_cancelled();
        }
    }
    if task_failed {
        Err(MetadataAuthorityRequestError::Failed)
    } else {
        result
    }
}

fn spawn<T, Query, Request>(requests: &mut JoinSet<Outcome<T>>, candidate: NodeId, query: Query)
where
    T: Send + 'static,
    Query: Fn(NodeId) -> Request + Send + 'static,
    Request: Future<Output = Outcome<T>> + Send + 'static,
{
    requests.spawn(async move {
        let mut delay = RETRY_INITIAL;
        loop {
            match query(candidate).await {
                Err(MetadataAuthorityRequestError::Unavailable) => {
                    // Retry the identical operation only after its previous request finishes.
                    // A slow peer cannot postpone discovery of a newly elected live peer.
                    tokio::time::sleep(delay).await;
                    delay = delay.saturating_mul(2).min(RETRY_MAX);
                }
                outcome => return outcome,
            }
        }
    });
}

fn completed<T>(result: Result<Outcome<T>, tokio::task::JoinError>) -> Outcome<T> {
    result.map_err(|_| MetadataAuthorityRequestError::Failed)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn unavailable_candidate_is_reconsidered_without_waiting_for_a_dead_peer()
    -> Result<(), Box<dyn std::error::Error>> {
        let dead = NodeId::from_bytes([1; 16])?;
        let elected = NodeId::from_bytes([2; 16])?;
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            discover(vec![dead, elected], Some(dead), move |node| {
                let calls = Arc::clone(&calls);
                async move {
                    if node == dead {
                        return std::future::pending().await;
                    }
                    if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        Err(MetadataAuthorityRequestError::Unavailable)
                    } else {
                        Ok([7; 32])
                    }
                }
            }),
        )
        .await??;
        assert_eq!(result, [7; 32]);
        assert_eq!(observed.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[tokio::test]
    async fn terminal_rejection_is_not_retried() -> Result<(), Box<dyn std::error::Error>> {
        let node = NodeId::from_bytes([1; 16])?;
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let result = discover(vec![node], Some(node), move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err::<[u8; 32], _>(MetadataAuthorityRequestError::Rejected) }
        })
        .await;
        assert!(matches!(
            result,
            Err(MetadataAuthorityRequestError::Rejected)
        ));
        assert_eq!(observed.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[tokio::test]
    async fn success_cancels_and_observes_pending_candidate()
    -> Result<(), Box<dyn std::error::Error>> {
        struct InFlight(Arc<AtomicUsize>);
        impl Drop for InFlight {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let dead = NodeId::from_bytes([1; 16])?;
        let local = NodeId::from_bytes([2; 16])?;
        let active = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&active);
        let result = discover(vec![dead, local], Some(dead), move |node| {
            let active = Arc::clone(&active);
            async move {
                if node == dead {
                    active.fetch_add(1, Ordering::SeqCst);
                    let _request = InFlight(active);
                    std::future::pending().await
                } else {
                    assert_eq!(active.load(Ordering::SeqCst), 1);
                    Ok([9; 32])
                }
            }
        })
        .await?;
        assert_eq!(result, [9; 32]);
        assert_eq!(observed.load(Ordering::SeqCst), 0);
        Ok(())
    }
}
