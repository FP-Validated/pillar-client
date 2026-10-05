use crate::types::SignerError;
use pillar_core::{
    audit::{self, EffectRecord, EffectiveKey},
    execution::{current, within_deadline, BudgetPermit, Outcome, RequestContext},
};
use std::{
    future::{poll_fn, Future},
    time::Duration,
};

fn lane(context: &RequestContext) -> &str {
    context.source_chain.as_deref().unwrap_or("background")
}
fn maximum() -> Duration {
    if current().is_some_and(|context| context.deadline.is_some()) {
        Duration::from_secs(58)
    } else {
        Duration::from_millis(55_200)
    }
}
async fn acquire(reference: &str) -> Result<Option<BudgetPermit>, SignerError> {
    let context = current();
    match context
        .as_ref()
        .and_then(|context| context.resources.as_ref())
    {
        Some(resources) => resources
            .kms
            .acquire_for(
                lane(context.as_ref().expect("resource context")),
                Some(reference),
            )
            .await
            .map(Some)
            .map_err(SignerError::Admission),
        None => Ok(None),
    }
}
pub(crate) async fn kms_operation<T, F: Future<Output = Result<T, SignerError>>>(
    reference: &str,
    future: F,
) -> Result<T, SignerError> {
    let mut permit = acquire(reference).await?;
    let result = within_deadline(maximum(), future).await;
    if let Some(permit) = &mut permit {
        permit.finish(match &result {
            Ok(Ok(_)) => Outcome::Success,
            Ok(Err(_)) => Outcome::Error,
            Err(_) => Outcome::TimedOut,
        });
    }
    result.map_err(SignerError::Admission)?
}
pub(crate) fn identity<'a>(
    backend: &'static str,
    reference: &str,
    version: impl FnOnce() -> &'a str,
    public_key: &[u8],
) -> Option<EffectiveKey> {
    audit::enabled().then(|| EffectiveKey {
        backend,
        reference: reference.into(),
        version: version().into(),
        public_key_hash: audit::fingerprint(public_key),
    })
}
async fn run_sign<F: Future<Output = Result<Vec<u8>, SignerError>>>(
    mut permit: Option<BudgetPermit>,
    identity: Option<EffectiveKey>,
    digest: &[u8],
    algorithm: &'static str,
    future: F,
) -> Result<Vec<u8>, SignerError> {
    let record = match identity {
        Some(identity) => match audit::begin_effect(identity, digest, algorithm).await {
            Ok(record) => record,
            Err(error) => {
                if let Some(permit) = &mut permit {
                    permit.finish(Outcome::Error);
                }
                return Err(SignerError::Audit(error));
            }
        },
        None if audit::enabled() => {
            if let Some(permit) = &mut permit {
                permit.finish(Outcome::Error);
            }
            return Err(SignerError::Audit(
                "durable audit: unresolved effective key identity".into(),
            ));
        }
        None => None,
    };
    tokio::pin!(future);
    let mut started = false;
    let result = within_deadline(
        maximum(),
        poll_fn(|cx| {
            if !started {
                started = true;
                if let Some(permit) = &mut permit {
                    permit.finish(Outcome::Unknown);
                }
            }
            future.as_mut().poll(cx)
        }),
    )
    .await;
    if let Some(permit) = &mut permit {
        permit.finish(match &result {
            Ok(Ok(_)) => Outcome::Success,
            _ if started => Outcome::Unknown,
            _ => Outcome::TimedOut,
        });
    }
    let result = result.map_err(SignerError::Admission)?;
    if let Some(record) = record {
        match &result {
            Ok(signature) => record
                .returned(signature)
                .await
                .map_err(SignerError::Audit)?,
            Err(_) => record.unknown().await.map_err(SignerError::Audit)?,
        }
    }
    result
}
pub(crate) fn owned_digest(digest: &[u8]) -> Result<[u8; 32], SignerError> {
    digest.try_into().map_err(|_| {
        SignerError::Audit("durable audit: expected a 32-byte transformed signing input".into())
    })
}
async fn evidence<F: Future>(future: F) -> F::Output {
    RequestContext::new(Duration::from_secs(2))
        .scope(future)
        .await
}
pub(crate) async fn sign_owned_effect<F>(
    reference: &str,
    identity: Option<EffectiveKey>,
    digest: &[u8],
    algorithm: &'static str,
    future: F,
) -> Result<Vec<u8>, SignerError>
where
    F: Future<Output = Result<Vec<u8>, SignerError>> + Send + 'static,
{
    let workers = audit::current_workers().map_err(SignerError::Audit)?;
    let mut permit = acquire(reference).await?;
    let reservation = workers.reserve().map_err(|_| {
        if let Some(permit) = &mut permit {
            permit.finish(Outcome::Overloaded);
        }
        SignerError::Admission(pillar_core::execution::BudgetError::Overloaded)
    })?;
    let identity = identity.ok_or_else(|| {
        if let Some(permit) = &mut permit {
            permit.finish(Outcome::Error);
        }
        SignerError::Audit("durable audit: unresolved effective key identity".into())
    })?;
    let record = match audit::begin_effect(identity, digest, algorithm).await {
        Ok(Some(record)) => record,
        Ok(None) => {
            if let Some(permit) = &mut permit {
                permit.finish(Outcome::Error);
            }
            return Err(SignerError::Audit(
                "durable audit: validated scope unavailable".into(),
            ));
        }
        Err(error) => {
            if let Some(permit) = &mut permit {
                permit.finish(Outcome::Error);
            }
            return Err(SignerError::Audit(error));
        }
    };
    if let Some(permit) = &mut permit {
        permit.finish(Outcome::Error);
    }
    let (mut sender, receiver) = tokio::sync::oneshot::channel();
    workers.spawn(
        reservation,
        audit::scope_external_effect(audit::provider_generation(), async move {
            if sender.is_closed() {
                let _ = evidence(record.unknown()).await;
                return;
            }
            let mut caller_lost = false;
            let result = {
                tokio::pin!(future);
                let mut started = false;
                let effect = tokio::time::timeout(
                    Duration::from_millis(55_200),
                    poll_fn(|cx| {
                        if !started {
                            started = true;
                            if let Some(permit) = &mut permit {
                                permit.finish(Outcome::Unknown);
                            }
                        }
                        future.as_mut().poll(cx)
                    }),
                );
                tokio::pin!(effect);
                tokio::select! {
                    result = &mut effect => result,
                    _ = sender.closed() => {
                        caller_lost = true;
                        let _ = evidence(record.unknown()).await;
                        effect.await
                    }
                }
            };
            let outcome = match &result {
                Ok(Ok(_)) => Outcome::Success,
                _ => Outcome::Unknown,
            };
            let result = match result {
                Ok(Ok(signature)) => evidence(record.returned(&signature))
                    .await
                    .map(|()| signature)
                    .map_err(SignerError::Audit),
                Ok(Err(error)) => {
                    let recorded = if caller_lost {
                        Ok(())
                    } else {
                        evidence(record.unknown()).await.map_err(SignerError::Audit)
                    };
                    recorded.and(Err(error))
                }
                Err(_) => {
                    let recorded = if caller_lost {
                        Ok(())
                    } else {
                        evidence(record.unknown()).await.map_err(SignerError::Audit)
                    };
                    recorded.and(Err(SignerError::Admission(
                        pillar_core::execution::BudgetError::Deadline,
                    )))
                }
            };
            if sender.send(result).is_err() {
                if !caller_lost {
                    let _ = evidence(record.unknown()).await;
                }
            } else if let Some(permit) = &mut permit {
                permit.finish(outcome);
            }
        }),
    );
    within_deadline(maximum(), receiver)
        .await
        .map_err(SignerError::Admission)?
        .map_err(|_| {
            SignerError::Audit(
                "durable audit: completion worker stopped; outcome remains unknown".into(),
            )
        })?
}
pub(crate) async fn sign_effect<F: Future<Output = Result<Vec<u8>, SignerError>>>(
    reference: &str,
    identity: Option<EffectiveKey>,
    digest: &[u8],
    algorithm: &'static str,
    future: F,
) -> Result<Vec<u8>, SignerError> {
    run_sign(
        acquire(reference).await?,
        identity,
        digest,
        algorithm,
        future,
    )
    .await
}
pub(crate) async fn try_sign_effect<F: Future<Output = Result<Vec<u8>, SignerError>>>(
    reference: &str,
    digest: &[u8],
    future: F,
) -> Result<Option<Vec<u8>>, SignerError> {
    let context = current();
    let permit = match context
        .as_ref()
        .and_then(|context| context.resources.as_ref())
    {
        Some(resources) => match resources
            .kms
            .try_acquire_for(
                lane(context.as_ref().expect("resource context")),
                Some(reference),
            )
            .map_err(SignerError::Admission)?
        {
            Some(permit) => Some(permit),
            None => return Ok(None),
        },
        None => None,
    };
    run_sign(permit, None, digest, "ecdsa", future)
        .await
        .map(Some)
}
pub(crate) async fn local_begin<B: AsRef<[u8]>>(
    public_key: impl FnOnce() -> B,
    digest: &[u8],
    algorithm: &'static str,
) -> Result<Option<EffectRecord>, SignerError> {
    if !audit::enabled() {
        return Ok(None);
    }
    let hash = audit::fingerprint(public_key().as_ref());
    audit::begin_effect(
        EffectiveKey {
            backend: "local",
            reference: hash.clone(),
            version: hash.clone(),
            public_key_hash: hash,
        },
        digest,
        algorithm,
    )
    .await
    .map_err(SignerError::Audit)
}
pub(crate) async fn local_returned(
    record: Option<EffectRecord>,
    signature: &[u8],
) -> Result<(), SignerError> {
    if let Some(record) = record {
        record
            .returned(signature)
            .await
            .map_err(SignerError::Audit)?;
    }
    Ok(())
}
