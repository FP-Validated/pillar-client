//! The AWS SDK's HTTP client, with name lookups held to a few slots.
//!
//! The SDK resolves names with `getaddrinfo` on Tokio's blocking pool, which a signing request that
//! gave up cannot stop; unbounded, stalled lookups crowd out every other blocking task.
use aws_smithy_runtime_api::client::{
    dns::{DnsFuture, ResolveDns, ResolveDnsError},
    http::SharedHttpClient,
};
use std::{future::Future, net::IpAddr, pin::Pin, sync::Arc};
use tokio::sync::Semaphore;

/// Lookups allowed in flight across every AWS client in the process.
const MAX_CONCURRENT_LOOKUPS: usize = 8;

type LookupFuture = Pin<Box<dyn Future<Output = std::io::Result<Vec<IpAddr>>> + Send>>;
type Lookup = Arc<dyn Fn(String) -> LookupFuture + Send + Sync>;

#[derive(Clone)]
pub(crate) struct BoundedDns {
    slots: Arc<Semaphore>,
    lookup: Lookup,
}

impl std::fmt::Debug for BoundedDns {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BoundedDns")
    }
}

impl BoundedDns {
    fn new(slots: usize, lookup: Lookup) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(slots)),
            lookup,
        }
    }

    fn system() -> Self {
        Self::new(
            MAX_CONCURRENT_LOOKUPS,
            Arc::new(|name| {
                Box::pin(async move {
                    Ok(tokio::net::lookup_host((name.as_str(), 0))
                        .await?
                        .map(|address| address.ip())
                        .collect())
                })
            }),
        )
    }
}

impl ResolveDns for BoundedDns {
    fn resolve_dns<'a>(&'a self, name: &'a str) -> DnsFuture<'a> {
        DnsFuture::new(async move {
            let slot = self
                .slots
                .clone()
                .acquire_owned()
                .await
                .map_err(ResolveDnsError::new)?;
            let lookup = (self.lookup)(name.to_string());
            // The task owns the slot, so it is freed when the lookup ends, not when the caller leaves.
            tokio::spawn(async move {
                let _slot = slot;
                lookup.await
            })
            .await
            .map_err(ResolveDnsError::new)?
            .map_err(ResolveDnsError::new)
        })
    }
}

fn http_client() -> SharedHttpClient {
    aws_smithy_http_client::Builder::new()
        .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
            aws_smithy_http_client::tls::rustls_provider::CryptoMode::AwsLc,
        ))
        .build_with_resolver(BoundedDns::system())
}

/// `aws_config::defaults` over the bounded-lookup client, with an upper limit on every SDK operation.
pub(crate) fn defaults() -> aws_config::ConfigLoader {
    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .http_client(http_client())
        .timeout_config(
            aws_config::timeout::TimeoutConfig::builder()
                .connect_timeout(std::time::Duration::from_secs(10))
                .operation_timeout(std::time::Duration::from_secs(60))
                .build(),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_smithy_runtime_api::client::dns::ResolveDns;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn a_cancelled_lookup_keeps_its_slot_until_the_lookup_itself_ends() {
        let started = Arc::new(AtomicUsize::new(0));
        let counted = started.clone();
        let dns = BoundedDns::new(
            2,
            Arc::new(move |_name: String| {
                counted.fetch_add(1, Ordering::SeqCst);
                Box::pin(std::future::pending()) as LookupFuture
            }),
        );
        let first = tokio::spawn({
            let dns = dns.clone();
            async move { dns.resolve_dns("a.example").await }
        });
        let second = tokio::spawn({
            let dns = dns.clone();
            async move { dns.resolve_dns("b.example").await }
        });
        let third = tokio::spawn({
            let dns = dns.clone();
            async move { dns.resolve_dns("c.example").await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(started.load(Ordering::SeqCst), 2, "two slots, two lookups");

        // The callers give up, but a resolver call that already started cannot be stopped.
        first.abort();
        second.abort();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            started.load(Ordering::SeqCst),
            2,
            "the abandoned lookups still hold both slots, so the third waits"
        );
        third.abort();
    }

    #[tokio::test]
    async fn a_finished_lookup_frees_its_slot() {
        let dns = BoundedDns::new(
            1,
            Arc::new(|name: String| {
                Box::pin(async move {
                    Ok(vec![if name == "a.example" {
                        std::net::Ipv4Addr::new(192, 0, 2, 1).into()
                    } else {
                        std::net::Ipv4Addr::new(192, 0, 2, 2).into()
                    }])
                }) as LookupFuture
            }),
        );
        assert_eq!(
            dns.resolve_dns("a.example").await.unwrap(),
            [std::net::IpAddr::from([192, 0, 2, 1])]
        );
        assert_eq!(
            dns.resolve_dns("b.example").await.unwrap(),
            [std::net::IpAddr::from([192, 0, 2, 2])]
        );
    }
}
