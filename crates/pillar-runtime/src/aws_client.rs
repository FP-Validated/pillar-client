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

fn timeout_config() -> aws_config::timeout::TimeoutConfig {
    aws_config::timeout::TimeoutConfig::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .operation_timeout(std::time::Duration::from_secs(60))
        .build()
}

/// `aws_config::defaults` over the bounded-lookup client, with an upper limit on every SDK operation.
pub(crate) fn defaults() -> aws_config::ConfigLoader {
    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .http_client(http_client())
        .timeout_config(timeout_config())
}

/// Loads `loader`, assuming the selected profile's role here when it sets `duration_seconds`:
/// the SDK's profile provider never sends that setting to STS (I-07).
pub(crate) async fn load(loader: aws_config::ConfigLoader) -> Result<aws_types::SdkConfig, String> {
    // Boxed: the SDK, profile and STS futures are large, and every startup future that loads an
    // AWS configuration would otherwise carry them inline.
    let config = Box::pin(loader.load()).await;
    let profile = Box::pin(profile_role_session(
        &aws_types::os_shim_internal::Fs::real(),
        &aws_types::os_shim_internal::Env::real(),
    ))
    .await?;
    let Some(session) = profile else {
        return Ok(config);
    };
    let provider_config = aws_config::provider_config::ProviderConfig::without_region()
        .with_region(config.region().cloned())
        .with_http_client(http_client())
        .with_timeout_config(timeout_config());
    let credentials = Box::pin(session.provider(&config, &provider_config)).await?;
    Ok(config
        .into_builder()
        .credentials_provider(credentials)
        .build())
}

#[derive(Debug, PartialEq)]
enum RoleBase {
    Profile(String),
    Static {
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
    },
    Environment,
    Ec2InstanceMetadata,
    EcsContainer,
}

#[derive(Debug, PartialEq)]
struct RoleSession {
    role_arn: String,
    duration: std::time::Duration,
    external_id: Option<String>,
    session_name: Option<String>,
    base: RoleBase,
}

impl RoleSession {
    async fn provider(
        self,
        config: &aws_types::SdkConfig,
        provider_config: &aws_config::provider_config::ProviderConfig,
    ) -> Result<aws_credential_types::provider::SharedCredentialsProvider, String> {
        use aws_credential_types::provider::SharedCredentialsProvider;
        let base = match self.base {
            RoleBase::Profile(name) => SharedCredentialsProvider::new(
                aws_config::profile::ProfileFileCredentialsProvider::builder()
                    .configure(provider_config)
                    .profile_name(name)
                    .build(),
            ),
            RoleBase::Static {
                access_key_id,
                secret_access_key,
                session_token,
            } => SharedCredentialsProvider::new(aws_credential_types::Credentials::new(
                access_key_id,
                secret_access_key,
                session_token,
                None,
                "ProfileFile",
            )),
            RoleBase::Environment => SharedCredentialsProvider::new(
                aws_config::environment::EnvironmentVariableCredentialsProvider::new(),
            ),
            RoleBase::Ec2InstanceMetadata => SharedCredentialsProvider::new(
                aws_config::imds::credentials::ImdsCredentialsProvider::builder()
                    .configure(provider_config)
                    .build(),
            ),
            RoleBase::EcsContainer => SharedCredentialsProvider::new(
                aws_config::ecs::EcsCredentialsProvider::builder()
                    .configure(provider_config)
                    .build(),
            ),
        };
        let mut role = aws_config::sts::AssumeRoleProvider::builder(self.role_arn)
            .session_length(self.duration)
            .configure(config);
        if let Some(external_id) = self.external_id {
            role = role.external_id(external_id);
        }
        if let Some(session_name) = self.session_name {
            role = role.session_name(session_name);
        }
        Ok(SharedCredentialsProvider::new(
            role.build_from_provider(base).await,
        ))
    }
}

/// The AssumeRole session of the selected profile when it sets `duration_seconds` and the default
/// chain would reach it; `None` leaves credentials to the SDK.
async fn profile_role_session(
    fs: &aws_types::os_shim_internal::Fs,
    env: &aws_types::os_shim_internal::Env,
) -> Result<Option<RoleSession>, String> {
    // Environment keys come before the profile in the default chain.
    if env.get("AWS_ACCESS_KEY_ID").is_ok() {
        return Ok(None);
    }
    let Ok(profiles) = aws_config::profile::load(
        fs,
        env,
        &aws_runtime::env_config::file::EnvConfigFiles::default(),
        None,
    )
    .await
    else {
        return Ok(None);
    };
    let name = profiles.selected_profile();
    let Some(profile) = profiles.get_profile(name) else {
        return Ok(None);
    };
    let (Some(duration), Some(role_arn)) =
        (profile.get("duration_seconds"), profile.get("role_arn"))
    else {
        return Ok(None);
    };
    let unsupported = || {
        format!(
            "AWS profile {name} sets duration_seconds, which is honoured only for role_arn with \
             source_profile or credential_source, without web_identity_token_file or mfa_serial"
        )
    };
    // STS takes 900 to 43200 seconds, and the SDK narrows the value to `i32` unchecked.
    let duration = duration
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|seconds| (900..=43_200).contains(seconds))
        .ok_or_else(|| {
            format!("AWS profile {name}: duration_seconds must be 900 to 43200 seconds")
        })?;
    if profile.get("web_identity_token_file").is_some() || profile.get("mfa_serial").is_some() {
        return Err(unsupported());
    }
    let base = match (
        profile.get("source_profile"),
        profile.get("credential_source"),
    ) {
        (Some(source), None) if source == name => RoleBase::Static {
            access_key_id: profile
                .get("aws_access_key_id")
                .ok_or_else(unsupported)?
                .to_string(),
            secret_access_key: profile
                .get("aws_secret_access_key")
                .ok_or_else(unsupported)?
                .to_string(),
            session_token: profile.get("aws_session_token").map(str::to_string),
        },
        (Some(source), None) => RoleBase::Profile(source.to_string()),
        (None, Some("Environment")) => RoleBase::Environment,
        (None, Some("Ec2InstanceMetadata")) => RoleBase::Ec2InstanceMetadata,
        (None, Some("EcsContainer")) => RoleBase::EcsContainer,
        _ => return Err(unsupported()),
    };
    Ok(Some(RoleSession {
        role_arn: role_arn.to_string(),
        duration: std::time::Duration::from_secs(duration),
        external_id: profile.get("external_id").map(str::to_string),
        session_name: profile.get("role_session_name").map(str::to_string),
        base,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_smithy_runtime_api::client::dns::ResolveDns;
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn session_for(
        config: &str,
        env: &[(&str, &str)],
    ) -> Result<Option<RoleSession>, String> {
        let fs = aws_types::os_shim_internal::Fs::from_slice(&[("/aws/config", config)]);
        let mut vars = vec![("AWS_CONFIG_FILE", "/aws/config"), ("HOME", "/home")];
        vars.extend_from_slice(env);
        profile_role_session(&fs, &aws_types::os_shim_internal::Env::from_slice(&vars)).await
    }

    #[tokio::test]
    async fn a_role_profile_with_duration_seconds_is_assumed_with_that_duration() {
        let config = "[profile base]\naws_access_key_id = AKID\naws_secret_access_key = SECRET\n\
                      [default]\nrole_arn = arn:aws:iam::123456789012:role/pillar\n\
                      source_profile = base\nduration_seconds = 900\nexternal_id = ext\n";
        let session = session_for(config, &[]).await.unwrap().unwrap();
        assert_eq!(
            session,
            RoleSession {
                role_arn: "arn:aws:iam::123456789012:role/pillar".to_string(),
                duration: std::time::Duration::from_secs(900),
                external_id: Some("ext".to_string()),
                session_name: None,
                base: RoleBase::Profile("base".to_string()),
            }
        );
        assert_eq!(
            session_for(config, &[("AWS_ACCESS_KEY_ID", "AKID")]).await,
            Ok(None),
            "environment keys come first in the default chain"
        );
        assert!(session_for(
            "[default]\nrole_arn = arn:aws:iam::1:role/r\nweb_identity_token_file = /t\nduration_seconds = 900\n",
            &[]
        )
        .await
        .is_err());
        assert!(session_for(
            "[default]\nrole_arn = arn:aws:iam::1:role/r\ncredential_source = Environment\nduration_seconds = 99999999999\n",
            &[]
        )
        .await
        .is_err());
    }

    /// Records each request body and fails the call, so nothing leaves the process.
    #[derive(Debug, Clone, Default)]
    struct CapturedBodies(Arc<std::sync::Mutex<Vec<String>>>);

    impl aws_smithy_runtime_api::client::http::HttpConnector for CapturedBodies {
        fn call(
            &self,
            request: aws_smithy_runtime_api::client::orchestrator::HttpRequest,
        ) -> aws_smithy_runtime_api::client::http::HttpConnectorFuture {
            let body = request.body().bytes().unwrap_or_default();
            self.0
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(body).into_owned());
            aws_smithy_runtime_api::client::http::HttpConnectorFuture::ready(Err(
                aws_smithy_runtime_api::client::result::ConnectorError::other(
                    "captured".into(),
                    None,
                ),
            ))
        }
    }

    #[tokio::test]
    async fn the_assume_role_request_carries_duration_seconds() {
        use aws_credential_types::provider::ProvideCredentials;
        let captured = CapturedBodies::default();
        let connector = captured.clone();
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .http_client(aws_smithy_runtime_api::client::http::http_client_fn(
                move |_, _| {
                    aws_smithy_runtime_api::client::http::SharedHttpConnector::new(
                        connector.clone(),
                    )
                },
            ))
            .region(aws_config::Region::new("us-east-1"))
            .load()
            .await;
        let session = RoleSession {
            role_arn: "arn:aws:iam::123456789012:role/pillar".to_string(),
            duration: std::time::Duration::from_secs(900),
            external_id: None,
            session_name: Some("pillar".to_string()),
            base: RoleBase::Static {
                access_key_id: "AKID".to_string(),
                secret_access_key: "SECRET".to_string(),
                session_token: None,
            },
        };
        let provider = session
            .provider(
                &config,
                &aws_config::provider_config::ProviderConfig::without_region(),
            )
            .await
            .unwrap();
        assert!(provider.provide_credentials().await.is_err());
        let bodies = captured.0.lock().unwrap().clone();
        let body = bodies.first().expect("one STS request");
        assert!(body.contains("Action=AssumeRole"), "{body}");
        assert!(body.contains("DurationSeconds=900"), "{body}");
    }

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
