use pillar_core::execution::{default_lane_resource_limit, BudgetLimits};
use std::{collections::HashMap, time::Duration};
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionLimits {
    pub signing: BudgetLimits,
    pub rpc: BudgetLimits,
    pub kms: BudgetLimits,
    pub kms_key_concurrency: usize,
    pub kms_lane_key_concurrency: usize,
}
impl Default for ExecutionLimits {
    fn default() -> Self {
        Self {
            signing: BudgetLimits {
                active: 64,
                per_lane: 8,
                waiting: 128,
                per_lane_waiting: 16,
                wait: Duration::from_secs(2),
            },
            rpc: BudgetLimits {
                active: 64,
                per_lane: 8,
                waiting: 512,
                per_lane_waiting: 64,
                wait: Duration::from_secs(2),
            },
            kms: BudgetLimits {
                active: 16,
                per_lane: 4,
                waiting: 128,
                per_lane_waiting: 16,
                wait: Duration::from_secs(2),
            },
            kms_key_concurrency: 4,
            kms_lane_key_concurrency: 3,
        }
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct AuditConfig {
    pub database_url: Zeroizing<String>,
    pub namespace: String,
    pub timeout: Duration,
    pub max_attempts: u64,
}
impl std::fmt::Debug for AuditConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditConfig")
            .field("database_url", &"<redacted>")
            .field("namespace", &self.namespace)
            .field("timeout", &self.timeout)
            .field("max_attempts", &self.max_attempts)
            .finish()
    }
}
fn number(
    map: &HashMap<String, String>,
    name: &str,
    default: usize,
    zero: bool,
) -> Result<usize, String> {
    let value = map.get(name).map_or(Ok(default), |value| {
        value
            .parse::<usize>()
            .map_err(|_| format!("invalid {name}"))
    })?;
    if (!zero && value == 0) || value > 1_000_000 {
        return Err(format!("invalid {name}: outside bounded range"));
    }
    Ok(value)
}
impl ExecutionLimits {
    pub fn from_map(map: &HashMap<String, String>) -> Result<Self, String> {
        let defaults = Self::default();
        let wait =
            Duration::from_millis(number(map, "PILLAR_ADMISSION_WAIT_MS", 2000, false)? as u64);
        let parse = |prefix: &str, defaults: BudgetLimits| -> Result<BudgetLimits, String> {
            let limits = BudgetLimits {
                active: number(
                    map,
                    &format!("PILLAR_{prefix}_CONCURRENCY"),
                    defaults.active,
                    false,
                )?,
                per_lane: number(
                    map,
                    &format!("PILLAR_{prefix}_CHAIN_CONCURRENCY"),
                    defaults.per_lane,
                    false,
                )?,
                waiting: number(
                    map,
                    &format!("PILLAR_{prefix}_QUEUE_CAPACITY"),
                    defaults.waiting,
                    true,
                )?,
                per_lane_waiting: number(
                    map,
                    &format!("PILLAR_{prefix}_CHAIN_QUEUE_CAPACITY"),
                    defaults.per_lane_waiting,
                    true,
                )?,
                wait,
            };
            if limits.per_lane > limits.active || limits.per_lane_waiting > limits.waiting {
                return Err(format!("invalid {prefix} resource limits"));
            }
            Ok(limits)
        };
        let signing = parse("SIGN", defaults.signing)?;
        let rpc = parse("RPC", defaults.rpc)?;
        let kms = parse("KMS", defaults.kms)?;
        let kms_key_concurrency = number(
            map,
            "PILLAR_KMS_KEY_CONCURRENCY",
            defaults.kms_key_concurrency,
            false,
        )?;
        if kms_key_concurrency > kms.active {
            return Err("invalid PILLAR_KMS_KEY_CONCURRENCY".into());
        }
        let kms_lane_key_concurrency = match map.get("PILLAR_KMS_CHAIN_KEY_CONCURRENCY") {
            None => default_lane_resource_limit(kms_key_concurrency, kms.per_lane),
            Some(_) => {
                let value = number(map, "PILLAR_KMS_CHAIN_KEY_CONCURRENCY", 0, false)?;
                if value > kms_key_concurrency
                    || (kms_key_concurrency > 1 && value == kms_key_concurrency)
                {
                    return Err(
                        "invalid PILLAR_KMS_CHAIN_KEY_CONCURRENCY: must leave headroom below PILLAR_KMS_KEY_CONCURRENCY"
                            .into(),
                    );
                }
                value
            }
        };
        Ok(Self {
            signing,
            rpc,
            kms,
            kms_key_concurrency,
            kms_lane_key_concurrency,
        })
    }
}
impl AuditConfig {
    pub fn from_map(map: &HashMap<String, String>) -> Result<Option<Self>, String> {
        match map.get("PILLAR_AUDIT_ENABLED").map(String::as_str) {
            None | Some("false") => return Ok(None),
            Some("true") => {}
            _ => return Err("PILLAR_AUDIT_ENABLED must be true or false".into()),
        }
        let database_url = map
            .get("PILLAR_AUDIT_DATABASE_URL")
            .filter(|v| !v.is_empty())
            .ok_or("PILLAR_AUDIT_DATABASE_URL is required for durable audit")?;
        let namespace = map
            .get("PILLAR_AUDIT_NAMESPACE")
            .filter(|v| {
                !v.is_empty()
                    && v.len() <= 128
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            })
            .ok_or("PILLAR_AUDIT_NAMESPACE must be 1-128 characters of [A-Za-z0-9._-]")?;
        let timeout_ms = number(map, "PILLAR_AUDIT_TIMEOUT_MS", 2000, false)?;
        if timeout_ms > 5000 {
            return Err("PILLAR_AUDIT_TIMEOUT_MS must not exceed 5000".into());
        }
        let max_attempts = number(map, "PILLAR_AUDIT_MAX_ATTEMPTS", 100_000, false)? as u64;
        Ok(Some(Self {
            database_url: Zeroizing::new(database_url.clone()),
            namespace: namespace.clone(),
            timeout: Duration::from_millis(timeout_ms as u64),
            max_attempts,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lane_key_limit(vars: &[(&str, &str)]) -> Result<usize, String> {
        let map = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        ExecutionLimits::from_map(&map).map(|limits| limits.kms_lane_key_concurrency)
    }

    #[test]
    fn lane_key_limit_defaults_one_below_the_key_cap_and_rejects_headroom_loss() {
        assert_eq!(lane_key_limit(&[]), Ok(3));
        assert_eq!(
            lane_key_limit(&[("PILLAR_KMS_KEY_CONCURRENCY", "2")]),
            Ok(1)
        );
        assert_eq!(
            lane_key_limit(&[("PILLAR_KMS_KEY_CONCURRENCY", "1")]),
            Ok(1)
        );
        assert_eq!(
            lane_key_limit(&[("PILLAR_KMS_CHAIN_KEY_CONCURRENCY", "2")]),
            Ok(2)
        );
        for bad in ["0", "4", "5"] {
            assert!(lane_key_limit(&[("PILLAR_KMS_CHAIN_KEY_CONCURRENCY", bad)]).is_err());
        }
        assert_eq!(
            lane_key_limit(&[
                ("PILLAR_KMS_CHAIN_CONCURRENCY", "2"),
                ("PILLAR_KMS_CHAIN_KEY_CONCURRENCY", "3")
            ]),
            Ok(3)
        );
        assert_eq!(
            lane_key_limit(&[
                ("PILLAR_KMS_KEY_CONCURRENCY", "1"),
                ("PILLAR_KMS_CHAIN_KEY_CONCURRENCY", "1")
            ]),
            Ok(1)
        );
        assert_eq!(ExecutionLimits::default().kms_lane_key_concurrency, 3);
    }
}
