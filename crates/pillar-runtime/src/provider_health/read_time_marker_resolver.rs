use super::*;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) async fn resolve_evm_timestamps<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    chain_name: &str,
    avg_block_time_seconds: f64,
    timestamps: &[i64],
) -> Result<BTreeMap<i64, i64>, AppCoreError>
where
    T: JsonRpcTransport,
{
    if avg_block_time_seconds <= 0.0 {
        return Err(AppCoreError::BadRequest(format!(
            "Invalid average block time for {chain_name} chain: {avg_block_time_seconds} (seconds)"
        )));
    }

    let mut resolved = BTreeMap::new();
    for target_timestamp in timestamps.iter().copied().collect::<BTreeSet<_>>() {
        let block_number = resolve_evm_timestamp(
            transport.clone(),
            url.clone(),
            headers.clone(),
            target_timestamp,
            avg_block_time_seconds,
        )
        .await?;
        resolved.insert(target_timestamp, block_number);
    }
    Ok(resolved)
}

async fn resolve_evm_timestamp<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    target_timestamp: i64,
    initial_avg_block_time_seconds: f64,
) -> Result<i64, AppCoreError>
where
    T: JsonRpcTransport,
{
    let latest_block =
        block_time_for_tag(transport.clone(), url.clone(), headers.clone(), "latest").await?;
    if target_timestamp > latest_block.timestamp {
        return Err(AppCoreError::BadRequest(format!(
            "Target timestamp {target_timestamp} is in the future"
        )));
    }

    let mut avg_block_time = initial_avg_block_time_seconds;
    let mut current_block = latest_block.clone();
    let mut upper_bound_block = latest_block.clone();
    let mut lower_bound_block = None::<BlockTime>;
    let max_attempts = latest_block.number.saturating_mul(4).max(16) as usize;

    for _ in 0..max_attempts {
        let mut blocks_to_jump =
            ((current_block.timestamp - target_timestamp) as f64 / avg_block_time).floor() as i64;
        if blocks_to_jump == 0 {
            blocks_to_jump = 1;
        }
        let target_block_number =
            (current_block.number - blocks_to_jump).clamp(1, latest_block.number);
        let next_block = block_time_for_tag(
            transport.clone(),
            url.clone(),
            headers.clone(),
            &format!("0x{target_block_number:x}"),
        )
        .await?;
        let previous_block = if target_block_number > 1 {
            Some(
                block_time_for_tag(
                    transport.clone(),
                    url.clone(),
                    headers.clone(),
                    &format!("0x{:x}", target_block_number - 1),
                )
                .await?,
            )
        } else {
            None
        };

        if block_matches_resolved_timestamp(&next_block, previous_block.as_ref(), target_timestamp)
        {
            return Ok(next_block.number);
        }

        if next_block.number == 1 && next_block.timestamp > target_timestamp {
            return Err(AppCoreError::BadRequest(format!(
                "Malformed command: Requested a timestamp lower than the first block: {target_timestamp}"
            )));
        }

        if next_block.timestamp >= target_timestamp {
            if next_block.number < upper_bound_block.number {
                upper_bound_block = next_block.clone();
            }
        } else if lower_bound_block
            .as_ref()
            .is_none_or(|block| block.number < next_block.number)
        {
            lower_bound_block = Some(next_block.clone());
        }

        let updated_avg_block_time = if let Some(lower_bound) = lower_bound_block.as_ref() {
            calculate_avg_block_time(lower_bound, &upper_bound_block)?
        } else {
            calculate_avg_block_time(&next_block, &latest_block)?
        };
        if updated_avg_block_time > 0.0 {
            avg_block_time = updated_avg_block_time;
        }
        current_block = next_block;
    }

    Err(AppCoreError::Internal(format!(
        "Unable to resolve timestamp {target_timestamp} within {max_attempts} block probes"
    )))
}

async fn block_time_for_tag<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    block_tag: &str,
) -> Result<BlockTime, AppCoreError>
where
    T: JsonRpcTransport,
{
    observe_block_time(transport, url, headers, block_tag)
        .await
        .map(|observation| observation.block)
}

fn calculate_avg_block_time(
    left_block: &BlockTime,
    right_block: &BlockTime,
) -> Result<f64, AppCoreError> {
    let block_delta = right_block.number - left_block.number;
    if block_delta == 0 {
        return Ok(0.0);
    }
    let avg_block_time = (right_block.timestamp - left_block.timestamp) as f64 / block_delta as f64;
    if avg_block_time < 0.0 {
        Err(AppCoreError::BadRequest(
            "Invalid block: The block with a smaller number has a larger timestamp".to_string(),
        ))
    } else {
        Ok(avg_block_time)
    }
}
