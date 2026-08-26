use super::*;

#[derive(Clone)]
struct FunctionBlockTransport {
    max_block_number: i64,
    timestamp_for_block: fn(i64) -> i64,
}

#[async_trait]
impl JsonRpcTransport for FunctionBlockTransport {
    async fn post_json(
        &self,
        _url: String,
        _headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        let tag = body["params"][0]
            .as_str()
            .ok_or_else(|| "missing block tag".to_string())?;
        let number = if tag == "latest" {
            self.max_block_number
        } else {
            i64::from_str_radix(tag.trim_start_matches("0x"), 16)
                .map_err(|error| error.to_string())?
        };
        if number < 1 || number > self.max_block_number {
            return Err("Invalid block number".to_string());
        }
        Ok(block_time(
            number,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            (self.timestamp_for_block)(number),
        ))
    }

    async fn get_json(
        &self,
        _url: String,
        _headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        Err("GET is not used for EVM timestamp resolution".to_string())
    }
}

async fn assert_resolves_all_timestamps_for_curve(
    timestamp_for_block: fn(i64) -> i64,
    max_block_number: i64,
) {
    let first_timestamp = timestamp_for_block(1);
    let latest_timestamp = timestamp_for_block(max_block_number);
    let timestamps = (first_timestamp..=latest_timestamp).collect::<Vec<_>>();

    for avg_block_time in [1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0] {
        let transport = FunctionBlockTransport {
            max_block_number,
            timestamp_for_block,
        };
        let resolved = resolve_evm_timestamps(
            transport,
            "https://ethereum-rpc.example".to_string(),
            HashMap::new(),
            "ethereum",
            avg_block_time,
            &timestamps,
        )
        .await
        .unwrap();

        for timestamp in &timestamps {
            let block_number = resolved[timestamp];
            assert!((1..=max_block_number).contains(&block_number));
            let block_timestamp = timestamp_for_block(block_number);
            if block_number == 1 {
                assert_eq!(block_timestamp, *timestamp);
            } else {
                assert!(block_timestamp >= *timestamp);
                assert!(timestamp_for_block(block_number - 1) < *timestamp);
            }
        }
    }
}

fn linear_timestamp(number: i64) -> i64 {
    2 * number
}

fn constant_timestamp(_number: i64) -> i64 {
    100
}

fn quadratic_timestamp(number: i64) -> i64 {
    ((number * number) + 9) / 10
}

fn square_root_timestamp(number: i64) -> i64 {
    100 * (number as f64).sqrt().floor() as i64
}

fn stair_step_timestamp(number: i64) -> i64 {
    (number + 9) / 10
}

fn random_timestamp(number: i64) -> i64 {
    let mut seed = 1u64;
    let mut sum = 0i64;
    for _ in 1..=number {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223) % (1u64 << 32);
        let value = ((seed as f64 / (1u64 << 32) as f64) * 5.0).floor() as i64 + 1;
        sum += value;
    }
    sum
}

#[tokio::test]
async fn resolve_timestamps_matches_typescript_linear_function() {
    assert_resolves_all_timestamps_for_curve(linear_timestamp, 100).await;
}

#[tokio::test]
async fn resolve_timestamps_matches_typescript_constant_function() {
    assert_resolves_all_timestamps_for_curve(constant_timestamp, 100).await;
}

#[tokio::test]
async fn resolve_timestamps_matches_typescript_quadratic_function() {
    assert_resolves_all_timestamps_for_curve(quadratic_timestamp, 100).await;
}

#[tokio::test]
async fn resolve_timestamps_matches_typescript_square_root_function() {
    assert_resolves_all_timestamps_for_curve(square_root_timestamp, 100).await;
}

#[tokio::test]
async fn resolve_timestamps_matches_typescript_stair_step_function() {
    assert_resolves_all_timestamps_for_curve(stair_step_timestamp, 100).await;
}

#[tokio::test]
async fn resolve_timestamps_matches_typescript_random_function() {
    assert_resolves_all_timestamps_for_curve(random_timestamp, 100).await;
}

#[tokio::test]
async fn resolve_timestamps_rejects_invalid_avg_block_time_like_typescript() {
    let err = resolve_evm_timestamps(
        FunctionBlockTransport {
            max_block_number: 100,
            timestamp_for_block: linear_timestamp,
        },
        "https://ethereum-rpc.example".to_string(),
        HashMap::new(),
        "ethereum",
        0.0,
        &[200],
    )
    .await
    .unwrap_err();

    assert_eq!(
        err.to_string(),
        "Invalid average block time for ethereum chain: 0 (seconds)"
    );
    assert!(matches!(err, AppCoreError::BadRequest(_)));
}
