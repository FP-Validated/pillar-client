use pillar_core::AppCoreError;

use crate::abi::decode_hex_bytes;
use crate::types::{
    EvmReadCommand, EvmReadCompute, EvmReadComputeSetting, EvmReadRequest, ReadResolvedTimeMarker,
    ReadTimeMarker,
};

const MAX_READ_REQUESTS: u16 = 256;

pub fn decode_evm_read_command(cmd: &str) -> Result<EvmReadCommand, AppCoreError> {
    let bytes = decode_hex_bytes(cmd)?;
    let mut cursor = ReadCursor::new(&bytes);
    let global_version = cursor.read_u16()?;
    let app_command_label = cursor.read_hex(2)?;
    let request_count = cursor.read_u16()?;
    if request_count > MAX_READ_REQUESTS {
        return Err(AppCoreError::BadRequest(format!(
            "read request count {request_count} exceeds limit {MAX_READ_REQUESTS}"
        )));
    }
    let mut requests = Vec::with_capacity(request_count as usize);
    for _ in 0..request_count {
        requests.push(decode_evm_read_request(&mut cursor)?);
    }
    let compute = if cursor.remaining() > 0 {
        Some(decode_evm_read_compute(&mut cursor)?)
    } else {
        None
    };
    if cursor.remaining() != 0 {
        return Err(AppCoreError::Internal(
            "Trailing bytes in read command".to_string(),
        ));
    }
    Ok(EvmReadCommand {
        global_version,
        app_command_label,
        requests,
        compute,
    })
}

pub fn extract_evm_read_resolved_time_markers(
    cmd: &str,
) -> Result<Vec<ReadResolvedTimeMarker>, AppCoreError> {
    let command = decode_evm_read_command(cmd)?;
    let mut markers = Vec::new();
    for request in command.requests {
        push_unique_read_marker(
            &mut markers,
            ReadResolvedTimeMarker {
                target_eid: request.target_eid,
                marker: request.marker,
                block_confirmation: request.block_confirmation,
            },
        );
    }
    if let Some(compute) = command.compute {
        push_unique_read_marker(
            &mut markers,
            ReadResolvedTimeMarker {
                target_eid: compute.target_eid,
                marker: compute.marker,
                block_confirmation: compute.block_confirmation,
            },
        );
    }
    if markers.iter().any(|marker| {
        matches!(
            marker.marker,
            ReadTimeMarker::BlockNumber { block_number: 0 }
        )
    }) {
        return Err(AppCoreError::Internal(
            "Malformed command: Block number cannot be zero!".to_string(),
        ));
    }
    Ok(markers)
}

fn push_unique_read_marker(
    markers: &mut Vec<ReadResolvedTimeMarker>,
    marker: ReadResolvedTimeMarker,
) {
    if !markers.iter().any(|existing| existing == &marker) {
        markers.push(marker);
    }
}

fn decode_evm_read_request(cursor: &mut ReadCursor<'_>) -> Result<EvmReadRequest, AppCoreError> {
    let request_start = cursor.position();
    let _request_version = cursor.read_u8()?;
    let _app_request_label = cursor.read_hex(2)?;
    let resolver_type = cursor.read_u16()?;
    if resolver_type != 1 {
        return Err(AppCoreError::Internal(format!(
            "Unsupported resolver type: {resolver_type}"
        )));
    }
    let request_size = cursor.read_u16()? as usize;
    let body_start = cursor.position();
    let (target_eid, marker, block_confirmation, to) = decode_evm_read_base(cursor)?;
    let consumed = cursor.position() - body_start;
    if request_size < consumed {
        return Err(AppCoreError::Internal(
            "Read request size is shorter than EVM base".to_string(),
        ));
    }
    let calldata = cursor.read_hex(request_size - consumed)?;
    let request = format!(
        "0x{}",
        hex::encode(&cursor.bytes[request_start..cursor.position()])
    );
    Ok(EvmReadRequest {
        request,
        target_eid,
        marker,
        block_confirmation,
        to,
        calldata: format!("0x{calldata}"),
    })
}

fn decode_evm_read_compute(cursor: &mut ReadCursor<'_>) -> Result<EvmReadCompute, AppCoreError> {
    let _compute_version = cursor.read_u8()?;
    let compute_type = cursor.read_u16()?;
    if compute_type != 1 {
        return Err(AppCoreError::Internal(format!(
            "Unsupported compute type: {compute_type}"
        )));
    }
    let setting = match cursor.read_u8()? {
        0 => EvmReadComputeSetting::OnlyMap,
        1 => EvmReadComputeSetting::OnlyReduce,
        2 => EvmReadComputeSetting::MapReduce,
        value => {
            return Err(AppCoreError::Internal(format!(
                "Unsupported compute setting: {value}"
            )))
        }
    };
    let (target_eid, marker, block_confirmation, to) = decode_evm_read_base(cursor)?;
    Ok(EvmReadCompute {
        target_eid,
        marker,
        block_confirmation,
        to,
        setting,
    })
}

fn decode_evm_read_base(
    cursor: &mut ReadCursor<'_>,
) -> Result<(u32, ReadTimeMarker, u16, String), AppCoreError> {
    let target_eid = cursor.read_u32()?;
    let marker = match cursor.read_u8()? {
        0 => ReadTimeMarker::Timestamp {
            timestamp: cursor.read_u64()?,
        },
        1 => ReadTimeMarker::BlockNumber {
            block_number: cursor.read_u64()?,
        },
        value => {
            return Err(AppCoreError::Internal(format!(
                "Unsupported timestamp block flag: {value}"
            )))
        }
    };
    let block_confirmation = cursor.read_u16()?;
    let to = format!("0x{}", cursor.read_hex(20)?);
    Ok((target_eid, marker, block_confirmation, to))
}

struct ReadCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ReadCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn position(&self) -> usize {
        self.offset
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn read_u8(&mut self) -> Result<u8, AppCoreError> {
        let bytes = self.read_bytes(1)?;
        Ok(bytes[0])
    }

    fn read_u16(&mut self) -> Result<u16, AppCoreError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes(bytes.try_into().map_err(|_| {
            AppCoreError::Internal("invalid u16".to_string())
        })?))
    }

    fn read_u32(&mut self) -> Result<u32, AppCoreError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| {
            AppCoreError::Internal("invalid u32".to_string())
        })?))
    }

    fn read_u64(&mut self) -> Result<u64, AppCoreError> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| {
            AppCoreError::Internal("invalid u64".to_string())
        })?))
    }

    fn read_hex(&mut self, len: usize) -> Result<String, AppCoreError> {
        Ok(hex::encode(self.read_bytes(len)?))
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], AppCoreError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| AppCoreError::Internal("read cursor overflow".to_string()))?;
        if end > self.bytes.len() {
            return Err(AppCoreError::Internal(
                "read command ended unexpectedly".to_string(),
            ));
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }
}
