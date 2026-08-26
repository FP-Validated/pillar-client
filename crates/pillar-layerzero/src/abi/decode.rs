use pillar_core::AppCoreError;

pub(crate) fn abi_word(data: &[u8], index: usize) -> Result<&[u8], AppCoreError> {
    let start = index
        .checked_mul(32)
        .ok_or_else(|| AppCoreError::Internal("abi word index overflow".to_string()))?;
    let end = start + 32;
    if end > data.len() {
        return Err(AppCoreError::Internal("abi word out of range".to_string()));
    }
    Ok(&data[start..end])
}

pub(crate) fn abi_bool(data: &[u8], index: usize) -> Result<bool, AppCoreError> {
    let word = abi_word(data, index)?;
    if word[..31].iter().any(|byte| *byte != 0) {
        return Err(AppCoreError::Internal("invalid abi bool".to_string()));
    }
    match word[31] {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(AppCoreError::Internal(format!(
            "invalid abi bool value: {value}"
        ))),
    }
}

pub(crate) fn abi_word_u64(data: &[u8], index: usize) -> Result<u64, AppCoreError> {
    let word = abi_word(data, index)?;
    if word[..24].iter().any(|byte| *byte != 0) {
        return Err(AppCoreError::Internal("abi uint64 overflow".to_string()));
    }
    Ok(u64::from_be_bytes(word[24..32].try_into().map_err(
        |_| AppCoreError::Internal("invalid abi uint64".to_string()),
    )?))
}

pub(crate) fn abi_dynamic_bytes(
    data: &[u8],
    index: usize,
    head_words: usize,
) -> Result<Vec<u8>, AppCoreError> {
    let offset = abi_word_usize(data, index, head_words)?;
    if offset + 32 > data.len() {
        return Err(AppCoreError::Internal(
            "dynamic bytes offset out of range".to_string(),
        ));
    }
    let len = abi_word_value(&data[offset..offset + 32])?;
    if len > usize::MAX as u128 {
        return Err(AppCoreError::Internal(
            "dynamic bytes length overflows usize".to_string(),
        ));
    }
    let len = len as usize;
    let start = offset + 32;
    let end = start + len;
    if end > data.len() {
        return Err(AppCoreError::Internal(
            "dynamic bytes body out of range".to_string(),
        ));
    }
    Ok(data[start..end].to_vec())
}

pub(crate) fn abi_address(
    data: &[u8],
    index: usize,
    head_words: usize,
) -> Result<String, AppCoreError> {
    let start = abi_head_start(data, index, head_words)?;
    let word = &data[start..start + 32];
    Ok(format!("0x{}", hex::encode(&word[12..])))
}

pub(crate) fn abi_word_usize(
    data: &[u8],
    index: usize,
    head_words: usize,
) -> Result<usize, AppCoreError> {
    let start = abi_head_start(data, index, head_words)?;
    let value = abi_word_value(&data[start..start + 32])?;
    if value > usize::MAX as u128 {
        return Err(AppCoreError::Internal(
            "ABI word overflows usize".to_string(),
        ));
    }
    Ok(value as usize)
}

fn abi_head_start(data: &[u8], index: usize, head_words: usize) -> Result<usize, AppCoreError> {
    if index >= head_words {
        return Err(AppCoreError::Internal(
            "ABI head index out of range".to_string(),
        ));
    }
    let min_len = head_words * 32;
    if data.len() < min_len {
        return Err(AppCoreError::Internal(
            "ABI data shorter than head".to_string(),
        ));
    }
    Ok(index * 32)
}

pub(crate) fn abi_word_value(word: &[u8]) -> Result<u128, AppCoreError> {
    if word.len() != 32 {
        return Err(AppCoreError::Internal(
            "ABI word must be 32 bytes".to_string(),
        ));
    }
    if word[..16].iter().any(|byte| *byte != 0) {
        return Err(AppCoreError::Internal("ABI word exceeds u128".to_string()));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&word[16..]);
    Ok(u128::from_be_bytes(out))
}
