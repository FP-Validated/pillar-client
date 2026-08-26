//! Decode a DVN `Proxy` contract storage cell to its implementation admin,
//! ported from the upstream LayerZero TypeScript implementation
//! `getImplementationContract` (`lzDecodeClass('Proxy', ...)` ->
//! `workerCoreStorage.admins[0]`).
//!
//! The base64 storage cell comes from a quorum-agreed toncenter contract-state
//! read (the runtime supplies it); this module is pure decoding.

use num_bigint::BigUint;

use super::cell::{boc_from_base64, map_err};
use super::cl_declare::{cell_name, cl_get_ref};
use pillar_core::AppCoreError;

/// `tonObjects.Proxy.name`.
const PROXY_NAME: &str = "pfProxy";

/// Decode the implementation (admin) target address from a DVN proxy storage
/// cell (base64 BOC). Returns `None` when the cell is not a `Proxy` (the caller
/// then falls back to the original DVN address, like `getImplementationContract`).
pub fn decode_proxy_admin_target(storage_boc_base64: &str) -> Result<Option<String>, AppCoreError> {
    let cell = boc_from_base64(storage_boc_base64)?;
    if cell_name(&cell)? != PROXY_NAME {
        return Ok(None);
    }
    // Proxy field 0 = workerCoreStorage; WorkerCoreStorage field 0 = admins.
    let worker_core_storage = cl_get_ref(&cell, 0)?;
    let admins = cl_get_ref(&worker_core_storage, 0)?;

    let mut parser = admins.parser();
    let admin: BigUint = parser.read_num(256).map_err(map_err)?;
    let raw = admin.to_bytes_be();
    let mut be = [0u8; 32];
    be[32 - raw.len()..].copy_from_slice(&raw);
    Ok(Some(format!("0:{}", hex::encode(be))))
}

#[cfg(test)]
mod tests {
    use super::super::cell::{build, builder};
    use super::super::cl_declare::{cl_declare, ClField, T_UINT256};
    use super::*;
    use ton_core::cell::{BoC, TonCell};

    fn addr_be(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn to_base64(cell: &TonCell) -> String {
        BoC::new(cell.clone()).to_base64(true).unwrap()
    }

    fn build_proxy_storage(admin: &[u8; 32]) -> TonCell {
        let mut admins_b = builder();
        admins_b
            .write_num(&BigUint::from_bytes_be(admin), 256)
            .unwrap();
        let admins = build(admins_b).unwrap();

        let worker_core_storage = cl_declare(
            "wrkCorStor",
            vec![
                ClField::Ref(admins),
                ClField::u256_be(T_UINT256, &addr_be(0xaa)), // proxy
                ClField::u256_be(T_UINT256, &[0u8; 32]),     // version
            ],
        )
        .unwrap();

        cl_declare(
            "pfProxy",
            vec![
                ClField::Ref(worker_core_storage),
                ClField::uint(0, 0u32), // callbackEnabled = false
            ],
        )
        .unwrap()
    }

    #[test]
    fn decodes_proxy_admin() {
        let admin = addr_be(0x42);
        let proxy = build_proxy_storage(&admin);
        let target = decode_proxy_admin_target(&to_base64(&proxy)).unwrap();
        assert_eq!(target, Some(format!("0:{}", hex::encode(admin))));
    }

    #[test]
    fn non_proxy_returns_none() {
        let other = cl_declare("Attest", vec![ClField::uint(0, 0u32)]).unwrap();
        assert_eq!(decode_proxy_admin_target(&to_base64(&other)).unwrap(), None);
    }
}
