//! `hash_table_visit` — `FUN_082d7bb8` @ **0x082d7bb8**, **28 bytes**
//! (`0x082d7bb8..0x082d7bd3`; next function at 0x082d7bd4).
//! Two inbound plain BLs (0x080782f8/0x082d9020), zero predicated BLs;
//! one outbound plain BL to the bucket-chain visitor at 0x080846f4.
//! Forwards table and callback with mode zero, no context callback and zero
//! context. Deliberate deviations: none; calls the ported visitor directly.

use super::hash_table_bucket_chain_visitor::{
    hash_table_bucket_chain_visitor, HashTableVisitCallback,
};

/// Visits each value with `callback(value)`.
/// Table, nodes and callback must satisfy the bucket-chain visitor contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hash_table_visit(
    table: *mut u8,
    callback: HashTableVisitCallback,
) {
    hash_table_bucket_chain_visitor(table, 0, Some(callback), None, 0);
}
