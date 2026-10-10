//! `hash_table_visit_with_context` — `FUN_082d7bd4` @ **0x082d7bd4**,
//! **28 bytes** (`0x082d7bd4..0x082d7bef`; next function at 0x082d7bf0).
//! Two inbound plain BLs (0x08073394/0x080733a4), zero predicated BLs;
//! one outbound plain BL to the bucket-chain visitor at 0x080846f4.
//! Forwards table, callback and context with mode one and no mode-zero
//! callback. Deliberate deviations: none; calls the ported visitor directly.

use super::hash_table_bucket_chain_visitor::hash_table_bucket_chain_visitor;
use super::hash_table_bucket_chain_visitor::HashTableValueCallback;

/// Visits each value with `callback(value, context)`.
/// Table, nodes and callback must satisfy the bucket-chain visitor contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hash_table_visit_with_context(
    table: *mut u8,
    callback: HashTableValueCallback,
    context: u32,
) {
    hash_table_bucket_chain_visitor(table, 1, None, Some(callback), context);
}
