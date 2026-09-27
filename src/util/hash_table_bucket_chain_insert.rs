//! Hash-table bucket-chain insertion — retailOS `FUN_083d32d4` at load
//! address `0x083d32d4`.
//!
//! Load address: `0x083d32d4`; true size: 40 bytes (`0x28`), from the first
//! `ldr` through `bx lr` at `0x083d32f8`; `push {r4-r8,lr}` at `0x083d32fc`
//! begins the next real function. Raw ARM decoding verifies two inbound plain
//! `bl` instructions (at `0x083d2774` and `0x083d29b8`) and zero predicated
//! `bl` instructions; this leaf has no outbound calls.
//!
//! Inserts `node` at the word-0 intrusive chain rooted at `chain_head`,
//! increments the owning hash table's word +0x10 node count with ARM `u32`
//! wrapping, and lowers word +0x0c's bucket cursor when this chain-head
//! address is lower. There are no deliberate deviations: owner fields and
//! links remain target-width `u32` words, so host pointer width cannot alter
//! the firmware layout.

/// Inserts an intrusive node into one target-width hash-table bucket chain.
///
/// # Safety
///
/// `table` must provide writable words through +0x10. `node` and `chain_head`
/// must be writable target-width pointer words; their values must identify
/// valid target-addressable nodes when nonzero.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.hash_table_bucket_chain_insert")]
#[inline(never)]
pub unsafe extern "C" fn hash_table_bucket_chain_insert(
    table: *mut u8,
    node: *mut u32,
    chain_head: *mut u32,
) {
    unsafe {
        node.write(chain_head.read());
        chain_head.write(node as usize as u32);
        let count = table.add(0x10).cast::<u32>();
        count.write_volatile(count.read_volatile().wrapping_add(1));

        let cursor = table.add(0x0c).cast::<u32>();
        if (chain_head as usize) < cursor.read_volatile() as usize {
            cursor.write_volatile(chain_head as usize as u32);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::testing::{hints, try_map_u32_slab};

    use super::hash_table_bucket_chain_insert;

    #[test]
    fn prepends_chain_wraps_count_and_only_lowers_cursor() {
        let Some(slab) = try_map_u32_slab(hints::HASH_TABLE_BUCKET_CHAIN_INSERT, 0x1000) else {
            return;
        };
        let table = slab;
        let lower_head = unsafe { slab.add(0x40).cast::<u32>() };
        let higher_head = unsafe { slab.add(0x60).cast::<u32>() };
        let first = unsafe { slab.add(0x80).cast::<u32>() };
        let second = unsafe { slab.add(0x90).cast::<u32>() };

        unsafe {
            table.add(0x0c).cast::<u32>().write((higher_head as usize) as u32);
            table.add(0x10).cast::<u32>().write(u32::MAX);
            first.write(0x1234_5678);
            lower_head.write(first as usize as u32);
            higher_head.write(0);

            hash_table_bucket_chain_insert(table, second, lower_head);

            assert_eq!(second.read(), first as usize as u32);
            assert_eq!(lower_head.read(), second as usize as u32);
            assert_eq!(table.add(0x10).cast::<u32>().read(), 0);
            assert_eq!(table.add(0x0c).cast::<u32>().read(), lower_head as usize as u32);

            hash_table_bucket_chain_insert(table, first, higher_head);

            assert_eq!(first.read(), 0);
            assert_eq!(higher_head.read(), first as usize as u32);
            assert_eq!(table.add(0x10).cast::<u32>().read(), 1);
            assert_eq!(table.add(0x0c).cast::<u32>().read(), lower_head as usize as u32);
        }
    }
}
