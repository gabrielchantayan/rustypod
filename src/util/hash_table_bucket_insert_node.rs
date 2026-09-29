//! `hash_table_bucket_insert_node` — retailOS `FUN_082d6990` at load address
//! `0x082d6990`.
//!
//! Load address: `0x082d6990`; true size: 96 bytes (`0x60`), from `ldr r3,
//! [r1,#4]` through `bx lr` at `0x082d69ec`; `ldr r2,[r0]` at `0x082d69f0`
//! begins the next real function. Raw ARM decoding verifies two inbound plain
//! `bl` instructions (at `0x08367504` and `0x0837af84`) and zero predicated
//! `bl` instructions; this leaf has no outbound calls.
//!
//! Inserts `node` before the current head of `bucket`'s contiguous run in the
//! table-wide intrusive doubly linked list. An empty bucket prepends to the
//! table list; a populated bucket inserts before that bucket's current head.
//! It then increments the bucket count with ARM `u32` wrapping and records
//! `node` as the bucket head. There are no deliberate deviations: all firmware
//! links and counters remain target-width `u32` words.

/// Inserts a node into a target-width hash-table bucket run.
///
/// # Safety
///
/// `table` must provide writable word +3. `bucket` must provide writable words
/// +0 and +1. `node` must provide writable words +0 and +1. Every nonzero link
/// word must identify a writable node with words +0 and +1.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.hash_table_bucket_insert_node")]
#[inline(never)]
pub unsafe extern "C" fn hash_table_bucket_insert_node(
    table: *mut u32,
    bucket: *mut u32,
    node: *mut u32,
) {
    unsafe {
        let bucket_head = bucket.add(1).read();
        if bucket_head == 0 {
            let table_head = table.add(3).read();
            node.write(table_head);
            if table_head != 0 {
                (table_head as usize as *mut u32).add(1).write(node as usize as u32);
            }
            node.add(1).write(0);
            table.add(3).write(node as usize as u32);
        } else {
            let old_head = bucket_head as usize as *mut u32;
            node.write(bucket_head);
            let previous = old_head.add(1).read();
            node.add(1).write(previous);
            if previous == 0 {
                table.add(3).write(node as usize as u32);
            } else {
                (previous as usize as *mut u32).write(node as usize as u32);
            }
            old_head.add(1).write(node as usize as u32);
        }
        bucket.write(bucket.read().wrapping_add(1));
        bucket.add(1).write(node as usize as u32);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::testing::{hints, try_map_u32_slab};

    use super::hash_table_bucket_insert_node;

    #[test]
    fn prepends_empty_bucket_and_links_prior_table_head() {
        let Some(slab) = try_map_u32_slab(hints::HASH_TABLE_BUCKET_INSERT_NODE, 0x1000) else {
            return;
        };
        let table = slab.cast::<u32>();
        let bucket = unsafe { slab.add(0x20).cast::<u32>() };
        let old_head = unsafe { slab.add(0x40).cast::<u32>() };
        let node = unsafe { slab.add(0x60).cast::<u32>() };

        unsafe {
            table.add(3).write(old_head as usize as u32);
            old_head.add(1).write(0);
            bucket.write(u32::MAX);
            bucket.add(1).write(0);

            hash_table_bucket_insert_node(table, bucket, node);

            assert_eq!(node.read(), old_head as usize as u32);
            assert_eq!(node.add(1).read(), 0);
            assert_eq!(old_head.add(1).read(), node as usize as u32);
            assert_eq!(table.add(3).read(), node as usize as u32);
            assert_eq!(bucket.read(), 0);
            assert_eq!(bucket.add(1).read(), node as usize as u32);
        }
    }

    #[test]
    fn inserts_before_populated_bucket_without_moving_table_head() {
        let Some(slab) = try_map_u32_slab(hints::HASH_TABLE_BUCKET_INSERT_NODE_POPULATED, 0x1000) else {
            return;
        };
        let table = slab.cast::<u32>();
        let bucket = unsafe { slab.add(0x20).cast::<u32>() };
        let previous = unsafe { slab.add(0x40).cast::<u32>() };
        let old_head = unsafe { slab.add(0x60).cast::<u32>() };
        let node = unsafe { slab.add(0x80).cast::<u32>() };

        unsafe {
            table.add(3).write(previous as usize as u32);
            previous.write(old_head as usize as u32);
            old_head.add(1).write(previous as usize as u32);
            bucket.write(3);
            bucket.add(1).write(old_head as usize as u32);

            hash_table_bucket_insert_node(table, bucket, node);

            assert_eq!(previous.read(), node as usize as u32);
            assert_eq!(node.read(), old_head as usize as u32);
            assert_eq!(node.add(1).read(), previous as usize as u32);
            assert_eq!(old_head.add(1).read(), node as usize as u32);
            assert_eq!(table.add(3).read(), previous as usize as u32);
            assert_eq!(bucket.read(), 4);
            assert_eq!(bucket.add(1).read(), node as usize as u32);
        }
    }
}
