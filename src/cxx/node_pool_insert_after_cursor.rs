//! `node_pool_insert_after_cursor` — retailOS `FUN_083d345c` @ `0x083d345c`.
//!
//! Raw `osos.dec` establishes the true 40-byte extent: ten A32 words from
//! `ldr r3, [r2]` through `bx lr` at `0x083d3480`; the next independently
//! linked function begins at `0x083d3484`. The body has no BL instructions.
//! The two direct inbound calls are plain unconditional `bl` instructions
//! (`0x083d2a9c` and `0x083d2ce0`); there are no predicated inbound `bl`
//! instructions.
//!
//! Inserts `node` immediately after `cursor` in its singly linked chain,
//! increments the target pool's word at `+0x10`, and replaces its `+0x0c`
//! low-water cursor when `cursor` compares lower as an unsigned address.
//! Deliberate deviations: pool state and links use target-width `u32` words,
//! and volatile accesses retain retailOS's observable load/store ordering on
//! 64-bit test hosts.

const LOW_WATER_CURSOR: usize = 3;
const LINKED_COUNT: usize = 4;

/// Inserts `node` immediately after `cursor` and updates its target pool state.
///
/// # Safety
///
/// `pool` must identify at least five writable target words, and `node` and
/// `cursor` must identify writable nodes whose first word is a link.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.node_pool_insert_after_cursor")]
#[inline(never)]
pub unsafe extern "C" fn node_pool_insert_after_cursor(
    pool: *mut u32,
    node: *mut u32,
    cursor: *mut u32,
) {
    unsafe {
        node.write_volatile(cursor.read_volatile());
        cursor.write_volatile(node as usize as u32);
        let count = pool.add(LINKED_COUNT);
        count.write_volatile(count.read_volatile().wrapping_add(1));
        let low_water_cursor = pool.add(LOW_WATER_CURSOR);
        if (cursor as usize as u32) < low_water_cursor.read_volatile() {
            low_water_cursor.write_volatile(cursor as usize as u32);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn inserts_after_cursor_updates_count_and_low_water_mark() {
        let Some(slab) = try_map_u32_slab(hints::NODE_POOL_INSERT_AFTER_CURSOR, 0x1000) else {
            note_missing_u32_fixture("node_pool_insert_after_cursor");
            return;
        };
        let words = slab.cast::<u32>();
        unsafe {
            let pool = words.add(0);
            let cursor = words.add(8);
            let node = words.add(12);
            let successor = words.add(16);
            *cursor = successor as usize as u32;
            *node = 0xdead_beef;
            *pool.add(LOW_WATER_CURSOR) = u32::MAX;
            *pool.add(LINKED_COUNT) = u32::MAX;

            node_pool_insert_after_cursor(pool, node, cursor);

            assert_eq!(*cursor, node as usize as u32);
            assert_eq!(*node, successor as usize as u32);
            assert_eq!(*pool.add(LINKED_COUNT), 0);
            assert_eq!(*pool.add(LOW_WATER_CURSOR), cursor as usize as u32);
            let low_cursor = words.add(4);
            let second_cursor = words.add(20);
            let second_node = words.add(24);
            *second_cursor = 0;
            *pool.add(LOW_WATER_CURSOR) = low_cursor as usize as u32;
            *pool.add(LINKED_COUNT) = 7;

            node_pool_insert_after_cursor(pool, second_node, second_cursor);

            assert_eq!(*second_cursor, second_node as usize as u32);
            assert_eq!(*second_node, 0);
            assert_eq!(*pool.add(LINKED_COUNT), 8);
            assert_eq!(*pool.add(LOW_WATER_CURSOR), low_cursor as usize as u32);
        }
    }
}
