//! `timing_wheel_node_replace_value` — retailOS `FUN_080fe5a0` @ `0x080fe5a0`.
//!
//! ## Extent and call sites, byte-verified
//!
//! The function occupies 88 bytes, from `0x080fe5a0` through its literal pool
//! word at `0x080fe5f8`; `0x080fe5fc` opens the next separately linked
//! function. Its body has two plain `bl` calls and one predicated `blne` call;
//! full-image decoding finds three inbound plain `bl` calls and no predicated
//! inbound forms.
//!
//! ## Algorithm
//!
//! Remove `node` from the scheduler timing wheel, retain `value`, release its
//! old `+0x1c` value when non-null, store `value` at `+0x1c` and `payload` at
//! `+0x18`, set rank to `value[2] + 1` with wrapping arithmetic, and tail-call
//! the timing-wheel insertion helper.
//!
//! ## Deliberate deviation
//!
//! Target firmware loads the scheduler table through global `0x089cc7e0`.
//! This port uses the existing `scheduler_table` host model; target builds
//! retain the same table singleton. Target pointer fields remain `u32` word
//! indices, so host pointer width never changes their offsets.

use crate::app::animation::{scheduler_table, timing_wheel_insert, timing_wheel_remove};
use crate::app::refcounted_value::{release_refcounted_value, retain_value};

/// Replaces a timing-wheel node's value and payload, then re-buckets it by the
/// new value's auxiliary word. `node` and `value` must be live, aligned
/// target-layout objects; node words `2`, `6`, and `7` correspond to offsets
/// `+0x08`, `+0x18`, and `+0x1c` respectively.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn timing_wheel_node_replace_value(
    node: *mut u32,
    value: *mut u32,
    payload: u32,
) {
    let table = scheduler_table();
    timing_wheel_remove(table, node);
    retain_value(value.cast());

    let old_value = *node.add(7);
    if old_value != 0 {
        release_refcounted_value(old_value as usize as *mut u8);
    }

    *node.add(7) = value as usize as u32;
    *node.add(6) = payload;
    *node.add(2) = (*value.add(2)).wrapping_add(1);
    timing_wheel_insert(table, node);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::animation::TIMING_WHEEL_BUCKETS;
    use crate::testing::{try_map_u32_slab, SCHEDULER_TABLE_TEST_LOCK};
    use std::sync::LazyLock;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(crate::testing::hints::TIMING_WHEEL_NODE_REPLACE_VALUE, 0x1000)
            .map(|pointer| pointer as usize)
    });

    fn fixture() -> Option<(*mut u32, *mut u32)> {
        let base = (*FIXTURE)? as *mut u32;
        Some((base, unsafe { base.add(16) }))
    }

    #[test]
    fn replaces_payload_retains_value_and_rebuckets_linked_node() {
        let _lock = SCHEDULER_TABLE_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let Some((node, value)) = fixture() else {
            return;
        };
        let table = scheduler_table();
        unsafe {
            for index in 0..TIMING_WHEEL_BUCKETS {
                *table.add(index) = 0;
            }
            core::ptr::write_bytes(node, 0, 16);
            core::ptr::write_bytes(value, 0, 6);
            *node.add(2) = 1;
            *node.add(5) = 1;
            *node.add(6) = 0x1111_2222;
            *node.add(7) = 0;
            *table = node as usize as u32;
            *value.add(2) = 3;
            *value.add(5) = 2;

            timing_wheel_node_replace_value(node, value, 0xaabb_ccdd);

            assert_eq!(*node.add(2), 4);
            assert_eq!(*node.add(6), 0xaabb_ccdd);
            assert_eq!(*node.add(7), value as usize as u32);
            assert_eq!(*value.add(5), 6);
            assert_eq!(*table, 0);
            assert_eq!(*table.add(3), node as usize as u32);
            assert_eq!(*node.add(5) & 1, 1);
        }
    }

    #[test]
    fn wrapping_rank_and_unlinked_input_leave_wheel_empty() {
        let _lock = SCHEDULER_TABLE_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let Some((node, value)) = fixture() else {
            return;
        };
        let table = scheduler_table();
        unsafe {
            for index in 0..TIMING_WHEEL_BUCKETS {
                *table.add(index) = 0;
            }
            core::ptr::write_bytes(node, 0, 16);
            core::ptr::write_bytes(value, 0, 6);
            *value.add(2) = u32::MAX;

            timing_wheel_node_replace_value(node, value, 0);

            assert_eq!(*node.add(2), 0);
            assert_eq!(*node.add(7), value as usize as u32);
            assert!(core::slice::from_raw_parts(table, TIMING_WHEEL_BUCKETS)
                .iter()
                .all(|bucket| *bucket == 0));
        }
    }
}
