//! retailOS `FUN_080fe678` @ `0x080fe678`: true extent 44 bytes.
//! Ten instructions occupy 0x080fe678..0x080fe69c; the vtable literal at
//! 0x080fe6a0 is 0x089800f8, and the next function starts at 0x080fe6a4.
//! Whole-image aligned ARM branch decoding finds two incoming plain BLs
//! (0x080fe66c, 0x08153248), zero incoming predicated BLs or tail branches,
//! and no aligned DATA references. Body: zero plain BLs, one BLNE to
//! release_refcounted_value, and a tail B to refcounted_base_destroy.
//!
//! Installs the derived vtable, releases the non-NULL owned value at +0x1c,
//! then destroys the timing-wheel base and returns the original pointer.
//! Neither the owned slot nor the opaque payload at +0x18 is cleared.
//! Deliberate deviations: Rust need not emit the final tail branch; the base
//! port supplies the existing host scheduler model. Vtable is an address
//! constant, not interpreted as live table data. Word indices preserve the
//! four-byte firmware layout on hosts with wider pointers.

use crate::app::fixed_value::refcounted_base_destroy;
use crate::app::refcounted_value::release_refcounted_value;

/// # Safety
/// `node` must be aligned and writable for eight words. Its nonzero owned
/// value must satisfy release_refcounted_value's contract, and its base
/// rank/links must satisfy refcounted_base_destroy's timing-wheel invariants.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn timing_wheel_node_destroy(node: *mut u32) -> *mut u32 {
    node.write_volatile(0x0898_00f8);
    let value = *node.add(7);
    if value != 0 {
        release_refcounted_value(value as usize as *mut u8);
    }
    refcounted_base_destroy(node.cast()).cast()
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::app::animation::{scheduler_table, TIMING_WHEEL_BUCKETS};
    use crate::app::fixed_value::REFCOUNTED_BASE_VTABLE;
    use crate::testing::{note_missing_u32_fixture, try_map_u32_slab, SCHEDULER_TABLE_TEST_LOCK};
    use std::sync::LazyLock;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(crate::testing::hints::TIMING_WHEEL_NODE_DESTROY, 0x1000)
            .map(|p| p as usize)
    });

    #[test]
    fn destroys_null_or_owned_value_and_unlinks_only_linked_nodes() {
        let _lock = SCHEDULER_TABLE_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("app::timing_wheel_node_destroy"));
            return;
        };
        unsafe {
            let node = base as *mut u32;
            let value = node.add(16);
            let successor = node.add(32);
            let table = scheduler_table();
            for owned in [false, true] {
                for linked in [false, true] {
                    for bucket in 0..TIMING_WHEEL_BUCKETS { *table.add(bucket) = 0; }
                    core::ptr::write_bytes(successor, 0, 8);
                    core::ptr::write_bytes(value, 0, 6);
                    *value.add(5) = 0b1011; // Two references; no deletion dispatch.
                    let slot = if owned { value as usize as u32 } else { 0 };
                    let flags = 0x2a | u32::from(linked);
                    let before = [0xdead_beef, 0x1234_5678, 1, 0,
                        successor as usize as u32, flags, 0xaabb_ccdd, slot, 0xcafe_babe];
                    core::ptr::copy_nonoverlapping(before.as_ptr(), node, before.len());
                    *successor.add(3) = node as usize as u32;
                    if linked { *table = node as usize as u32; }

                    assert_eq!(timing_wheel_node_destroy(node), node);
                    assert_eq!(*node, REFCOUNTED_BASE_VTABLE);
                    assert_eq!(*node.add(5), 0x2a);
                    for index in [1, 2, 3, 4, 6, 7, 8] {
                        assert_eq!(*node.add(index), before[index], "word {index}");
                    }
                    assert_eq!(*value.add(5), if owned { 0b111 } else { 0b1011 });
                    assert_eq!(*table, if linked { successor as usize as u32 } else { 0 });
                    assert_eq!(*successor.add(3), if linked { 0 } else { node as usize as u32 });
                    assert!(core::slice::from_raw_parts(table.add(1), TIMING_WHEEL_BUCKETS - 1)
                        .iter().all(|entry| *entry == 0));
                    *table = 0;
                }
            }
        }
    }
}
