//! Rebind the two retained values of a timing-wheel node.

use crate::app::animation::{scheduler_table, timing_wheel_insert, timing_wheel_remove};
use crate::app::fixed_value::{value_aux_max, FixedValue};
use crate::app::refcounted_value::{release_refcounted_value, retain_value};

/// retailOS `FUN_081976ec` @ 0x081976ec: 120 bytes, including the
/// scheduler-global literal at 0x08197760; next function is 0x08197764.
/// Raw words verify four unconditional BLs and two BLNEs in the body,
/// followed by a tail B to timing_wheel_insert. Two inbound BLs, both
/// unconditional, occur at 0x08152788 and 0x08152eb4; no predicated callers.
///
/// Unlink the node, retain driver then step before releasing its old driver
/// (+0x1c) and step (+0x18), replace both slots, set rank to the wrapping
/// unsigned maximum aux plus one, reload the scheduler and relink. The
/// shared node layout uses target-width word indices on every platform.
/// No deliberate target deviations; scheduler_table uses its existing host
/// model. This is the same algorithm as timer_step_value_set_values; LLVM
/// may fold their identical bodies.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn two_value_wheel_node_set_values(
    node: *mut u32,
    driver: *mut FixedValue,
    step: *mut FixedValue,
) {
    timing_wheel_remove(scheduler_table(), node);
    retain_value(driver.cast());
    retain_value(step.cast());
    let old_driver = *node.add(7);
    if old_driver != 0 {
        release_refcounted_value(old_driver as usize as *mut u8);
    }
    let old_step = *node.add(6);
    if old_step != 0 {
        release_refcounted_value(old_step as usize as *mut u8);
    }
    *node.add(7) = driver as usize as u32;
    *node.add(6) = step as usize as u32;
    *node.add(2) = value_aux_max(step, driver).wrapping_add(1);
    timing_wheel_insert(scheduler_table(), node);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{try_map_u32_slab, SCHEDULER_TABLE_TEST_LOCK};

    #[test]
    fn rebinding_preserves_alias_counts_and_moves_between_buckets() {
        let _lock = SCHEDULER_TABLE_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let base = try_map_u32_slab(crate::testing::hints::TWO_VALUE_WHEEL_NODE_SET_VALUES, 0x1000)
            .expect("target-width fixture") as *mut u32;
        unsafe {
            let node = base;
            let peer = base.add(16);
            let driver = base.add(32);
            let step = base.add(48);
            let old = base.add(64);
            let table = scheduler_table();
            for &(driver_aux, step_aux, rank, linked) in &[
                (2, 5, 6, true), (7, 3, 8, true),
                (0x8000_0000, 0, 0x8000_0001, false),
                (u32::MAX, 1, 0, false),
            ] {
                for i in 0..12 { *table.add(i) = 0; }
                for i in 0..80 { *base.add(i) = 0; }
                *node = 0x12345678;
                *node.add(1) = 0xabcdef01;
                *node.add(2) = 1;
                *node.add(4) = peer as usize as u32;
                *node.add(5) = 0x43;
                *node.add(6) = old as usize as u32;
                *node.add(7) = driver as usize as u32;
                *peer.add(3) = node as usize as u32;
                *table = node as usize as u32;
                *driver.add(2) = driver_aux;
                *driver.add(5) = 6; // One live reference, aliased old/new driver.
                *step.add(2) = step_aux;
                *step.add(5) = 6;
                *old.add(5) = 10; // Two references: release must not destroy it.
                if linked { *table.add((rank - 1) as usize) = peer as usize as u32; }
                two_value_wheel_node_set_values(node, driver.cast(), step.cast());
                assert_eq!(*node, 0x12345678);
                assert_eq!(*node.add(1), 0xabcdef01);
                assert_eq!(*node.add(2), rank);
                assert_eq!(*node.add(6), step as usize as u32);
                assert_eq!(*node.add(7), driver as usize as u32);
                assert_eq!(*driver.add(5), 6); // Retain before release, no destruction.
                assert_eq!(*step.add(5), 10);
                assert_eq!(*old.add(5), 6);
                assert_eq!(*table, peer as usize as u32);
                assert_eq!(*node.add(5), if linked { 0x43 } else { 0x42 });
                if linked {
                    assert_eq!(*table.add((rank - 1) as usize), node as usize as u32);
                    assert_eq!(*node.add(3), 0);
                    assert_eq!(*node.add(4), peer as usize as u32);
                    assert_eq!(*peer.add(3), node as usize as u32);
                } else {
                    assert_eq!(*peer.add(3), 0);
                }
            }
            // Unlinked node and empty old slots; both new slots alias one value.
            for i in 0..12 { *table.add(i) = 0; }
            for i in 0..8 { *node.add(i) = 0; }
            *driver.add(2) = 0;
            *driver.add(5) = 6;
            two_value_wheel_node_set_values(node, driver.cast(), driver.cast());
            assert_eq!(*driver.add(5), 14);
            assert_eq!(*node.add(2), 1);
            assert_eq!(*node.add(5), 1);
            assert_eq!(*table, node as usize as u32);
            assert_eq!(*node.add(3), 0);
            assert_eq!(*node.add(4), 0);
            for i in 0..12 { *table.add(i) = 0; }
        }
    }
}
