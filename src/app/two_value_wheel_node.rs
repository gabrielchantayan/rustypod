//! `two_value_wheel_node_init` — retailOS `FUN_081977c4` @ `0x081977c4`.
//!
//! ## Extent and call sites, byte-verified
//!
//! The true extent is **152 bytes**: 36 ARM instruction words from
//! `0x081977c4` through `0x08197850`, followed by the vtable and scheduler
//! literal-pool words at `0x08197854` and `0x08197858`. The next real
//! function begins at `0x0819785c` (`cmp r0, #0`). Raw ARM decoding finds
//! **three plain `bl` call sites** and no predicated calls.
//!
//! ## Stock algorithm
//!
//! Constructs a caller-allocated 0x20-byte timing-wheel node over a driver
//! and step value. It initializes the refcounted prefix, installs this
//! class's vtable, clears the two owned value slots, defensively unlinks the
//! fresh node, retains driver then step, releases the cleared old slots if
//! non-null, writes the new pointers, sets rank to one plus the unsigned
//! maximum of their auxiliary words, and inserts the node into the wheel.
//!
//! ## Deliberate deviations
//!
//! Target code reloads the scheduler singleton before insertion; this port
//! reads it once because no intervening callee can change it. Host builds use
//! a private wheel table. The vtable is preserved as an address constant: the
//! decrypted bytes on its stale `0x0898xxxx` page are not the live table.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of_mut;

use crate::app::animation::{timing_wheel_insert, timing_wheel_remove};
#[cfg(target_os = "none")]
use crate::app::animation::SCHEDULER_SINGLETON_GLOBAL;
#[cfg(not(target_os = "none"))]
use crate::app::animation::TIMING_WHEEL_BUCKETS;
use crate::app::fixed_value::{refcounted_base_init, value_aux_max, FixedValue};
use crate::app::refcounted_value::{release_refcounted_value, retain_value};

/// The vtable literal at `0x08197854`; an address constant only.
pub const TWO_VALUE_WHEEL_NODE_VTABLE: u32 = 0x0898_9b48;

/// Target-width layout of the 0x20-byte two-value timing-wheel node.
#[repr(C)]
pub struct TwoValueWheelNode {
    pub vtable: u32,
    /// Not written by this constructor.
    pub opaque_04: u32,
    pub rank: u32,
    pub wheel_prev: u32,
    pub wheel_next: u32,
    pub flags: u32,
    /// Third argument (`step`).
    pub step_value: u32,
    /// Second argument (`driver`).
    pub driver_value: u32,
}

const _: () = assert!(core::mem::size_of::<TwoValueWheelNode>() == 0x20);
const _: () = assert!(core::mem::offset_of!(TwoValueWheelNode, rank) == 0x08);
const _: () = assert!(core::mem::offset_of!(TwoValueWheelNode, flags) == 0x14);
const _: () = assert!(core::mem::offset_of!(TwoValueWheelNode, step_value) == 0x18);
const _: () = assert!(core::mem::offset_of!(TwoValueWheelNode, driver_value) == 0x1c);

#[cfg(target_os = "none")]
#[inline(always)]
fn scheduler_table() -> *mut u32 {
    unsafe { core::ptr::read_volatile(SCHEDULER_SINGLETON_GLOBAL as *const u32) as *mut u32 }
}

#[cfg(not(target_os = "none"))]
static mut HOST_TWO_VALUE_WHEEL_NODE_BUCKETS: [u32; TIMING_WHEEL_BUCKETS] = [0; TIMING_WHEEL_BUCKETS];

#[cfg(not(target_os = "none"))]
#[inline(always)]
fn scheduler_table() -> *mut u32 {
    addr_of_mut!(HOST_TWO_VALUE_WHEEL_NODE_BUCKETS).cast()
}

/// `two_value_wheel_node_init` — retailOS `FUN_081977c4` @ `0x081977c4`
/// (152 bytes including its two-word pool; three plain `bl` call sites).
///
/// Initializes caller-owned storage as a two-value timing-wheel node and
/// returns that storage. The driver is stored at +0x1c, the step at +0x18;
/// rank is `max(driver.aux, step.aux).wrapping_add(1)`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn two_value_wheel_node_init(
    this: *mut TwoValueWheelNode,
    driver: *mut FixedValue,
    step: *mut FixedValue,
) -> *mut TwoValueWheelNode {
    let table = scheduler_table();
    refcounted_base_init(this.cast::<FixedValue>());
    (*this).vtable = TWO_VALUE_WHEEL_NODE_VTABLE;
    (*this).step_value = 0;
    (*this).driver_value = 0;
    timing_wheel_remove(table, this.cast());

    retain_value(driver.cast());
    retain_value(step.cast());

    let old_driver = (*this).driver_value;
    if old_driver != 0 {
        release_refcounted_value(old_driver as usize as *mut u8);
    }
    let old_step = (*this).step_value;
    if old_step != 0 {
        release_refcounted_value(old_step as usize as *mut u8);
    }

    (*this).driver_value = driver as usize as u32;
    (*this).step_value = step as usize as u32;
    (*this).rank = value_aux_max(step, driver).wrapping_add(1);
    timing_wheel_insert(table, this.cast());
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{note_missing_u32_fixture, try_map_u32_slab, SCHEDULER_TABLE_TEST_LOCK};
    use std::sync::{LazyLock, MutexGuard};

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(crate::testing::hints::TWO_VALUE_WHEEL_NODE, 0x1000).map(|p| p as usize)
    });

    fn take_lock() -> MutexGuard<'static, ()> {
        SCHEDULER_TABLE_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    unsafe fn scalar(at: *mut FixedValue, aux: u32) {
        core::ptr::write(at, FixedValue {
            vtable: crate::app::fixed_value::FIXED_VALUE_VTABLE,
            value_q16: 0,
            aux,
            opaque: [0, 0],
            flags: 0b110,
        });
    }

    unsafe fn clear_table(table: *mut u32) {
        for bucket in 0..TIMING_WHEEL_BUCKETS {
            table.add(bucket).write(0);
        }
    }

    #[test]
    fn initializes_target_layout_and_retains_both_values() {
        let _lock = take_lock();
        let Some(base) = *FIXTURE else {
            note_missing_u32_fixture("app::two_value_wheel_node");
            return;
        };
        unsafe {
            let base = base as *mut u8;
            let node = base.cast::<TwoValueWheelNode>();
            let driver = base.add(0x20).cast::<FixedValue>();
            let step = base.add(0x38).cast::<FixedValue>();
            clear_table(scheduler_table());
            core::ptr::write(node, TwoValueWheelNode {
                vtable: 0xdead_beef, opaque_04: 0x1111_1111, rank: 9,
                wheel_prev: 7, wheel_next: 8, flags: 0xffff_fffe,
                step_value: 1, driver_value: 2,
            });
            scalar(driver, 3);
            scalar(step, 5);

            assert_eq!(two_value_wheel_node_init(node, driver, step), node);
            assert_eq!((*node).vtable, TWO_VALUE_WHEEL_NODE_VTABLE);
            assert_eq!((*node).opaque_04, 0x1111_1111);
            assert_eq!((*node).step_value, step as usize as u32);
            assert_eq!((*node).driver_value, driver as usize as u32);
            assert_eq!((*node).rank, 6);
            assert_eq!([(*driver).flags, (*step).flags], [0b1010; 2]);
            assert_eq!(*scheduler_table().add(5), node as usize as u32);
        }
    }

    #[test]
    fn wrapping_rank_does_not_touch_dirty_wheel_links() {
        let _lock = take_lock();
        let Some(base) = *FIXTURE else {
            note_missing_u32_fixture("app::two_value_wheel_node");
            return;
        };
        unsafe {
            let base = base as *mut u8;
            let node = base.cast::<TwoValueWheelNode>();
            let driver = base.add(0x20).cast::<FixedValue>();
            let step = base.add(0x38).cast::<FixedValue>();
            clear_table(scheduler_table());
            core::ptr::write(node, TwoValueWheelNode {
                vtable: 0, opaque_04: 0, rank: 0, wheel_prev: 0x2222_2222,
                wheel_next: 0x3333_3333, flags: 0, step_value: 0, driver_value: 0,
            });
            scalar(driver, u32::MAX);
            scalar(step, 0);

            two_value_wheel_node_init(node, driver, step);
            assert_eq!((*node).rank, 0);
            assert_eq!((*node).wheel_prev, 0x2222_2222);
            assert_eq!((*node).wheel_next, 0x3333_3333);
            assert_eq!((*node).flags, 0);
        }
    }
}
