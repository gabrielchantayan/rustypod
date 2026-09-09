//! `timed_transition_init` — original: `FUN_081607b0` @ 0x081607b0.
//!
//! The 0x34-byte wheel node behind the constructor wrapper at 0x0816082c.
//! Raw extent is 120 bytes: 0x081607b0..0x08160824 of code, plus the trailing
//! scheduler-global literal at 0x08160828; the next real function begins at
//! 0x0816082c. Twenty-one `bl` call sites were verified by scanning every ARM
//! branch word in `osos.dec`; all 21 are unconditional `bl`.
//!
//! ## Algorithm
//!
//! Unlink the node from the global timing wheel, clear byte `+0x2c`, force the
//! rank to 1, store the raw inputs at `+0x18/+0x1c/+0x20/+0x24`, compute
//! `fixed16_recip_unguarded(duration_ms * 65)` into `+0x30`, store either the
//! explicit owner or `this` at `+0x28`, then reinsert the node.
//!
//! ## Deviations
//!
//! - Timing-wheel remove `0x082738e0` is now the direct
//!   [`crate::app::animation::timing_wheel_remove`] port. Insertion
//!   `0x08273898` remains a host seam; target builds transmute its ROM address.
//! - The reciprocal is routed through the already-ported
//!   [`crate::util::fixed::fixed16_recip_unguarded`]; no extra seam is needed.

use core::ptr::addr_of;
#[cfg(not(target_os = "none"))]
use core::ptr::addr_of_mut;

use crate::app::animation::timing_wheel_remove;
#[cfg(target_os = "none")]
use crate::app::animation::{SCHEDULER_SINGLETON_GLOBAL, WHEEL_INSERT_ADDRESS};
#[cfg(not(target_os = "none"))]
use crate::app::animation::TIMING_WHEEL_BUCKETS;
use crate::app::fixed_value::refcounted_base_init;
use crate::util::fixed::fixed16_recip_unguarded;

/// The derived timed-transition vtable installed by
/// [`timed_transition_construct`] (original literal @ 0x0816086c).
pub const TIMED_TRANSITION_VTABLE: u32 = 0x0898_7d60;

/// The 0x34-byte wheel node initialized by `timed_transition_init`.
#[repr(C)]
pub struct TimedTransition {
    /// +0x00: class vtable, planted by the 0x0816082c wrapper.
    pub vtable: u32,
    /// +0x04: untouched by this initializer.
    pub opaque_04: u32,
    /// +0x08: wheel rank. The initializer forces it to 1.
    pub wheel_rank: u32,
    /// +0x0c: wheel back-link, managed by the timing-wheel helpers.
    pub wheel_prev: u32,
    /// +0x10: wheel forward-link, managed by the timing-wheel helpers.
    pub wheel_next: u32,
    /// +0x14: base flags word; the wheel helpers consult bit 0.
    pub flags: u32,
    /// +0x18: start value.
    pub start_value: u32,
    /// +0x1c: target value.
    pub target_value: u32,
    /// +0x20: duration in milliseconds.
    pub duration_ms: u32,
    /// +0x24: extra word supplied by the caller.
    pub aux_value: u32,
    /// +0x28: explicit owner pointer, or `this` when the caller passes 0.
    pub owner_or_self: u32,
    /// +0x2c: armed byte, cleared by the initializer.
    pub armed: u8,
    /// +0x2d..+0x2f: padding.
    _pad_2d: [u8; 3],
    /// +0x30: Q16.16 reciprocal of `duration_ms * 65`.
    pub inverse_duration_q16: u32,
}

const _: () = assert!(core::mem::size_of::<TimedTransition>() == 0x34);
const _: () = assert!(core::mem::offset_of!(TimedTransition, opaque_04) == 0x04);
const _: () = assert!(core::mem::offset_of!(TimedTransition, wheel_rank) == 0x08);
const _: () = assert!(core::mem::offset_of!(TimedTransition, wheel_prev) == 0x0c);
const _: () = assert!(core::mem::offset_of!(TimedTransition, wheel_next) == 0x10);
const _: () = assert!(core::mem::offset_of!(TimedTransition, flags) == 0x14);
const _: () = assert!(core::mem::offset_of!(TimedTransition, start_value) == 0x18);
const _: () = assert!(core::mem::offset_of!(TimedTransition, target_value) == 0x1c);
const _: () = assert!(core::mem::offset_of!(TimedTransition, duration_ms) == 0x20);
const _: () = assert!(core::mem::offset_of!(TimedTransition, aux_value) == 0x24);
const _: () = assert!(core::mem::offset_of!(TimedTransition, owner_or_self) == 0x28);
const _: () = assert!(core::mem::offset_of!(TimedTransition, armed) == 0x2c);
const _: () = assert!(core::mem::offset_of!(TimedTransition, inverse_duration_q16) == 0x30);

/// Wheel insertion helper for the timed-transition node.
#[derive(Clone, Copy)]
pub struct TimedTransitionWheelOps {
    /// Timing-wheel insert `0x08273898` `(table, node)`.
    pub wheel_insert: unsafe extern "C" fn(table: *mut u8, node: *mut TimedTransition),
}


#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_wheel_insert(table: *mut u8, node: *mut TimedTransition) {
    let f: unsafe extern "C" fn(*mut u8, *mut TimedTransition) =
        core::mem::transmute(WHEEL_INSERT_ADDRESS);
    f(table, node)
}


#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_wheel_insert(_table: *mut u8, _node: *mut TimedTransition) {}

/// Wired default: ROM insertion address on target, inert stub on host.
pub const DEFAULT_TIMED_TRANSITION_WHEEL_OPS: TimedTransitionWheelOps =
    TimedTransitionWheelOps {
        wheel_insert: firmware_wheel_insert,
    };

/// The active wheel callee set, read through `read_volatile` so LLVM cannot
/// fold the default in and delete the dispatch.
pub static mut TIMED_TRANSITION_WHEEL_OPS: TimedTransitionWheelOps =
    DEFAULT_TIMED_TRANSITION_WHEEL_OPS;

#[inline(always)]
fn timed_transition_ops() -> TimedTransitionWheelOps {
    unsafe { core::ptr::read_volatile(addr_of!(TIMED_TRANSITION_WHEEL_OPS)) }
}

#[cfg(target_os = "none")]
#[inline(always)]
fn scheduler_table() -> *mut u8 {
    unsafe { core::ptr::read_volatile(SCHEDULER_SINGLETON_GLOBAL as *const u32) as *mut u8 }
}

#[cfg(not(target_os = "none"))]
static mut HOST_TIMED_TRANSITION_WHEEL_BUCKETS: [u32; TIMING_WHEEL_BUCKETS] =
    [0; TIMING_WHEEL_BUCKETS];

#[cfg(not(target_os = "none"))]
#[inline(always)]
fn scheduler_table() -> *mut u8 {
    unsafe { addr_of_mut!(HOST_TIMED_TRANSITION_WHEEL_BUCKETS).cast::<u8>() }
}

/// timed_transition_init — original: `FUN_081607b0` @ 0x081607b0 (120 bytes;
/// 21 unconditional `bl` call sites).
///
/// Arms the wheel node in caller-allocated 0x34-byte storage and returns the
/// same pointer. The caller supplies the target value, duration, start value,
/// an auxiliary word, and an optional owner pointer. A NULL owner stores `this`
/// at +0x28, matching the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn timed_transition_init(
    this: *mut TimedTransition,
    target_value: u32,
    duration_ms: u32,
    start_value: u32,
    aux_value: u32,
    owner_or_self: u32,
) -> *mut TimedTransition {
    let ops = timed_transition_ops();
    let table = scheduler_table();

    timing_wheel_remove(table.cast(), this.cast());
    (*this).armed = 0;
    (*this).wheel_rank = 1;
    (*this).duration_ms = duration_ms;
    (*this).target_value = target_value;
    (*this).start_value = start_value;
    (*this).inverse_duration_q16 =
        fixed16_recip_unguarded(duration_ms.wrapping_mul(65) as i32) as u32;
    (*this).aux_value = aux_value;
    (*this).owner_or_self = if owner_or_self == 0 {
        this as usize as u32
    } else {
        owner_or_self
    };
    (ops.wheel_insert)(table, this);
    this
}

/// `timed_transition_construct` — original: `FUN_0816082c` @ 0x0816082c
/// (64 bytes: 60 instruction bytes plus the vtable literal @ 0x0816086c;
/// 19 unconditional `bl` call sites verified by decoding every B/BL word in
/// `osos.dec`).
///
/// Constructs a refcounted timed-transition object in the caller's 0x34-byte
/// storage: initialize its shared base, install the derived vtable, then arm
/// its timing-wheel state with the five supplied transition values. Returns
/// `this`.
///
/// Deliberate deviations: this composes the independently ported
/// [`refcounted_base_init`] and [`timed_transition_init`]. The timing-wheel
/// seam and its host behavior therefore remain those documented by
/// `timed_transition_init`.
///
/// # Safety
///
/// `this` must identify live, 4-byte-aligned, writable storage for a
/// [`TimedTransition`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn timed_transition_construct(
    this: *mut TimedTransition,
    target_value: u32,
    duration_ms: u32,
    start_value: u32,
    aux_value: u32,
    owner_or_self: u32,
) -> *mut TimedTransition {
    refcounted_base_init(this.cast());
    (*this).vtable = TIMED_TRANSITION_VTABLE;
    timed_transition_init(
        this,
        target_value,
        duration_ms,
        start_value,
        aux_value,
        owner_or_self,
    )
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};
    use std::vec;
    use std::vec::Vec;

    const SLAB_LEN: usize = 0x1000;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        Insert { table: usize, node: usize },
    }

    static EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::TIMED_TRANSITION, SLAB_LEN).map(|pointer| pointer as usize)
    });

    #[derive(Clone, Copy)]
    struct Fixture {
        transition: *mut TimedTransition,
    }

    fn fixture() -> Option<Fixture> {
        let base = (*SLAB)? as *mut u8;
        Some(Fixture {
            transition: base.cast::<TimedTransition>(),
        })
    }

    fn record(event: Event) {
        EVENTS
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(event);
    }

    fn events() -> Vec<Event> {
        EVENTS
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }


    unsafe extern "C" fn recording_wheel_insert(table: *mut u8, node: *mut TimedTransition) {
        record(Event::Insert {
            table: table as usize,
            node: node as usize,
        });
    }

    struct OpsRestore(TimedTransitionWheelOps);

    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe {
                TIMED_TRANSITION_WHEEL_OPS = self.0;
            }
        }
    }

    fn install_ops(ops: TimedTransitionWheelOps) -> OpsRestore {
        let previous = unsafe { TIMED_TRANSITION_WHEEL_OPS };
        unsafe {
            TIMED_TRANSITION_WHEEL_OPS = ops;
        }
        OpsRestore(previous)
    }

    fn map_or_skip() -> Option<Fixture> {
        let fixture = fixture();
        if fixture.is_none() {
            assert!(note_missing_u32_fixture("timed_transition_init"));
        }
        fixture
    }

    #[test]
    fn init_writes_fields_and_falls_back_to_self_owner() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let fixture = match map_or_skip() {
            Some(fixture) => fixture,
            None => return,
        };

        unsafe {
            core::ptr::write_bytes(
                fixture.transition.cast::<u8>(),
                0xa5,
                core::mem::size_of::<TimedTransition>(),
            );
            (*fixture.transition).flags = 0xa5a5_a5a4;
        }
        EVENTS
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clear();

        let _ops = install_ops(TimedTransitionWheelOps {
            wheel_insert: recording_wheel_insert,
        });

        let target_value = 0x1111_2222;
        let duration_ms = 1000;
        let start_value = 0x3333_4444;
        let aux_value = 0x5555_6666;

        let returned = unsafe {
            timed_transition_init(
                fixture.transition,
                target_value,
                duration_ms,
                start_value,
                aux_value,
                0,
            )
        };

        assert_eq!(returned, fixture.transition);
        assert_eq!(events(), {
            let table = scheduler_table() as usize;
            vec![Event::Insert {
                table,
                node: fixture.transition as usize,
            }]
        });

        let transition = unsafe { &*fixture.transition };
        assert_eq!(transition.wheel_rank, 1);
        assert_eq!(transition.armed, 0);
        assert_eq!(transition.start_value, start_value);
        assert_eq!(transition.target_value, target_value);
        assert_eq!(transition.duration_ms, duration_ms);
        assert_eq!(transition.aux_value, aux_value);
        assert_eq!(transition.owner_or_self, fixture.transition as usize as u32);
        assert_eq!(
            transition.inverse_duration_q16,
            fixed16_recip_unguarded(duration_ms.wrapping_mul(65) as i32) as u32,
        );
        assert_eq!(transition.vtable, 0xa5a5_a5a5);
        assert_eq!(transition.opaque_04, 0xa5a5_a5a5);
        assert_eq!(transition.wheel_prev, 0xa5a5_a5a5);
        assert_eq!(transition.wheel_next, 0xa5a5_a5a5);
        assert_eq!(transition.flags, 0xa5a5_a5a4);
    }

    #[test]
    fn init_uses_the_explicit_owner_when_present() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let fixture = match map_or_skip() {
            Some(fixture) => fixture,
            None => return,
        };

        unsafe {
            core::ptr::write_bytes(
                fixture.transition.cast::<u8>(),
                0x5c,
                core::mem::size_of::<TimedTransition>(),
            );
        }
        EVENTS
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clear();

        let _ops = install_ops(TimedTransitionWheelOps {
            wheel_insert: recording_wheel_insert,
        });

        let owner = 0x1234_5678;
        unsafe {
            timed_transition_init(fixture.transition, 0x0102_0304, 500, 0x0506_0708, 0x090a_0b0c, owner)
        };

        let transition = unsafe { &*fixture.transition };
        assert_eq!(transition.owner_or_self, owner);
        assert_eq!(transition.wheel_rank, 1);
        assert_eq!(transition.armed, 0);
        assert_eq!(events().len(), 1);
        assert_eq!(events()[0], Event::Insert {
            table: scheduler_table() as usize,
            node: fixture.transition as usize,
        });
    }

    #[test]
    fn construct_initializes_base_vtable_and_transition() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let fixture = match map_or_skip() {
            Some(fixture) => fixture,
            None => return,
        };

        unsafe {
            core::ptr::write_bytes(
                fixture.transition.cast::<u8>(),
                0xff,
                core::mem::size_of::<TimedTransition>(),
            );
        }
        EVENTS
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clear();
        let _ops = install_ops(TimedTransitionWheelOps {
            wheel_insert: recording_wheel_insert,
        });

        let returned = unsafe {
            timed_transition_construct(
                fixture.transition,
                0x1122_3344,
                1,
                0x5566_7788,
                0x99aa_bbcc,
                0xdead_beef,
            )
        };

        assert_eq!(returned, fixture.transition);
        let transition = unsafe { &*fixture.transition };
        assert_eq!(transition.vtable, TIMED_TRANSITION_VTABLE);
        assert_eq!(transition.flags, 0);
        assert_eq!(transition.opaque_04, u32::MAX);
        assert_eq!(transition.wheel_rank, 1);
        assert_eq!(transition.armed, 0);
        assert_eq!(transition.start_value, 0x5566_7788);
        assert_eq!(transition.target_value, 0x1122_3344);
        assert_eq!(transition.duration_ms, 1);
        assert_eq!(transition.aux_value, 0x99aa_bbcc);
        assert_eq!(transition.owner_or_self, 0xdead_beef);
        assert_eq!(
            transition.inverse_duration_q16,
            fixed16_recip_unguarded(65) as u32,
        );
        assert_eq!(
            events(),
            vec![Event::Insert {
                table: scheduler_table() as usize,
                node: fixture.transition as usize,
            }]
        );
    }
}
