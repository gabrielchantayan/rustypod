//! `timer_step_value_init` — original: `FUN_08167a6c` @ 0x08167a6c.
//!
//! The constructor of retailOS's two-value wheel node: a refcounted
//! object that retains a **driver** value (every observed caller passes
//! a timer-like object — usually the view's TimedTransition at +0x11c,
//! the same pointer handed to `timed_transition_init`, or the 0x34-byte
//! periodic timer built at 0x08224a9c) plus a **step** scalar (a fresh
//! `fixed_value_init(x << 16)`, typically 1.0), enqueues itself in the
//! firmware timing wheel, and is then used as the animated `current`
//! value of a subsequent `animation_init`. Callers build it as
//! `timer_step_value_init(operator_new(0x20) @ 0x082aadd4, driver, step)`,
//! so — like [`crate::app::fixed_value::fixed_value_init`] — it runs in
//! caller-allocated storage and returns `this`.
//!
//! ## Extent and call sites, byte-verified
//!
//! Ghidra's "144 bytes" covers only the instruction words: 0x08167a6c..
//! 0x08167afc (`pop {r4-r8, pc}`). The trailing literal pool holds TWO
//! words — the class vtable 0x0898806c at 0x08167afc and the scheduler
//! singleton pointer word 0x089cc7e0 at 0x08167b00 — for a true extent
//! of **152 bytes**; the next real function opens `cmp r0, #0` at
//! 0x08167b04 (the class's deleting destructor, which shares the same
//! vtable literal).
//!
//! **14 `bl` call sites**, verified by decoding every B/BL word in
//! osos.dec: 0x08156b68, 0x08156c44, 0x08156d48, 0x08156df8,
//! 0x08199da8, 0x08199e04, 0x08199efc, 0x08199fa4, 0x0819a0fc,
//! 0x0819a168, 0x0819a26c, 0x0819a330, 0x08224b08, 0x08224b38 — all
//! plain unconditional `bl`, no predicated forms, no B tail branches,
//! and no DATA word references the address. Callers invoke the
//! constructor directly on fresh `operator_new(0x20)` storage with no
//! NULL guard.
//!
//! ## Stock algorithm
//!
//! ```text
//! 08167a6c  push {r4-r8, lr}
//! 08167a70  mov r7, r2 / mov r6, r1          ; step, driver
//! 08167a78  bl  0x08138460        ; refcounted base ctor (ported)
//! 08167a80  ldr r0, =0x0898806c   ; class vtable (pool 0x08167afc)
//!           str r0, [r4]          ; overrides the base vtable
//! 08167a8c  mov r0, #0 ; str +0x18 / +0x1c   ; clear both value slots
//! 08167a98  ldr r0, [r5]          ; r5 -> global 0x089cc7e0: scheduler ptr
//!           bl  0x082738e0        ; timing_wheel_remove(table, this)
//! 08167aa4  mov r0, r6/r7         ; retain(driver), retain(step)
//!           bl  0x08273a14
//! 08167ab4  ldr/cmp [+0x1c], blne 0x082739e0 ; release old driver slot
//! 08167ac0  ldr/cmp [+0x18], blne 0x082739e0 ; release old step slot
//! 08167acc  str r6, [r4, #0x1c]   ; driver -> +0x1c
//! 08167ad8  str r7, [r4, #0x18]   ; step   -> +0x18
//! 08167adc  bl  0x08273a40        ; value_aux_max(step, driver)
//! 08167ae0  add r0, #1 ; str [r4, #8]        ; rank = max(aux) + 1
//! 08167ae8  ldr r0, [r5] ; bl 0x08273898     ; timing_wheel_insert
//! 08167af4  mov r0, r4 ; pop {r4-r8, pc}     ; return this
//! ```
//!
//! The two conditional releases read slots step three just zeroed, so
//! they are statically dead — the ADS memberwise-assign idiom (release
//! the old value before overwriting), kept for structure parity exactly
//! as in [`crate::app::animation::animation_init`]. The rank key at
//! +0x08 is one past the unsigned maximum of the two arguments' +0x08
//! aux words (the `value_aux_max` leaf, ported in
//! [`crate::app::fixed_value`]): plain scalars carry aux 0, so a node
//! over plain scalars lands at rank 1 = timing-wheel bucket 0.
//!
//! The class is one of a family of byte-identical two-value
//! constructors that differ only in their vtable literal — 0x081977c4
//! (vtable 0x08989b48) is word-for-word the same body, and 0x081679d8 /
//! 0x8181060 / 0x8197744 call the same aux-max leaf. Its sibling
//! destructor pair sits immediately after this body: 0x08167b1c
//! releases +0x1c then +0x18 and tail-branches to
//! `refcounted_base_destroy`; 0x08167b04 is the deleting-dtor wrapper
//! (`operator delete` @ 0x082aad24).
//!
//! ## Deviations
//!
//! - Timing-wheel remove 0x082738e0 is the direct
//!   [`crate::app::animation::timing_wheel_remove`] port. Wheel insert
//!   0x08273898 remains unported and dispatches through
//!   [`TIMER_STEP_VALUE_OPS`] (the per-class seam pattern of
//!   `app/timed_transition.rs`): target builds transmute ROM address
//!   0x08273898; the host default is inert and tests install a
//!   recording model.
//! - Retain 0x08273a14, release 0x082739e0 and the aux-max leaf
//!   0x08273a40 are direct ports
//!   ([`crate::app::refcounted_value`], [`value_aux_max`]).
//! - The scheduler pointer is loaded once through the live global word
//!   0x089cc7e0 on target where the stock body loads it twice (before
//!   remove and before insert); nothing between the two stock loads can
//!   change it. Host builds hand the seam a house-static 12-bucket
//!   table modelled on the lazy allocator @ 0x082739a0.
//! - [`TIMER_STEP_VALUE_VTABLE`] is an address constant only: it lives
//!   on the stale 0x0898xxxx page (the `app/registry.rs` caveat — its
//!   bytes there are RTTI strings, not code), so the port reproduces
//!   the stored pointer value, never the table's contents.

use core::ptr::addr_of;
#[cfg(not(target_os = "none"))]
use core::ptr::addr_of_mut;

use crate::app::animation::timing_wheel_remove;
#[cfg(target_os = "none")]
use crate::app::animation::{SCHEDULER_SINGLETON_GLOBAL, WHEEL_INSERT_ADDRESS};
#[cfg(not(target_os = "none"))]
use crate::app::animation::TIMING_WHEEL_BUCKETS;
use crate::app::fixed_value::{refcounted_base_init, value_aux_max, FixedValue};
use crate::app::refcounted_value::{release_refcounted_value, retain_value};

/// Firmware load address of the class vtable literal (pool word at
/// 0x08167afc). Address constant only — see the module header's caveat.
pub const TIMER_STEP_VALUE_VTABLE: u32 = 0x0898_806c;

/// The timer step-value object: 0x20 bytes on the 32-bit target (every
/// caller allocates `operator_new(0x20)`). Pointer fields are u32
/// target pointers, hence the width-independent size; the +0x08..+0x14
/// prefix is the shared timing-wheel node layout used by Animation and
/// TimedTransition.
#[repr(C)]
pub struct TimerStepValue {
    /// +0x00: the vtable — [`crate::app::fixed_value::REFCOUNTED_BASE_VTABLE`]
    /// during the base constructor, [`TIMER_STEP_VALUE_VTABLE`] after it.
    pub vtable: u32,
    /// +0x04: not written by any function of this family.
    pub opaque_04: u32,
    /// +0x08: the timing-wheel rank: one past the larger argument aux
    /// word (unsigned). Insert buckets the node at `rank - 1`.
    pub rank: u32,
    /// +0x0c: wheel link, written only by insert/remove (u32 target ptr).
    pub wheel_prev: u32,
    /// +0x10: wheel link, written only by insert/remove (u32 target ptr).
    pub wheel_next: u32,
    /// +0x14: flags (bit 0 linked-in-wheel, bit 1 refcounted) and the
    /// refcount in bits 2..; zeroed by the base constructor.
    pub flags: u32,
    /// +0x18: retained step scalar (u32 target ptr to a FixedValue) —
    /// the third constructor argument (r2).
    pub step_value: u32,
    /// +0x1c: retained driver value — the second constructor argument
    /// (r1); every observed caller passes a timer-like object.
    pub driver_value: u32,
}

const _: () = assert!(core::mem::size_of::<TimerStepValue>() == 0x20);
const _: () = assert!(core::mem::offset_of!(TimerStepValue, opaque_04) == 0x04);
const _: () = assert!(core::mem::offset_of!(TimerStepValue, rank) == 0x08);
const _: () = assert!(core::mem::offset_of!(TimerStepValue, wheel_prev) == 0x0c);
const _: () = assert!(core::mem::offset_of!(TimerStepValue, wheel_next) == 0x10);
const _: () = assert!(core::mem::offset_of!(TimerStepValue, flags) == 0x14);
const _: () = assert!(core::mem::offset_of!(TimerStepValue, step_value) == 0x18);
const _: () = assert!(core::mem::offset_of!(TimerStepValue, driver_value) == 0x1c);

/// Indirect dispatch for the unported wheel insertion callee (see the
/// module header). Host tests install a recording model; a later port
/// replaces its default without touching these callers.
#[derive(Clone, Copy)]
pub struct TimerStepValueOps {
    /// Timing-wheel insert 0x08273898 `(table, node)`: push `node` at
    /// the head of bucket `node->rank - 1` and set the linked flag.
    pub wheel_insert: unsafe extern "C" fn(table: *mut u8, node: *mut TimerStepValue),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_wheel_insert(table: *mut u8, node: *mut TimerStepValue) {
    let f: unsafe extern "C" fn(*mut u8, *mut TimerStepValue) =
        core::mem::transmute(WHEEL_INSERT_ADDRESS);
    f(table, node)
}

/// Host default: inert.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_wheel_insert(_table: *mut u8, _node: *mut TimerStepValue) {}

/// Wired default: the ROM insert address on target and an inert stub on host.
pub const DEFAULT_TIMER_STEP_VALUE_OPS: TimerStepValueOps = TimerStepValueOps {
    wheel_insert: firmware_wheel_insert,
};

/// The active callee set, read through `read_volatile` so LLVM cannot
/// fold the indirect call to the default.
pub static mut TIMER_STEP_VALUE_OPS: TimerStepValueOps = DEFAULT_TIMER_STEP_VALUE_OPS;

#[inline(always)]
fn timer_step_value_ops() -> TimerStepValueOps {
    unsafe { core::ptr::read_volatile(addr_of!(TIMER_STEP_VALUE_OPS)) }
}

/// The first argument both wheel callees receive: the word stored at
/// the scheduler singleton global. On target that is the live singleton
/// pointer (created lazily @ 0x082739a0); host builds model the created
/// state with a house-static bucket array.
#[cfg(target_os = "none")]
#[inline(always)]
fn scheduler_table() -> *mut u8 {
    unsafe { core::ptr::read_volatile(SCHEDULER_SINGLETON_GLOBAL as *const u32) as *mut u8 }
}

#[cfg(not(target_os = "none"))]
static mut HOST_TIMER_STEP_VALUE_WHEEL_BUCKETS: [u32; TIMING_WHEEL_BUCKETS] =
    [0; TIMING_WHEEL_BUCKETS];

#[cfg(not(target_os = "none"))]
#[inline(always)]
fn scheduler_table() -> *mut u8 {
    unsafe { addr_of_mut!(HOST_TIMER_STEP_VALUE_WHEEL_BUCKETS).cast::<u8>() }
}

/// timer_step_value_init — original: `FUN_08167a6c` @ 0x08167a6c (152
/// bytes including the two-word pool; 14 `bl` call sites,
/// binary-verified — see the module header).
///
/// Constructs the two-value wheel node over `(driver, step)` in the
/// caller-allocated 0x20 bytes at `this` and returns `this`: run the
/// refcounted base constructor, install the class vtable, clear both
/// value slots, unlink defensively from the timing wheel, retain
/// `driver` then `step`, replay the (statically dead)
/// release-before-overwrite of each slot — driver (+0x1c) first, then
/// step (+0x18) — store `driver` at +0x1c and `step` at +0x18, then
/// store `rank = value_aux_max(step, driver) + 1` (unsigned, wrapping)
/// and link the object into the wheel.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn timer_step_value_init(
    this: *mut TimerStepValue,
    driver: *mut FixedValue,
    step: *mut FixedValue,
) -> *mut TimerStepValue {
    let ops = timer_step_value_ops();
    let table = scheduler_table();

    // 08167a78: bl 0x08138460 — the shared refcounted base constructor.
    refcounted_base_init(this.cast::<FixedValue>());
    // 08167a80..08167a88: override the base vtable with the derived one.
    (*this).vtable = TIMER_STEP_VALUE_VTABLE;
    // 08167a8c..08167a94: str +0x18, +0x1c.
    (*this).step_value = 0;
    (*this).driver_value = 0;

    // 08167a98..08167aa0: defensive unlink — +0x14 just cleared means
    // the firmware body returns on its first flag test; kept for parity.
    timing_wheel_remove(table.cast(), this.cast());

    // 08167aa4..08167ab0: retain(driver), retain(step).
    retain_value(driver.cast());
    retain_value(step.cast());

    // 08167ab4..08167ac8: memberwise-assign release of each OLD slot,
    // checked driver (+0x1c) first, then step (+0x18). Both loads land
    // on words step three zeroed — dead code the compiler must still be
    // free to keep or drop.
    let old_driver = (*this).driver_value;
    if old_driver != 0 {
        release_refcounted_value(old_driver as usize as *mut u8);
    }
    let old_step = (*this).step_value;
    if old_step != 0 {
        release_refcounted_value(old_step as usize as *mut u8);
    }

    // 08167acc..08167ad8: str r6 -> +0x1c, str r7 -> +0x18.
    (*this).driver_value = driver as usize as u32;
    (*this).step_value = step as usize as u32;

    // 08167ad0..08167ae4: rank = value_aux_max(step, driver) + 1
    // (unsigned compare inside the leaf, wrapping add here).
    (*this).rank = value_aux_max(step, driver).wrapping_add(1);

    // 08167ae8..08167af0: link into the timing wheel at bucket rank-1.
    (ops.wheel_insert)(table, this);
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{note_missing_u32_fixture, try_map_u32_slab, SCHEDULER_TABLE_TEST_LOCK};
    use std::sync::{LazyLock, MutexGuard};

    /// Restores the ops seam even if a test panics mid-run.
    struct SeamGuard;

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(TIMER_STEP_VALUE_OPS)
                    .write_volatile(DEFAULT_TIMER_STEP_VALUE_OPS);
            }
        }
    }

    const EVENT_WHEEL_INSERT: u32 = 4;

    /// One observed seam call: kind, node address, table address, and
    /// the node's rank at call time.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Event {
        kind: u32,
        node: usize,
        table: usize,
        rank_at_insert: u32,
    }

    static mut LOG: [Event; 8] = [Event { kind: 0, node: 0, table: 0, rank_at_insert: 0 }; 8];
    static mut LOG_LEN: usize = 0;

    unsafe fn record(event: Event) {
        let slot = LOG_LEN;
        assert!(slot < LOG.len(), "event log overflow");
        LOG[slot] = event;
        LOG_LEN = slot + 1;
    }

    fn reset_log() {
        unsafe {
            LOG_LEN = 0;
        }
    }

    fn log() -> std::vec::Vec<Event> {
        unsafe {
            let len = LOG_LEN;
            std::vec::Vec::from(core::slice::from_raw_parts(
                core::ptr::addr_of!(LOG).cast::<Event>(),
                len,
            ))
        }
    }

    unsafe extern "C" fn recording_wheel_insert(table: *mut u8, node: *mut TimerStepValue) {
        record(Event {
            kind: EVENT_WHEEL_INSERT,
            node: node as usize,
            table: table as usize,
            rank_at_insert: (*node).rank,
        });
    }

    unsafe fn install_recording_ops() {
        core::ptr::addr_of_mut!(TIMER_STEP_VALUE_OPS).write_volatile(TimerStepValueOps {
            wheel_insert: recording_wheel_insert,
        });
    }

    fn take_lock() -> MutexGuard<'static, ()> {
        SCHEDULER_TABLE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Fixture addresses inside the low-4-GiB slab, so the node's u32
    /// target pointers round-trip exactly.
    #[derive(Clone, Copy)]
    struct Fixture {
        node: *mut TimerStepValue,
        driver: *mut FixedValue,
        step: *mut FixedValue,
        table: *mut u8,
    }

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(crate::testing::hints::TIMER_STEP_VALUE, 0x1000).map(|p| p as usize)
    });

    fn fixture() -> Option<Fixture> {
        let base = (*FIXTURE)? as *mut u8;
        Some(unsafe {
            Fixture {
                node: base.cast::<TimerStepValue>(),
                driver: base.add(0x28).cast::<FixedValue>(),
                step: base.add(0x40).cast::<FixedValue>(),
                table: scheduler_table(),
            }
        })
    }

    /// A scalar with flag bit 1 set ("refcounted") and count 1 — what
    /// `fixed_value_init` output looks like once someone retained it.
    fn counted_scalar(at: *mut FixedValue, aux: u32) -> *mut FixedValue {
        unsafe {
            core::ptr::write(
                at,
                FixedValue {
                    vtable: crate::app::fixed_value::FIXED_VALUE_VTABLE,
                    value_q16: 0,
                    aux,
                    opaque: [0, 0],
                    flags: 0b110, // bit 1 set, count 1 in bits 2..
                },
            );
        }
        at
    }

    /// Dirty storage so every write the constructor performs (and every
    /// field it must NOT touch) is observable. Clear the linked flag:
    /// these caller tests do not construct a real wheel chain.
    fn dirty_node(at: *mut TimerStepValue) {
        unsafe {
            core::ptr::write(
                at,
                TimerStepValue {
                    vtable: 0xdead_beef,
                    opaque_04: 0x1111_1111,
                    rank: 0xcafe_babe,
                    wheel_prev: 0x2222_2222,
                    wheel_next: 0x3333_3333,
                    flags: 0xffff_fffe,
                    step_value: 0x4444_4444,
                    driver_value: 0x5555_5555,
                },
            );
        }
    }

    #[test]
    fn it_returns_the_storage_it_was_given() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::timer_step_value");
            return;
        };
        unsafe {
            install_recording_ops();
            dirty_node(f.node);
            counted_scalar(f.driver, 0);
            counted_scalar(f.step, 0);

            let returned = timer_step_value_init(f.node, f.driver, f.step);
            assert_eq!(returned, f.node);
        }
    }

    #[test]
    fn it_installs_the_derived_vtable_and_the_base_ctor_zeroes_flags() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::timer_step_value");
            return;
        };
        unsafe {
            install_recording_ops();
            dirty_node(f.node);
            counted_scalar(f.driver, 0);
            counted_scalar(f.step, 0);

            timer_step_value_init(f.node, f.driver, f.step);

            let node = &*f.node;
            assert_eq!(node.vtable, TIMER_STEP_VALUE_VTABLE, "0x0898806c, the 0x08167afc pool word");
            assert_eq!(node.flags, 0, "the base ctor zeroes +0x14 and retains touch only the arguments");
        }
    }

    #[test]
    fn value_slots_hold_step_then_driver_in_target_order() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::timer_step_value");
            return;
        };
        unsafe {
            install_recording_ops();
            dirty_node(f.node);
            counted_scalar(f.driver, 0);
            counted_scalar(f.step, 0);

            timer_step_value_init(f.node, f.driver, f.step);

            let node = &*f.node;
            assert_eq!(
                node.step_value, f.step as usize as u32,
                "+0x18 takes the third argument (r2)"
            );
            assert_eq!(
                node.driver_value, f.driver as usize as u32,
                "+0x1c takes the second argument (r1)"
            );
        }
    }

    #[test]
    fn rank_is_one_plus_the_unsigned_max_of_the_two_aux_words() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::timer_step_value");
            return;
        };
        unsafe {
            install_recording_ops();
            // (driver, step) aux tuples: plain scalars, mixed values,
            // ties, high-bit values proving the compares are unsigned,
            // and the wrapping edge 0xffff_ffff + 1 == 0.
            for &(drv, stp) in &[
                (0u32, 0u32),
                (5, 3),
                (3, 5),
                (7, 7),
                (0x8000_0000, 1),
                (1, 0x8000_0000),
                (0xffff_ffff, 0xffff_ffff),
                (0xffff_fffe, 0x8000_0000),
            ] {
                reset_log();
                dirty_node(f.node);
                counted_scalar(f.driver, drv);
                counted_scalar(f.step, stp);

                timer_step_value_init(f.node, f.driver, f.step);

                let expected = drv.max(stp).wrapping_add(1);
                assert_eq!((*f.node).rank, expected, "aux ({drv:#x}, {stp:#x})");
                assert_eq!(
                    log().last().unwrap().rank_at_insert,
                    expected,
                    "the node enters the wheel already carrying its rank"
                );
            }
        }
    }

    #[test]
    fn direct_retain_calls_precede_wheel_insertion() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::timer_step_value");
            return;
        };
        unsafe {
            install_recording_ops();
            reset_log();
            dirty_node(f.node);
            counted_scalar(f.driver, 0xa0_0000);
            counted_scalar(f.step, 0);

            timer_step_value_init(f.node, f.driver, f.step);

            let seen = log();
            assert_eq!(
                seen.iter().map(|event| event.kind).collect::<std::vec::Vec<_>>(),
                std::vec![EVENT_WHEEL_INSERT]
            );
            assert_eq!(seen[0].node, f.node as usize, "insert targets this");
            assert_eq!(
                [(*f.driver).flags, (*f.step).flags],
                [0b1010; 2],
                "the direct retain port receives driver, then step"
            );
            assert_eq!(seen[0].table, f.table as usize, "insert receives the scheduler-table word");
        }
    }

    #[test]
    fn constructor_releases_no_slots_after_clearing_them() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::timer_step_value");
            return;
        };
        unsafe {
            install_recording_ops();
            dirty_node(f.node);
            counted_scalar(f.driver, 0);
            counted_scalar(f.step, 0);

            timer_step_value_init(f.node, f.driver, f.step);

            // The two blne releases read slots the constructor zeroed
            // itself, so release_refcounted_value sees no values to
            // touch: each argument's flags word carries exactly one
            // retain (+4) and nothing more.
            assert_eq!((*f.driver).flags, 0b1010);
            assert_eq!((*f.step).flags, 0b1010);
        }
    }

    #[test]
    fn untouched_fields_keep_their_sentinels() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::timer_step_value");
            return;
        };
        unsafe {
            install_recording_ops();
            dirty_node(f.node);
            counted_scalar(f.driver, 0);
            counted_scalar(f.step, 0);

            timer_step_value_init(f.node, f.driver, f.step);

            let node = &*f.node;
            assert_eq!(node.opaque_04, 0x1111_1111, "+0x04 is not written");
            assert_eq!(node.wheel_prev, 0x2222_2222, "+0x0c belongs to the wheel ops");
            assert_eq!(node.wheel_next, 0x3333_3333, "+0x10 belongs to the wheel ops");
        }
    }

    #[test]
    fn construction_produces_the_exact_final_word_image() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::timer_step_value");
            return;
        };
        unsafe {
            install_recording_ops();
            dirty_node(f.node);
            counted_scalar(f.driver, 0x00a0_0000);
            counted_scalar(f.step, 0x0000_0002);

            timer_step_value_init(f.node, f.driver, f.step);

            let words = core::slice::from_raw_parts(f.node.cast::<u32>(), 8);
            assert_eq!(
                words,
                &[
                    TIMER_STEP_VALUE_VTABLE, // +0x00
                    0x1111_1111,             // +0x04 sentinel survives
                    0x00a0_0001,             // +0x08 rank = max(0xa0_0000, 2) + 1
                    0x2222_2222,             // +0x0c sentinel
                    0x3333_3333,             // +0x10 sentinel
                    0,                       // +0x14 flags/refcount
                    f.step as u32,           // +0x18
                    f.driver as u32,         // +0x1c
                ],
                "all eight words, nothing else touched"
            );
        }
    }

    #[test]
    fn default_host_wheel_seam_is_inert() {
        let _lock = take_lock();
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::timer_step_value");
            return;
        };
        unsafe {
            // No recording ops installed: the host default must simply
            // not fire, while the direct retains still run.
            dirty_node(f.node);
            counted_scalar(f.driver, 0);
            counted_scalar(f.step, 0);

            timer_step_value_init(f.node, f.driver, f.step);

            assert_eq!((*f.node).vtable, TIMER_STEP_VALUE_VTABLE);
            assert_eq!((*f.driver).flags, 0b1010);
            assert_eq!((*f.step).flags, 0b1010);
        }
    }
}
