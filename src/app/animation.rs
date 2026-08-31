//! `animation_init` — original: `FUN_08166b88` @ 0x08166b88.
//!
//! The full constructor of retailOS's UI **animation** object: the class
//! that binds three refcounted Q16.16 scalars (the animated value plus its
//! from/to endpoints) and enqueues itself in the firmware's timing wheel.
//! Every caller builds it as
//! `animation_init(operator_new(0x24) @ 0x082aadd4, current, from, to)`
//! (e.g. 0x08180a54: the from/to pair comes straight from two
//! `fixed_value_init(x << 16)` scalars, `current` is the view's stored
//! property slot), so — like [`crate::app::fixed_value::fixed_value_init`] —
//! this constructor runs in caller-allocated storage and returns `this`.
//!
//! ## Extent and call sites, byte-verified
//!
//! The true extent is **212 bytes**, not Ghidra's 204: fifty instruction
//! words run 0x08166b88..0x08166c50 (`pop {r4-r8, pc}`) and the trailing
//! literal pool holds **two** words — the animation vtable 0x08987f00 at
//! 0x08166c54 and the scheduler singleton pointer 0x089cc7e0 at
//! 0x08166c58. Ghidra's "204 bytes" drops that last pool word; the next
//! real function starts at 0x08166c5c (the sibling default constructor,
//! which installs the same vtable but never touches the wheel). The
//! preceding function ends at 0x08166b84: a slot setter for +0x20 whose
//! tail branch into the wheel insert confirmed the callee identities
//! below.
//!
//! **44 `bl` call sites**, verified by decoding every B/BL word in
//! osos.dec: all 44 are plain unconditional `bl` (no predicated forms, no
//! B tail branches), and no DATA word anywhere references the address —
//! callers invoke the constructor directly by name with no NULL guard,
//! always on fresh `operator_new(0x24)` storage.
//!
//! ## Stock algorithm
//!
//! ```text
//! 08166b88  push {r4-r8, lr}
//! 08166b8c  mov r8, r1 / mov r7, r3 / mov r6, r2   ; current, to, from
//! 08166b98  bl  0x08138460        ; refcounted base ctor (ported)
//! 08166ba0  ldr r0, =0x08987f00   ; animation vtable (pool 0x08166c54)
//!           str r0, [r4]          ; overrides the base vtable
//! 08166bac  mov r0, #0 ; str +0x18 / +0x1c / +0x20     ; clear endpoints
//! 08166bc4  ldr r0, [r5]          ; r5 -> global 0x089cc7e0: scheduler ptr
//!           bl  0x082738e0        ; timing_wheel_remove(table, this)
//! 08166bcc  mov r0, r8/r6/r7      ; retain(current), retain(from),
//!           bl  0x08273a14        ; retain(to)
//! 08166be0  ldr/cmp [+0x20], blne 0x082739e0   ; release old current
//! 08166bec  ldr/cmp [+0x18], blne 0x082739e0   ; release old from
//! 08166bf8  ldr/cmp [+0x1c], blne 0x082739e0   ; release old to
//! 08166c04  add r0, r4, #0x18 ; stm r0, {r6, r7, r8}   ; from, to, current
//! 08166c0c  ldr r0, [r6+8] ; ldr r1, [r7+8] ; ldr r3, [r8+8]
//!           ...                   ; unsigned max of the three aux words
//! 08166c38  add r0, #1 ; str [r4+8]     ; rank = max(...) + 1
//! 08166c40  ldr r0, [r5] ; bl 0x08273898  ; timing_wheel_insert(table,this)
//! 08166c4c  mov r0, r4 ; pop {r4-r8, pc}  ; return this
//! ```
//!
//! The three conditional releases read slots that step four just zeroed,
//! so they are statically dead; they are the ADS memberwise-assign idiom
//! (release old value before overwrite) kept here for structure parity —
//! see the test that pins them dead. The rank key at +0x08 reuses the
//! FixedValue aux word convention ([`crate::app::fixed_value`]): a plain
//! scalar leaves aux 0, so an animation over plain scalars lands at rank 1
//! = timing-wheel bucket 0. The wheel itself is the 52-byte singleton the
//! lazy allocator @ 0x082739a0 parks in the global word 0x089cc7e0 (48
//! bytes = 12 bucket heads, then a guard word): insert 0x08273898 buckets
//! a node at `[rank - 1]`, sets the linked flag (bit 0 of byte +0x14) and
//! threads the doubly-linked list through +0x0c/+0x10; remove
//! 0x082738e0 unlinks only when that flag bit is set — which for a freshly
//! zeroed object makes step five a defensive no-op, reproduced anyway.
//!
//! # Deviations
//!
//! - **Three callees remain unported** and dispatch through
//!   [`ANIMATION_INIT_OPS`] (the `app/pending_event_take.rs` pattern):
//!   target builds transmute the ROM addresses 0x08273a14 (retain:
//!   `flags & 2 ? word(+0x14) += 4 : noop`) and
//!   0x082738e0/0x08273898; host defaults are inert stubs and every test
//!   installs recording reference models. Release 0x082739e0 is now the
//!   direct [`crate::app::refcounted_value::release_refcounted_value`] port.
//!   The shared base constructor
//!   [`crate::app::fixed_value::refcounted_base_init`] is ported and called
//!   directly, like the original's direct `bl`.
//! - The scheduler pointer is loaded through the live global word
//!   0x089cc7e0 on target (the singleton may be created lazily after this
//!   image was baked); host builds hand the seams a house-static 12-bucket
//!   table modelled on the allocator above.
//! - [`ANIMATION_VTABLE`] is an address constant only: it lives on the
//!   stale 0x0898xxxx page (the `app/registry.rs` caveat), so the port
//!   reproduces the stored pointer value, never the table's contents.
//! - The rank max recomputes `max(from, to)` in its fall-through arm
//!   exactly like the original (0x08166c30); LLVM folds the duplicate
//!   select, which changes nothing observable.

use crate::app::fixed_value::{refcounted_base_init, FixedValue};
use crate::app::refcounted_value::release_refcounted_value;

/// Firmware load address of the animation vtable literal (pool word at
/// 0x08166c54). Address constant only — see the module header's caveat.
pub const ANIMATION_VTABLE: u32 = 0x0898_7f00;

/// Firmware address of the global word holding the timing-wheel singleton
/// pointer (loaded twice via `ldr r5, [pc, #...]`; `ldr r0, [r5]` feeds
/// both wheel calls).
pub const SCHEDULER_SINGLETON_GLOBAL: usize = 0x089c_c7e0;

/// Firmware load addresses of the three unported callees, kept beside the
/// transmutes below.
pub const RETAIN_ADDRESS: usize = 0x0827_3a14;
pub const WHEEL_REMOVE_ADDRESS: usize = 0x0827_38e0;
pub const WHEEL_INSERT_ADDRESS: usize = 0x0827_3898;

/// One bucket head per unit of rank: the lazy allocator @ 0x082739a0
/// carves `operator_new(0x34)` and zeroes the first 48 bytes.
pub const TIMING_WHEEL_BUCKETS: usize = 12;

/// The animation object: 0x24 bytes on the 32-bit target (every caller
/// allocates `operator_new(0x24)`). Pointer fields are u32 target
/// pointers, hence the width-independent size.
#[repr(C)]
pub struct Animation {
    /// +0x00: the vtable — [`crate::app::fixed_value::REFCOUNTED_BASE_VTABLE`]
    /// during the base constructor, [`ANIMATION_VTABLE`] after it.
    pub vtable: u32,
    /// +0x04: not written by any function of this family.
    pub opaque_04: u32,
    /// +0x08: the timing-wheel rank: one past the largest endpoint aux
    /// word (unsigned). Insert buckets the node at `rank - 1`.
    pub rank: u32,
    /// +0x0c: wheel link, written only by insert/remove (u32 target ptr).
    pub wheel_prev: u32,
    /// +0x10: wheel link, written only by insert/remove (u32 target ptr).
    pub wheel_next: u32,
    /// +0x14: flags (bit 0 linked-in-wheel, bit 1 refcounted) and the
    /// refcount in bits 2..; zeroed by the base constructor.
    pub flags: u32,
    /// +0x18: retained `from` endpoint (u32 target ptr to a FixedValue).
    pub from_value: u32,
    /// +0x1c: retained `to` endpoint.
    pub to_value: u32,
    /// +0x20: retained animated value — the setter @ 0x08166b2c swaps
    /// exactly this slot and raises the rank, never lowering it.
    pub current_value: u32,
}

const _: () = assert!(core::mem::size_of::<Animation>() == 0x24);
const _: () = assert!(core::mem::offset_of!(Animation, opaque_04) == 0x04);
const _: () = assert!(core::mem::offset_of!(Animation, rank) == 0x08);
const _: () = assert!(core::mem::offset_of!(Animation, wheel_prev) == 0x0c);
const _: () = assert!(core::mem::offset_of!(Animation, wheel_next) == 0x10);
const _: () = assert!(core::mem::offset_of!(Animation, flags) == 0x14);
const _: () = assert!(core::mem::offset_of!(Animation, from_value) == 0x18);
const _: () = assert!(core::mem::offset_of!(Animation, to_value) == 0x1c);
const _: () = assert!(core::mem::offset_of!(Animation, current_value) == 0x20);

/// Indirect dispatch for the three unported callees (see the module header).
/// Host tests install recording models; a later port of each replaces its
/// default without touching this caller.
#[derive(Clone, Copy)]
pub struct AnimationInitOps {
    /// Retain 0x08273a14 `(value)`: when flag bit 1 is set, add 4 to the
    /// flags/refcount word at +0x14. No return value.
    pub retain_value: unsafe extern "C" fn(value: *mut FixedValue),
    /// Timing-wheel remove 0x082738e0 `(table, node)`: unlink `node`
    /// from bucket `node->rank - 1` iff the linked flag is set.
    pub wheel_remove: unsafe extern "C" fn(table: *mut u8, node: *mut Animation),
    /// Timing-wheel insert 0x08273898 `(table, node)`: push `node` at the
    /// head of bucket `node->rank - 1` and set the linked flag.
    pub wheel_insert: unsafe extern "C" fn(table: *mut u8, node: *mut Animation),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_retain(value: *mut FixedValue) {
    let f: unsafe extern "C" fn(*mut FixedValue) = core::mem::transmute(RETAIN_ADDRESS);
    f(value)
}


#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_wheel_remove(table: *mut u8, node: *mut Animation) {
    let f: unsafe extern "C" fn(*mut u8, *mut Animation) =
        core::mem::transmute(WHEEL_REMOVE_ADDRESS);
    f(table, node)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_wheel_insert(table: *mut u8, node: *mut Animation) {
    let f: unsafe extern "C" fn(*mut u8, *mut Animation) =
        core::mem::transmute(WHEEL_INSERT_ADDRESS);
    f(table, node)
}

/// Host defaults: inert — every test installs its own model.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_retain(_value: *mut FixedValue) {}


/// Host default: inert.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_wheel_remove(_table: *mut u8, _node: *mut Animation) {}

/// Host default: inert.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_wheel_insert(_table: *mut u8, _node: *mut Animation) {}

/// Wired defaults: ROM addresses on target, documented inert stubs on
/// host.
pub const DEFAULT_ANIMATION_INIT_OPS: AnimationInitOps = AnimationInitOps {
    retain_value: firmware_retain,
    wheel_remove: firmware_wheel_remove,
    wheel_insert: firmware_wheel_insert,
};

/// The active callee set, read through `read_volatile` so LLVM cannot
/// fold the indirect calls to the defaults.
pub static mut ANIMATION_INIT_OPS: AnimationInitOps = DEFAULT_ANIMATION_INIT_OPS;

#[inline(always)]
fn animation_init_ops() -> AnimationInitOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ANIMATION_INIT_OPS)) }
}

/// The first argument both wheel callees receive: the word stored at
/// [`SCHEDULER_SINGLETON_GLOBAL`]. On target that is the live singleton
/// pointer (created lazily @ 0x082739a0); host builds model the created
/// state with a house-static bucket array.
#[cfg(target_os = "none")]
fn scheduler_table() -> *mut u8 {
    unsafe { core::ptr::read_volatile(SCHEDULER_SINGLETON_GLOBAL as *mut u32) as *mut u8 }
}

#[cfg(not(target_os = "none"))]
static mut HOST_SCHEDULER_BUCKETS: [u32; TIMING_WHEEL_BUCKETS] = [0; TIMING_WHEEL_BUCKETS];

#[cfg(not(target_os = "none"))]
fn scheduler_table() -> *mut u8 {
    unsafe { core::ptr::addr_of_mut!(HOST_SCHEDULER_BUCKETS).cast::<u8>() }
}

/// animation_init — original: `FUN_08166b88` @ 0x08166b88 (212 bytes
/// including the two-word pool; 44 `bl` call sites, binary-verified — see
/// the module header).
///
/// Constructs an animation over `(current, from, to)` in the
/// caller-allocated 0x24 bytes at `this` and returns `this`: run the
/// refcounted base constructor, install the animation vtable, clear the
/// three endpoint slots, unlink defensively from the timing wheel, retain
/// the three arguments in order current/from/to, replay the (statically
/// dead) release-before-overwrite of each slot, store the endpoints, then
/// store `rank = max(from.aux, to.aux, current.aux) + 1` (unsigned,
/// wrapping) and link the object into the wheel.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn animation_init(
    this: *mut Animation,
    current_value: *mut FixedValue,
    from: *mut FixedValue,
    to: *mut FixedValue,
) -> *mut Animation {
    // 08166b98: bl 0x08138460 — the shared refcounted base constructor.
    refcounted_base_init(this.cast::<FixedValue>());
    // 08166ba0..08166ba8: override the base vtable with the derived one.
    (*this).vtable = ANIMATION_VTABLE;
    // 08166bac..08166bb8: str +0x18, +0x1c, +0x20.
    (*this).from_value = 0;
    (*this).to_value = 0;
    (*this).current_value = 0;

    let ops = animation_init_ops();
    let table = scheduler_table();

    // 08166bc4: defensive unlink — byte +0x14 just cleared means the
    // firmware body returns on its first flag test; kept for parity.
    (ops.wheel_remove)(table, this);

    // 08166bcc..08166bdc: retain(current), retain(from), retain(to).
    (ops.retain_value)(current_value);
    (ops.retain_value)(from);
    (ops.retain_value)(to);

    // 08166be0..08166c00: memberwise-assign release of each OLD slot,
    // checked current (+0x20) first, then from (+0x18), then to (+0x1c).
    // All three loads land on words step three zeroed — dead code the
    // compiler must still be free to keep or drop.
    let old_current = (*this).current_value;
    if old_current != 0 {
        release_refcounted_value(old_current as usize as *mut u8);
    }
    let old_from = (*this).from_value;
    if old_from != 0 {
        release_refcounted_value(old_from as usize as *mut u8);
    }
    let old_to = (*this).to_value;
    if old_to != 0 {
        release_refcounted_value(old_to as usize as *mut u8);
    }

    // 08166c04..08166c08: stm r0={r6,r7,r8} — from, to, current.
    (*this).from_value = from as usize as u32;
    (*this).to_value = to as usize as u32;
    (*this).current_value = current_value as usize as u32;

    // 08166c0c..08166c3c: unsigned max of the three aux words, +1. The
    // fall-through arm recomputes max(from, to) instead of reusing r2,
    // exactly like the original; LLVM folds the duplicate select.
    let from_aux = (*from).aux;
    let to_aux = (*to).aux;
    let current_aux = (*current_value).aux;
    let highest = if from_aux <= to_aux {
        if to_aux <= current_aux {
            current_aux
        } else if from_aux <= to_aux {
            to_aux
        } else {
            from_aux
        }
    } else if from_aux <= current_aux {
        current_aux
    } else {
        from_aux
    };
    (*this).rank = highest.wrapping_add(1);

    // 08166c48: link into the timing wheel at bucket rank-1.
    (ops.wheel_insert)(table, this);
    this
}

/// animation_set_current_value — original: `FUN_08166b2c` @ 0x08166b2c
/// (88 instruction bytes; the separate literal-pool word at 0x08166b84
/// holds the scheduler-global address). Binary decoding of every ARM B/BL
/// word in osos.dec finds 30 call sites: all are plain unconditional `bl`;
/// there are no predicated calls, tail branches, or DATA-word references.
///
/// Replaces the retained current-value slot at +0x20. It unlinks `this`
/// from the timing wheel, retains `value`, releases the old current value
/// only when non-NULL, stores `value`, raises `rank` to
/// `max(rank, value.aux + 1)` using unsigned comparison and wrapping
/// addition, then reinserts the node. `value` has no NULL guard because
/// the stock body dereferences `value + 8` unconditionally.
///
/// Deliberate deviation: the three unported direct callees use the existing
/// [`ANIMATION_INIT_OPS`] volatile seam. Release is now called through the
/// direct [`release_refcounted_value`] port. The scheduler-global word is read
/// separately for remove and insert, as in the two stock `ldr [r5]` sites.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn animation_set_current_value(
    this: *mut Animation,
    value: *mut FixedValue,
) {
    let ops = animation_init_ops();

    // 08166b40..08166b44: unlink before changing rank or the slot.
    (ops.wheel_remove)(scheduler_table(), this);
    // 08166b48..08166b4c: retain the incoming value before releasing old.
    (ops.retain_value)(value);

    // 08166b50..08166b5c: memberwise-assign's conditional old-value
    // release, then the +0x20 replacement.
    let old_value = (*this).current_value;
    if old_value != 0 {
        release_refcounted_value(old_value as usize as *mut u8);
    }
    (*this).current_value = value as usize as u32;

    // 08166b60..08166b70: candidate = value->aux + 1; `strcc` only raises
    // this->rank, using the CPU's unsigned carry-clear condition.
    let candidate_rank = (*value).aux.wrapping_add(1);
    if (*this).rank < candidate_rank {
        (*this).rank = candidate_rank;
    }

    // 08166b74..08166b80: reload the scheduler word and tail-branch to
    // wheel_insert(table, this). Its return value is discarded by callers.
    (ops.wheel_insert)(scheduler_table(), this);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// Serializes swaps of [`ANIMATION_INIT_OPS`] and the shared fixture
    /// slab across this module's tests.
    pub(crate) static ANIMATION_INIT_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Restores the ops seam even if a test panics mid-run.
    struct SeamGuard;

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(ANIMATION_INIT_OPS).write_volatile(DEFAULT_ANIMATION_INIT_OPS);
            }
        }
    }

    const EVENT_RETAIN: u32 = 1;
    const EVENT_WHEEL_REMOVE: u32 = 3;
    const EVENT_WHEEL_INSERT: u32 = 4;

    /// One observed seam call: (kind, argument, extra). For wheel events
    /// `argument` is the node address and `extra` the table address; for
    /// wheel-insert events `extra2` additionally captures the node's rank
    /// at call time.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Event {
        kind: u32,
        argument: usize,
        extra: usize,
        rank_at_insert: Option<u32>,
    }

    static mut LOG: [Event; 16] = [Event {
        kind: 0,
        argument: 0,
        extra: 0,
        rank_at_insert: None,
    }; 16];
    static mut LOG_LEN: usize = 0;

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

    unsafe extern "C" fn recording_retain(value: *mut FixedValue) {
        // The firmware arithmetic: flag bit 1 gates the += 4.
        if (*value).flags as u8 & 2 != 0 {
            (*value).flags = (*value).flags.wrapping_add(4);
        }
        record(Event {
            kind: EVENT_RETAIN,
            argument: value as usize,
            extra: 0,
            rank_at_insert: None,
        });
    }


    unsafe extern "C" fn recording_wheel_remove(table: *mut u8, node: *mut Animation) {
        record(Event {
            kind: EVENT_WHEEL_REMOVE,
            argument: node as usize,
            extra: table as usize,
            rank_at_insert: Some((*node).rank),
        });
    }

    unsafe extern "C" fn recording_wheel_insert(table: *mut u8, node: *mut Animation) {
        record(Event {
            kind: EVENT_WHEEL_INSERT,
            argument: node as usize,
            extra: table as usize,
            rank_at_insert: Some((*node).rank),
        });
    }

    unsafe fn record(event: Event) {
        let slot = LOG_LEN;
        assert!(slot < LOG.len(), "event log overflow");
        LOG[slot] = event;
        LOG_LEN = slot + 1;
    }

    unsafe fn install_recording_ops() {
        core::ptr::addr_of_mut!(ANIMATION_INIT_OPS).write_volatile(AnimationInitOps {
            retain_value: recording_retain,
            wheel_remove: recording_wheel_remove,
            wheel_insert: recording_wheel_insert,
        });
    }

    fn take_lock() -> MutexGuard<'static, ()> {
        ANIMATION_INIT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Fixture addresses inside the low-4-GiB slab, so the animation's
    /// u32 target pointers round-trip exactly.
    #[derive(Clone, Copy)]
    struct Fixture {
        animation: *mut Animation,
        current: *mut FixedValue,
        from: *mut FixedValue,
        to: *mut FixedValue,
        table: *mut u8,
    }

    static FIXTURE: OnceLock<Option<usize>> = OnceLock::new();

    fn fixture() -> Option<Fixture> {
        let base = *FIXTURE.get_or_init(|| {
            try_map_u32_slab(crate::testing::hints::ANIMATION_INIT, 0x1000)
                .map(|p| p as usize)
        });
        let base = base? as *mut u8;
        Some(unsafe {
            Fixture {
                animation: base.cast::<Animation>(),
                current: base.add(0x28).cast::<FixedValue>(),
                from: base.add(0x40).cast::<FixedValue>(),
                to: base.add(0x58).cast::<FixedValue>(),
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
    /// field it must NOT touch) is observable.
    fn dirty_animation(at: *mut Animation) {
        unsafe {
            core::ptr::write(
                at,
                Animation {
                    vtable: 0xdead_beef,
                    opaque_04: 0x1111_1111,
                    rank: 0xcafe_babe,
                    wheel_prev: 0x2222_2222,
                    wheel_next: 0x3333_3333,
                    flags: 0xffff_ffff,
                    from_value: 0x4444_4444,
                    to_value: 0x5555_5555,
                    current_value: 0x6666_6666,
                },
            );
        }
    }

    #[test]
    fn it_returns_the_storage_it_was_given() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            install_recording_ops();
            reset_log();
            dirty_animation(f.animation);
            counted_scalar(f.current, 0);
            counted_scalar(f.from, 0);
            counted_scalar(f.to, 0);

            let returned = animation_init(f.animation, f.current, f.from, f.to);
            assert_eq!(returned, f.animation);
        }
    }

    #[test]
    fn it_installs_the_derived_vtable_and_the_base_ctor_zeroes_flags() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            install_recording_ops();
            reset_log();
            dirty_animation(f.animation);
            counted_scalar(f.current, 0);
            counted_scalar(f.from, 0);
            counted_scalar(f.to, 0);

            animation_init(f.animation, f.current, f.from, f.to);

            let anim = &*f.animation;
            assert_eq!(anim.vtable, ANIMATION_VTABLE, "0x08987f00, the 0x08166c54 pool word");
            assert_eq!(anim.flags, 0, "the base ctor zeroes +0x14 and retains touch only the arguments");
        }
    }

    #[test]
    fn endpoint_slots_hold_from_to_current_in_target_order() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            install_recording_ops();
            reset_log();
            dirty_animation(f.animation);
            counted_scalar(f.current, 0);
            counted_scalar(f.from, 0);
            counted_scalar(f.to, 0);

            animation_init(f.animation, f.current, f.from, f.to);

            let anim = &*f.animation;
            assert_eq!(
                anim.from_value, f.from as usize as u32,
                "+0x18 takes the third argument (r2)"
            );
            assert_eq!(
                anim.to_value, f.to as usize as u32,
                "+0x1c takes the fourth argument (r3)"
            );
            assert_eq!(
                anim.current_value, f.current as usize as u32,
                "+0x20 takes the second argument (r1)"
            );
        }
    }

    #[test]
    fn rank_is_one_plus_the_unsigned_max_of_the_three_aux_words() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            install_recording_ops();
            // (current, from, to) aux tuples: plain scalars, mixed values,
            // ties, high-bit values proving the compares are unsigned, and
            // the wrapping edge 0xffff_ffff + 1 == 0.
            for &(cur, frm, tou) in &[
                (0u32, 0u32, 0u32),
                (5, 3, 4),
                (3, 5, 4),
                (3, 4, 5),
                (7, 7, 7),
                (0x8000_0000, 1, 2),
                (1, 0xffff_fffe, 2),
                (0xffff_ffff, 0xffff_ffff, 0xffff_ffff),
                (0, 0xffff_ffff, 0x8000_0000),
            ] {
                reset_log();
                dirty_animation(f.animation);
                counted_scalar(f.current, cur);
                counted_scalar(f.from, frm);
                counted_scalar(f.to, tou);

                animation_init(f.animation, f.current, f.from, f.to);

                let expected = cur.max(frm).max(tou).wrapping_add(1);
                assert_eq!((*f.animation).rank, expected, "aux ({cur:#x}, {frm:#x}, {tou:#x})");
                assert_eq!(
                    log().last().unwrap().rank_at_insert,
                    Some(expected),
                    "the node enters the wheel already carrying its rank"
                );
            }
        }
    }

    #[test]
    fn the_call_protocol_is_remove_retain_x3_assign_insert() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            install_recording_ops();
            reset_log();
            dirty_animation(f.animation);
            counted_scalar(f.current, 0xa0_0000);
            counted_scalar(f.from, 0);
            counted_scalar(f.to, 0xff_0000);

            animation_init(f.animation, f.current, f.from, f.to);

            let seen = log();
            let kinds: std::vec::Vec<u32> = seen.iter().map(|e| e.kind).collect();
            assert_eq!(
                kinds,
                std::vec![
                    EVENT_WHEEL_REMOVE,
                    EVENT_RETAIN,
                    EVENT_RETAIN,
                    EVENT_RETAIN,
                    EVENT_WHEEL_INSERT,
                ],
                "unlink first, three retains, then the insert"
            );
            assert_eq!(seen[0].argument, f.animation as usize, "remove targets this");
            assert_eq!(seen[1].argument, f.current as usize, "retain order: current");
            assert_eq!(seen[2].argument, f.from as usize, "then from");
            assert_eq!(seen[3].argument, f.to as usize, "then to");
            assert_eq!(seen[4].argument, f.animation as usize, "insert targets this");
            assert_eq!(
                seen[0].extra, f.table as usize,
                "both wheel calls receive the scheduler-table word"
            );
            assert_eq!(seen[4].extra, f.table as usize);
        }
    }

    #[test]
    fn constructor_releases_no_slots_after_clearing_them() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            install_recording_ops();
            reset_log();
            dirty_animation(f.animation);
            counted_scalar(f.current, 0);
            counted_scalar(f.from, 0);
            counted_scalar(f.to, 0);

            animation_init(f.animation, f.current, f.from, f.to);

            // The three blne releases read slots the constructor zeroed
            // itself, so release_refcounted_value sees no values to touch.
            assert_eq!((*f.current).flags, 0b1010);
            assert_eq!((*f.from).flags, 0b1010);
            assert_eq!((*f.to).flags, 0b1010);
        }
    }

    #[test]
    fn untouched_fields_keep_their_sentinels() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            install_recording_ops();
            reset_log();
            dirty_animation(f.animation);
            counted_scalar(f.current, 0);
            counted_scalar(f.from, 0);
            counted_scalar(f.to, 0);

            animation_init(f.animation, f.current, f.from, f.to);

            let anim = &*f.animation;
            assert_eq!(anim.opaque_04, 0x1111_1111, "+0x04 is not written");
            assert_eq!(anim.wheel_prev, 0x2222_2222, "+0x0c belongs to the wheel ops");
            assert_eq!(anim.wheel_next, 0x3333_3333, "+0x10 belongs to the wheel ops");
        }
    }

    #[test]
    fn construction_produces_the_exact_final_word_image() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            install_recording_ops();
            reset_log();
            dirty_animation(f.animation);
            counted_scalar(f.current, 0x00a0_0000);
            counted_scalar(f.from, 0x0000_0002);
            counted_scalar(f.to, 0x0000_0009);

            animation_init(f.animation, f.current, f.from, f.to);

            let words = core::slice::from_raw_parts(f.animation.cast::<u32>(), 9);
            assert_eq!(
                words,
                &[
                    ANIMATION_VTABLE,      // +0x00
                    0x1111_1111,          // +0x04 sentinel survives
                    0x00a0_0001,          // +0x08 rank = max(2, 9, 0xa0_0000) + 1
                    0x2222_2222,          // +0x0c sentinel
                    0x3333_3333,          // +0x10 sentinel
                    0,                    // +0x14 flags/refcount
                    f.from as u32,        // +0x18
                    f.to as u32,          // +0x1c
                    f.current as u32,     // +0x20
                ],
                "all nine words, nothing else touched"
            );
        }
    }

    #[test]
    fn the_host_scheduler_model_matches_the_lazy_allocator_shape() {
        // 12 bucket heads of 4 bytes inside the 52-byte singleton.
        let _lock = take_lock();
        let table = scheduler_table();
        assert!(!table.is_null());
        let buckets = unsafe { core::slice::from_raw_parts(table.cast::<u32>(), TIMING_WHEEL_BUCKETS) };
        assert!(buckets.iter().all(|b| *b == 0), "freshly allocated buckets are NULL");
    }

    #[test]
    fn default_host_seams_are_inert_but_safe_to_call() {
        // Without installed models nothing records and nothing writes:
        // the defaults exist so a forgotten install cannot corrupt state.
        let _lock = take_lock();
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            core::ptr::addr_of_mut!(ANIMATION_INIT_OPS)
                .write_volatile(DEFAULT_ANIMATION_INIT_OPS);
            reset_log();
            dirty_animation(f.animation);
            counted_scalar(f.current, 0);
            counted_scalar(f.from, 0);
            counted_scalar(f.to, 0);

            animation_init(f.animation, f.current, f.from, f.to);

            assert!(log().is_empty(), "no events without a recording model");
            assert_eq!((*f.animation).vtable, ANIMATION_VTABLE);
            assert_eq!((*f.animation).rank, 1, "plain scalars carry aux 0");
            assert_eq!((*f.current).flags, 0b110, "the inert retain wrote nothing");
        }
    }
    #[test]
    fn setter_unlinks_retains_releases_replaces_and_relinks() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            install_recording_ops();
            reset_log();
            dirty_animation(f.animation);
            counted_scalar(f.current, 3);
            (*f.current).flags = 0b1010; // count 2: owned slot can release one.
            counted_scalar(f.from, 9);
            (*f.animation).current_value = f.current as usize as u32;
            (*f.animation).rank = 4;

            animation_set_current_value(f.animation, f.from);

            let seen = log();
            assert_eq!(
                seen.iter().map(|event| event.kind).collect::<std::vec::Vec<_>>(),
                std::vec![EVENT_WHEEL_REMOVE, EVENT_RETAIN, EVENT_WHEEL_INSERT],
                "stock order is remove, retain incoming, direct release old, tail insert"
            );
            assert_eq!(seen[0].argument, f.animation as usize);
            assert_eq!(seen[1].argument, f.from as usize);
            assert_eq!(seen[2].argument, f.animation as usize);
            assert_eq!(seen[0].extra, f.table as usize);
            assert_eq!(seen[2].extra, f.table as usize);
            assert_eq!(seen[2].rank_at_insert, Some(10));
            assert_eq!((*f.animation).current_value, f.from as usize as u32);
            assert_eq!((*f.animation).rank, 10);
            assert_eq!((*f.current).flags, 0b110, "old value loses one reference");
            assert_eq!((*f.from).flags, 0b1010, "incoming value gains one reference");
            assert_eq!((*f.animation).opaque_04, 0x1111_1111, "+0x04 is untouched");
            assert_eq!((*f.animation).from_value, 0x4444_4444, "+0x18 is untouched");
            assert_eq!((*f.animation).to_value, 0x5555_5555, "+0x1c is untouched");
        }
    }

    #[test]
    fn setter_never_lowers_rank_and_wraps_the_aux_candidate() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            install_recording_ops();
            for &(rank, aux, expected) in &[
                (0, 0, 1),
                (7, 0, 7),
                (0x7fff_ffff, 0x8000_0000, 0x8000_0001),
                (u32::MAX, u32::MAX, u32::MAX),
                (0, u32::MAX, 0),
            ] {
                reset_log();
                dirty_animation(f.animation);
                counted_scalar(f.current, 0);
                counted_scalar(f.from, aux);
                (*f.current).flags = 0b1010;
                (*f.animation).current_value = f.current as usize as u32;
                (*f.animation).rank = rank;

                animation_set_current_value(f.animation, f.from);

                assert_eq!((*f.animation).rank, expected, "rank {rank:#x}, aux {aux:#x}");
                assert_eq!(log().last().unwrap().rank_at_insert, Some(expected));
            }
        }
    }

    #[test]
    fn setter_skips_release_for_an_empty_current_slot() {
        let _lock = take_lock();
        let _restore = SeamGuard;
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            install_recording_ops();
            reset_log();
            dirty_animation(f.animation);
            counted_scalar(f.from, 0);
            (*f.animation).current_value = 0;
            (*f.animation).rank = 0;

            animation_set_current_value(f.animation, f.from);

            assert_eq!(
                log().iter().map(|event| event.kind).collect::<std::vec::Vec<_>>(),
                std::vec![EVENT_WHEEL_REMOVE, EVENT_RETAIN, EVENT_WHEEL_INSERT],
                "the only predicated callee inside the body is release(old)"
            );
            assert_eq!((*f.animation).current_value, f.from as usize as u32);
            assert_eq!((*f.animation).rank, 1);
        }
    }

}
