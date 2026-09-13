//! Vtable-gated state-flag predicate.
//!
//! `vtable_predicate_state_flag_set` — original: `FUN_082a4380` @
//! `0x082a4380` (52 bytes). Raw ARM establishes this exact extent: it starts
//! with `push {r4, lr}` and ends with `pop {r4, pc}` at `0x082a43b0`; the next
//! separately linked function starts at `0x082a43b4`. Direct B/BL decoding of
//! `osos.dec` found six call sites, all unconditional `bl` (none predicated):
//! `0x0817d8b8`, `0x081a6be4`, `0x0821706c`, `0x0821d254`, `0x0821f35c`, and
//! `0x0821f42c`.
//!
//! Algorithm: call the object's vtable slot `+0x08` with `this`. Only when
//! that opaque predicate returns nonzero, read the object-owned state pointer
//! at `+0x08` and return whether its word at `+0xbc` has bit `0x8000` set.
//! Every pointer and vtable entry is deliberately unchecked, matching the ARM
//! code. No deliberate deviations.

/// ARMv5TE vtable word index for the predicate callback at byte offset `+0x08`.
const VTABLE_PREDICATE_SLOT: usize = 0x08 / 4;
/// State-word bit selected after a successful predicate callback.
const REQUIRED_STATE_FLAG: u32 = 0x8000;

/// ABI of the unrecovered vtable predicate at object vtable `+0x08`.
pub type VtablePredicate = unsafe extern "C" fn(*mut VtablePredicateObject) -> u32;

/// Recovered object prefix consumed by [`vtable_predicate_state_flag_set`].
///
/// On ARM, `vtable` is at `+0x00`, the unresolved word stays at `+0x04`, and
/// `state` is at `+0x08`. Native host pointers intentionally remain
/// pointer-width so test callbacks can be invoked directly; named fields avoid
/// accidentally treating the host representation as the target byte layout.
#[repr(C)]
pub struct VtablePredicateObject {
    pub vtable: *const VtablePredicate,
    pub unresolved_04: u32,
    pub state: *const VtablePredicateState,
}

/// Recovered state prefix whose flag word is read at `+0xbc`.
#[repr(C)]
pub struct VtablePredicateState {
    pub unresolved_before_flags: [u32; 0xbc / 4],
    pub flags: u32,
}

#[cfg(target_os = "none")]
const _: [u8; 0x08] = [0; core::mem::offset_of!(VtablePredicateObject, state)];
#[cfg(target_os = "none")]
const _: [u8; 0xbc] = [0; core::mem::offset_of!(VtablePredicateState, flags)];

/// Calls vtable slot `+0x08`, then tests bit `0x8000` of the state word.
///
/// The original's `cmp`, conditional state loads, and conditional `tst` mean
/// the state pointer is not accessed when the virtual predicate returns zero.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_predicate_state_flag_set(
    object: *mut VtablePredicateObject,
) -> u32 {
    let predicate = unsafe { object.read().vtable.add(VTABLE_PREDICATE_SLOT).read() };
    if unsafe { predicate(object) } == 0 {
        return 0;
    }

    let flags = unsafe { object.read().state.read().flags };
    u32::from(flags & REQUIRED_STATE_FLAG != 0)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut FORWARDED_OBJECT: usize = 0;
    static mut WRONG_SLOT_CALLS: usize = 0;
    static mut PREDICATE_RETURN: u32 = 0;

    unsafe extern "C" fn wrong_slot(_object: *mut VtablePredicateObject) -> u32 {
        unsafe { WRONG_SLOT_CALLS += 1 };
        0
    }

    unsafe extern "C" fn recording_predicate(object: *mut VtablePredicateObject) -> u32 {
        unsafe {
            FORWARDED_OBJECT = object as usize;
            PREDICATE_RETURN
        }
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench(predicate_return: u32) -> Bench {
        let lock = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            FORWARDED_OBJECT = 0;
            WRONG_SLOT_CALLS = 0;
            PREDICATE_RETURN = predicate_return;
        }
        Bench { _lock: lock }
    }

    fn state(flags: u32) -> VtablePredicateState {
        VtablePredicateState {
            unresolved_before_flags: [0; 0xbc / 4],
            flags,
        }
    }

    #[test]
    fn calls_slot_08_forwards_this_and_requires_the_state_flag() {
        let _bench = bench(0xfeed_beef);
        let mut vtable = [wrong_slot as VtablePredicate; VTABLE_PREDICATE_SLOT + 1];
        vtable[VTABLE_PREDICATE_SLOT] = recording_predicate;
        let mut object_state = state(0x8001);
        let mut object = VtablePredicateObject {
            vtable: vtable.as_ptr(),
            unresolved_04: 0x1122_3344,
            state: &mut object_state,
        };

        assert_eq!(unsafe { vtable_predicate_state_flag_set(&mut object) }, 1);
        assert_eq!(unsafe { FORWARDED_OBJECT }, (&mut object as *mut VtablePredicateObject) as usize);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x08 may run");

        object_state.flags = 0x7fff_7fff;
        assert_eq!(unsafe { vtable_predicate_state_flag_set(&mut object) }, 0);
        object_state.flags = 0xffff_8000;
        assert_eq!(unsafe { vtable_predicate_state_flag_set(&mut object) }, 1);
    }

    #[test]
    fn false_virtual_predicate_short_circuits_before_state_access() {
        let _bench = bench(0);
        let mut vtable = [wrong_slot as VtablePredicate; VTABLE_PREDICATE_SLOT + 1];
        vtable[VTABLE_PREDICATE_SLOT] = recording_predicate;
        let mut object = VtablePredicateObject {
            vtable: vtable.as_ptr(),
            unresolved_04: 0,
            state: core::ptr::null(),
        };

        assert_eq!(unsafe { vtable_predicate_state_flag_set(&mut object) }, 0);
        assert_eq!(unsafe { FORWARDED_OBJECT }, (&mut object as *mut VtablePredicateObject) as usize);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0);
    }
}
