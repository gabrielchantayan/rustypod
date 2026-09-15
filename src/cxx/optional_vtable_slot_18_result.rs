//! Optional virtual slot-`+0x18` result dispatcher.
//!
//! `optional_vtable_slot_18_result` — original: `FUN_0828ae4c` @
//! **0x0828ae4c** (28 bytes). Raw ARM establishes the exact extent from
//! `ldr r0,[r0,#0xdc]` at `0x0828ae4c` through `bx lr` at `0x0828ae64`; the
//! separately linked next function starts at `0x0828ae68`.
//!
//! Decoding every immediate ARM `B`/`BL` word in `osos.dec` finds five inbound
//! direct calls, all unconditional `bl`, at `0x0828a4f8`, `0x0828a50c`,
//! `0x0828ac04`, `0x0828ae04`, and `0x0828aec4`; there are no predicated `bl`
//! forms.
//!
//! # Algorithm
//!
//! Loads the optional target word at owner `+0xdc`. A null target returns one.
//! Otherwise it tail-dispatches the target through its vtable slot `+0x18`,
//! forwarding the target as the sole argument and preserving the callback
//! result. The target and its vtable have no NULL guards on that path; their
//! concrete identities remain unrecovered and are deliberately not invented.
//!
//! # Deliberate deviation
//!
//! ARM vtable entries are four-byte words, while host function pointers are
//! pointer-width. The Rust vtable therefore selects word index six from typed
//! host callback cells. Rust represents the ARM `bxne` terminal branch as a
//! typed callback call.

/// ARMv5TE vtable word index for byte offset `+0x18`.
const OPTIONAL_DISPATCH_SLOT: usize = 0x18 / 4;

/// ABI of the unrecovered callback at target vtable slot `+0x18`.
pub type OptionalVtableSlot18 = unsafe extern "C" fn(*mut OptionalVtableSlot18Target) -> u32;

/// Opaque target consumed by [`optional_vtable_slot_18_result`].
#[repr(C)]
pub struct OptionalVtableSlot18Target {
    pub vtable: *const OptionalVtableSlot18,
}

/// Owner prefix consumed by [`optional_vtable_slot_18_result`].
///
/// The 55 target words place `target` at ARM byte offset `+0xdc`; this avoids
/// host pointer-width changing the verified target offset.
#[repr(C)]
pub struct OptionalVtableSlot18Owner {
    pub unresolved_000_0db: [u32; 0xdc / 4],
    pub target: *mut OptionalVtableSlot18Target,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0xdc] = [0; core::mem::offset_of!(OptionalVtableSlot18Owner, target)];

/// Returns one for an absent target, otherwise invokes its vtable slot `+0x18`.
///
/// # Safety
///
/// When `target` is non-NULL, it must point to a readable target with a valid
/// vtable slot six whose callback accepts that target. As in the firmware,
/// neither pointer is validated on the dispatching path.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn optional_vtable_slot_18_result(
    owner: *mut OptionalVtableSlot18Owner,
) -> u32 {
    let target = unsafe { (*owner).target };
    if target.is_null() {
        return 1;
    }

    let callback = unsafe { (*target).vtable.add(OPTIONAL_DISPATCH_SLOT).read() };
    unsafe { callback(target) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut FORWARDED_TARGET: usize = 0;
    static mut DISPATCH_CALLS: usize = 0;
    static mut WRONG_SLOT_CALLS: usize = 0;

    unsafe extern "C" fn wrong_slot(_target: *mut OptionalVtableSlot18Target) -> u32 {
        unsafe { WRONG_SLOT_CALLS += 1 };
        0
    }

    unsafe extern "C" fn record_dispatch(target: *mut OptionalVtableSlot18Target) -> u32 {
        unsafe {
            FORWARDED_TARGET = target as usize;
            DISPATCH_CALLS += 1;
        }
        0xa5a5_5a5a
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            FORWARDED_TARGET = 0;
            DISPATCH_CALLS = 0;
            WRONG_SLOT_CALLS = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn absent_target_returns_one_without_dispatch() {
        let _bench = bench();
        let mut owner = OptionalVtableSlot18Owner {
            unresolved_000_0db: [0xa5a5_a5a5; 0xdc / 4],
            target: core::ptr::null_mut(),
        };

        assert_eq!(unsafe { optional_vtable_slot_18_result(&mut owner) }, 1);
        assert_eq!(unsafe { DISPATCH_CALLS }, 0);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0);
    }

    #[test]
    fn present_target_dispatches_only_slot_18_and_preserves_result() {
        let _bench = bench();
        let mut vtable = [wrong_slot as OptionalVtableSlot18; OPTIONAL_DISPATCH_SLOT + 1];
        vtable[OPTIONAL_DISPATCH_SLOT] = record_dispatch;
        let mut target = OptionalVtableSlot18Target { vtable: vtable.as_ptr() };
        let mut owner = OptionalVtableSlot18Owner {
            unresolved_000_0db: [0; 0xdc / 4],
            target: &mut target,
        };

        assert_eq!(unsafe { optional_vtable_slot_18_result(&mut owner) }, 0xa5a5_5a5a);
        assert_eq!(unsafe { FORWARDED_TARGET }, (&mut target as *mut OptionalVtableSlot18Target) as usize);
        assert_eq!(unsafe { DISPATCH_CALLS }, 1);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x18 dispatches");
    }
}
