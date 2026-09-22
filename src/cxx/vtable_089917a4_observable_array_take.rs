//! Takes the owned ObservableArray after its vtable lifecycle dispatch.
//!
//! `vtable_089917a4_observable_array_take` — original: `FUN_0820440c` @
//! **0x0820440c** (40 bytes). Raw `osos.dec` establishes the exact extent:
//! ten ARM words from `push {r4,lr}` through `pop {r4,pc}`; the next real
//! function begins at `0x08204434`. Decoding raw immediate ARM branches finds
//! three inbound plain `bl` calls (`0x081dcda0`, `0x081dce60`, `0x0820fe58`)
//! and no predicated direct `bl` calls. The body has no direct `bl`; it makes
//! one unconditional indirect `blx` through vtable slot `+0x08`.
//!
//! # Algorithm
//!
//! Calls this object's unresolved vtable slot `+0x08`, then reads the owned
//! ObservableArray word at `+0x14`, clears that word, and returns the former
//! value. The callers use the value before destroying the enclosing object,
//! so clearing the field transfers ownership away from that destructor.
//!
//! # Deliberate deviation
//!
//! The slot-`+0x08` method's identity remains unrecovered. Rust models only
//! its verified `fn(this)` ABI. Host vtables use native-width function
//! pointers; `repr(C)` plus target-only offset assertions retain the ARM
//! layout. Rust's typed call replaces the indirect `blx`.

/// ARMv5TE word index of the lifecycle callback.
const LIFECYCLE_SLOT: usize = 0x08 / 4;
/// ARMv5TE word index of the owned ObservableArray pointer.
const OWNED_ARRAY_WORD: usize = 0x14 / 4;

/// ABI of the unresolved vtable slot `+0x08` lifecycle callback.
pub type ObservableArrayLifecycle = unsafe extern "C" fn(*mut ObservableArrayTakeOwner);

/// Vtable prefix consumed by [`vtable_089917a4_observable_array_take`].
#[repr(C)]
pub struct ObservableArrayTakeVtable {
    /// `+0x00..+0x04`: unresolved slots.
    pub opaque_00_04: [usize; LIFECYCLE_SLOT],
    /// `+0x08`: lifecycle callback run before ownership transfer.
    pub lifecycle: ObservableArrayLifecycle,
}

/// Observable-array owner prefix consumed by the transfer wrapper.
#[repr(C)]
pub struct ObservableArrayTakeOwner {
    /// `+0x00`: virtual method table.
    pub vtable: *const ObservableArrayTakeVtable,
    /// `+0x04..+0x10`: opaque state.
    pub opaque_04_10: [u32; OWNED_ARRAY_WORD - 1],
    /// `+0x14`: owned ObservableArray pointer represented as a target word.
    pub owned_array: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x08] = [0; core::mem::offset_of!(ObservableArrayTakeVtable, lifecycle)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x14] = [0; core::mem::offset_of!(ObservableArrayTakeOwner, owned_array)];

/// Dispatches the lifecycle slot and transfers the owner's ObservableArray word.
///
/// # Safety
///
/// `owner` must designate a readable and writable [`ObservableArrayTakeOwner`]
/// with a non-NULL vtable and callable slot-`+0x08` callback. The retail
/// wrapper performs none of these validations.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vtable_089917a4_observable_array_take")]
pub unsafe extern "C" fn vtable_089917a4_observable_array_take(
    owner: *mut ObservableArrayTakeOwner,
) -> u32 {
    let lifecycle = unsafe { (*(*owner).vtable).lifecycle };
    unsafe { lifecycle(owner) };
    let owned_array = unsafe { (*owner).owned_array };
    unsafe { (*owner).owned_array = 0 };
    owned_array
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};

    static TRANSFER_LOCK: Mutex<()> = Mutex::new(());
    static mut LIFECYCLE_CALLS: u32 = 0;
    static mut WRONG_SLOT_CALLS: u32 = 0;
    static mut FORWARDED_OWNER: *mut ObservableArrayTakeOwner = ptr::null_mut();
    static mut ARRAY_VISIBLE_TO_LIFECYCLE: u32 = 0;

    unsafe extern "C" fn wrong_slot(_owner: *mut ObservableArrayTakeOwner) {
        unsafe { WRONG_SLOT_CALLS += 1 };
    }

    unsafe extern "C" fn record_lifecycle(owner: *mut ObservableArrayTakeOwner) {
        unsafe {
            LIFECYCLE_CALLS += 1;
            FORWARDED_OWNER = owner;
            ARRAY_VISIBLE_TO_LIFECYCLE = (*owner).owned_array;
        }
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = TRANSFER_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            LIFECYCLE_CALLS = 0;
            WRONG_SLOT_CALLS = 0;
            FORWARDED_OWNER = ptr::null_mut();
            ARRAY_VISIBLE_TO_LIFECYCLE = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn dispatches_before_transferring_and_clearing_the_owned_array() {
        let _bench = bench();
        let vtable = ObservableArrayTakeVtable {
            opaque_00_04: [wrong_slot as usize; LIFECYCLE_SLOT],
            lifecycle: record_lifecycle,
        };
        let mut owner = ObservableArrayTakeOwner {
            vtable: &vtable,
            opaque_04_10: [0; OWNED_ARRAY_WORD - 1],
            owned_array: 0xfeed_cafe,
        };

        let taken = unsafe { vtable_089917a4_observable_array_take(&mut owner) };

        assert_eq!(taken, 0xfeed_cafe);
        assert_eq!(owner.owned_array, 0, "the source word is cleared after transfer");
        unsafe {
            assert_eq!(LIFECYCLE_CALLS, 1, "the +0x08 lifecycle slot runs once");
            assert_eq!(WRONG_SLOT_CALLS, 0, "no preceding vtable slot is called");
            assert!(core::ptr::eq(FORWARDED_OWNER, &mut owner));
            assert_eq!(ARRAY_VISIBLE_TO_LIFECYCLE, 0xfeed_cafe, "the callback precedes the clear");
        }
    }

    #[test]
    fn transfers_zero_after_still_running_the_lifecycle_callback() {
        let _bench = bench();
        let vtable = ObservableArrayTakeVtable {
            opaque_00_04: [wrong_slot as usize; LIFECYCLE_SLOT],
            lifecycle: record_lifecycle,
        };
        let mut owner = ObservableArrayTakeOwner {
            vtable: &vtable,
            opaque_04_10: [0; OWNED_ARRAY_WORD - 1],
            owned_array: 0,
        };

        assert_eq!(unsafe { vtable_089917a4_observable_array_take(&mut owner) }, 0);
        unsafe {
            assert_eq!(LIFECYCLE_CALLS, 1);
            assert_eq!(ARRAY_VISIBLE_TO_LIFECYCLE, 0);
        }
    }
}
