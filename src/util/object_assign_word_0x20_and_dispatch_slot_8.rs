//! `object_assign_word_0x20_and_dispatch_slot_8` — original: `FUN_08168314`
//! @ `0x08168314` (28 bytes; three verified direct `bl` call sites, all
//! unconditional).
//!
//! Raw `osos.dec` establishes the exact A32 extent `0x08168314..0x0816832c`:
//! `mov r2,r0; movs r0,r1; str r1,[r2,#0x20]; ldrne r1,[r0]; ldrne
//! r1,[r1,#8]; bxne r1; bx lr`. The next real function starts at `0x08168330`.
//! It stores `target` in `owner+0x20`, then, when non-NULL, dispatches the
//! target's vtable word at `+0x08` with `target` in `r0`; its return register
//! passes through unchanged. The vtable method's identity is not established.
//!
//! Deliberate deviation: Rust uses a normal conditional branch rather than
//! predicated loads and `bxne`. Host builds use a dispatch seam because native
//! host pointers cannot inhabit the retailOS four-byte vtable layout.

/// ABI observed for the unresolved vtable slot at `+0x08`.
type TargetVtableSlot8Method = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(target_os = "none")]
unsafe fn dispatch_target_vtable_slot_8(target: *mut u8) -> *mut u8 {
    let vtable_address = unsafe { target.cast::<u32>().read() };
    let entry_address = unsafe { (vtable_address as usize as *const u32).add(2).read() };
    let method: TargetVtableSlot8Method = unsafe { core::mem::transmute(entry_address as usize) };
    unsafe { method(target) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unresolved_target_vtable_slot_8(_target: *mut u8) -> *mut u8 {
    panic!("object_assign_word_0x20_and_dispatch_slot_8 requires its retailOS vtable method")
}

/// Host-test replacement for the unresolved retailOS vtable dispatch.
#[cfg(not(target_os = "none"))]
pub static mut TARGET_VTABLE_SLOT_8_DISPATCH: TargetVtableSlot8Method =
    unresolved_target_vtable_slot_8;

/// Stores `target` in `owner+0x20` and dispatches its vtable slot `+0x08`.
///
/// # Safety
///
/// `owner` must address writable, four-byte-aligned storage at `+0x20`. A
/// non-NULL `target` must provide the valid retailOS vtable and method expected
/// by the unchecked original instructions.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.object_assign_word_0x20_and_dispatch_slot_8")]
#[inline(never)]
pub unsafe extern "C" fn object_assign_word_0x20_and_dispatch_slot_8(
    owner: *mut u8,
    target: *mut u8,
) -> *mut u8 {
    unsafe { owner.add(0x20).cast::<u32>().write(target as usize as u32) };
    if target.is_null() {
        return target;
    }

    #[cfg(target_os = "none")]
    return unsafe { dispatch_target_vtable_slot_8(target) };

    #[cfg(not(target_os = "none"))]
    unsafe { TARGET_VTABLE_SLOT_8_DISPATCH(target) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{object_assign_word_0x20_and_dispatch_slot_8, TargetVtableSlot8Method, TARGET_VTABLE_SLOT_8_DISPATCH};
    use core::ptr;
    use parking_lot::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCH_CALLS: usize = 0;
    static mut OBSERVED_TARGET: usize = 0;

    unsafe extern "C" fn record_dispatch(target: *mut u8) -> *mut u8 {
        unsafe {
            DISPATCH_CALLS += 1;
            OBSERVED_TARGET = target as usize;
        }
        target.wrapping_add(1)
    }

    struct DispatchGuard {
        _lock: MutexGuard<'static, ()>,
        previous: TargetVtableSlot8Method,
    }

    impl Drop for DispatchGuard {
        fn drop(&mut self) {
            unsafe { TARGET_VTABLE_SLOT_8_DISPATCH = self.previous };
        }
    }

    fn install_dispatch() -> DispatchGuard {
        let lock = DISPATCH_LOCK.lock();
        unsafe {
            DISPATCH_CALLS = 0;
            OBSERVED_TARGET = 0;
            let previous = TARGET_VTABLE_SLOT_8_DISPATCH;
            TARGET_VTABLE_SLOT_8_DISPATCH = record_dispatch;
            DispatchGuard { _lock: lock, previous }
        }
    }

    #[test]
    fn null_target_is_stored_without_dispatch() {
        let _dispatch = install_dispatch();
        let mut owner = [0xa5a5_a5a5u32; 9];

        let returned = unsafe {
            object_assign_word_0x20_and_dispatch_slot_8(owner.as_mut_ptr().cast(), ptr::null_mut())
        };

        assert!(returned.is_null());
        assert_eq!(owner[7], 0xa5a5_a5a5);
        assert_eq!(owner[8], 0);
        assert_eq!(unsafe { DISPATCH_CALLS }, 0);
    }

    #[test]
    fn nonnull_target_is_stored_dispatched_and_returned() {
        let _dispatch = install_dispatch();
        let mut owner = [0xa5a5_a5a5u32; 9];
        let mut target = [0u32; 3];
        let target_pointer = target.as_mut_ptr().cast::<u8>();

        let returned = unsafe {
            object_assign_word_0x20_and_dispatch_slot_8(owner.as_mut_ptr().cast(), target_pointer)
        };

        assert_eq!(owner[8], target_pointer as usize as u32);
        assert_eq!(unsafe { DISPATCH_CALLS }, 1);
        assert_eq!(unsafe { OBSERVED_TARGET }, target_pointer as usize);
        assert_eq!(returned, target_pointer.wrapping_add(1));
    }
}
