//! `object_release_slot1` — original: `FUN_083e7448` @ `0x083e7448`
//! (36 bytes; 6 verified direct `bl` call sites, all unconditional).
//!
//! Raw ARM extent is exactly 36 bytes (`0x083e7448..0x083e746c`); the distinct
//! sibling `FUN_083e746c` starts immediately afterward. The wrapper reads an
//! object pointer from its caller-owned slot. A NULL object skips all dispatch.
//! Otherwise it loads the object's vtable and invokes entry `+0x04` with the
//! object in `r0`; it then returns the original slot. The six inbound calls are
//! plain, unconditional `bl` at `0x081857c8`, `0x0819ef14`, `0x081e01a4`,
//! `0x081e0264`, `0x081ea724`, and `0x081eaf48`; no predicated direct calls
//! were found. The vtable target's identity is not established, so this port
//! preserves the indirect call instead of inventing a callee name.
//!
//! Deliberate deviation: Rust returns normally after the indirect method;
//! retailOS uses `blxne` followed by `mov r0,r4`. Both discard the method's
//! return value and return the original slot address.

/// Word index of the unresolved release method in the object's vtable: +0x04
/// on ARM.
const RELEASE_VTABLE_INDEX: usize = 0x04 / 4;

/// ABI of the unresolved object vtable release method.
type ObjectReleaseMethod = unsafe extern "C" fn(*mut u8);

/// `object_release_slot1` — original: `FUN_083e7448` @ `0x083e7448`
/// (36 bytes; 6 verified direct `bl` call sites, all unconditional).
///
/// If `*slot` is non-NULL, invokes its vtable entry `+0x04` with that object.
/// Returns `slot` regardless of the method's return register. `slot` must be
/// valid and aligned; a non-NULL object must provide an aligned vtable and a
/// valid method address, matching the raw unchecked loads and `blxne`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.object_release_slot1")]
#[inline(never)]
pub unsafe extern "C" fn object_release_slot1(slot: *mut *mut u8) -> *mut *mut u8 {
    let object = unsafe { slot.read() };
    if !object.is_null() {
        let vtable = unsafe { (object as *const *const usize).read() };
        let entry = unsafe { vtable.add(RELEASE_VTABLE_INDEX).read() };
        let release: ObjectReleaseMethod = unsafe { core::mem::transmute(entry) };
        unsafe { release(object) };
    }
    slot
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::object_release_slot1;
    use core::ptr;
    use parking_lot::{Mutex, MutexGuard};

    static RELEASE_LOCK: Mutex<()> = Mutex::new(());
    static mut RELEASE_CALLS: usize = 0;
    static mut WRONG_ENTRY_CALLS: usize = 0;
    static mut OBSERVED_OBJECT: usize = 0;

    unsafe extern "C" fn wrong_entry(_object: *mut u8) {
        unsafe { WRONG_ENTRY_CALLS += 1 };
    }

    unsafe extern "C" fn record_release(object: *mut u8) {
        unsafe {
            RELEASE_CALLS += 1;
            OBSERVED_OBJECT = object as usize;
        }
    }

    #[repr(C)]
    struct VtableObject {
        vtable: *const usize,
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = RELEASE_LOCK.lock();
        unsafe {
            RELEASE_CALLS = 0;
            WRONG_ENTRY_CALLS = 0;
            OBSERVED_OBJECT = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn null_object_skips_release_dispatch_and_returns_slot() {
        let _bench = bench();
        let mut slot: *mut u8 = ptr::null_mut();

        let slot_address = &mut slot as *mut *mut u8;
        let returned = unsafe { object_release_slot1(slot_address) };

        assert_eq!(returned, slot_address);
        assert!(slot.is_null());
        assert_eq!(unsafe { RELEASE_CALLS }, 0);
        assert_eq!(unsafe { WRONG_ENTRY_CALLS }, 0);
    }

    #[test]
    fn releases_through_vtable_slot_0x04_with_object() {
        let _bench = bench();
        let mut vtable = [wrong_entry as usize; 2];
        vtable[1] = record_release as usize;
        let mut object = VtableObject { vtable: vtable.as_ptr() };
        let object_address = (&mut object as *mut VtableObject).cast::<u8>();
        let mut slot = object_address;
        let slot_address = &mut slot as *mut *mut u8;

        let returned = unsafe { object_release_slot1(slot_address) };

        assert_eq!(returned, slot_address);
        assert_eq!(slot, object_address);
        assert_eq!(unsafe { RELEASE_CALLS }, 1);
        assert_eq!(unsafe { OBSERVED_OBJECT }, object_address as usize);
        assert_eq!(unsafe { WRONG_ENTRY_CALLS }, 0);
    }
}
