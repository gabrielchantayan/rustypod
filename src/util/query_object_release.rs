//! `query_object_release_slot` — original: `FUN_083e75d0` @ `0x083e75d0`
//! (36 bytes; 17 verified direct `bl` call sites, all unconditional).
//!
//! Raw ARM extent is exactly 36 bytes (`0x083e75d0..0x083e75f0`); the distinct
//! sibling `FUN_083e75f4` begins immediately afterward. The wrapper reads a
//! query-object pointer from its caller-owned slot. A NULL object skips all
//! dispatch. Otherwise it loads the object's vtable and invokes entry `+0x1c`
//! with the object in `r0`; it then returns the original slot. All 17 direct
//! callers construct their stack-local object with `query_object_create`
//! (`FUN_082597a0`) and invoke this wrapper at scope exit. The identity of the
//! vtable target is not established, so this port preserves the indirect call
//! instead of assigning it an unverified callee name.
//!
//! Deliberate deviation: Rust returns normally after the indirect method;
//! retailOS uses `blx` followed by `mov r0,r4`. Both discard the method's
//! return value and return the original slot address.

/// Word index of the query-object release method in its vtable: +0x1c on ARM.
const RELEASE_VTABLE_INDEX: usize = 0x1c / 4;

/// ABI of the unresolved query-object vtable release method.
type QueryObjectReleaseMethod = unsafe extern "C" fn(*mut u8);

/// query_object_release_slot — original: `FUN_083e75d0` @ `0x083e75d0`
/// (36 bytes; 17 verified direct `bl` call sites, all unconditional).
///
/// If `*slot` is non-NULL, invokes its vtable entry `+0x1c` with that object.
/// Returns `slot` regardless of the method's return register. `slot` must be
/// valid and aligned; a non-NULL object must provide an aligned vtable and a
/// valid method address, matching the raw unchecked loads and `blxne`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn query_object_release_slot(slot: *mut *mut u8) -> *mut *mut u8 {
    let object = unsafe { slot.read() };
    if !object.is_null() {
        let vtable = unsafe { (object as *const *const usize).read() };
        let entry = unsafe { vtable.add(RELEASE_VTABLE_INDEX).read() };
        let release: QueryObjectReleaseMethod = unsafe { core::mem::transmute(entry) };
        unsafe { release(object) };
    }
    slot
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::query_object_release_slot;
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
        let returned = unsafe { query_object_release_slot(slot_address) };

        assert_eq!(returned, slot_address);
        assert!(slot.is_null());
        assert_eq!(unsafe { RELEASE_CALLS }, 0);
        assert_eq!(unsafe { WRONG_ENTRY_CALLS }, 0);
    }

    #[test]
    fn releases_through_vtable_slot_0x1c_with_object() {
        let _bench = bench();
        let mut vtable = [wrong_entry as usize; 8];
        vtable[7] = record_release as usize;
        let mut object = VtableObject { vtable: vtable.as_ptr() };
        let object_address = (&mut object as *mut VtableObject).cast::<u8>();
        let mut slot = object_address;
        let slot_address = &mut slot as *mut *mut u8;

        let returned = unsafe { query_object_release_slot(slot_address) };

        assert_eq!(returned, slot_address);
        assert_eq!(slot, object_address);
        assert_eq!(unsafe { RELEASE_CALLS }, 1);
        assert_eq!(unsafe { OBSERVED_OBJECT }, object_address as usize);
        assert_eq!(unsafe { WRONG_ENTRY_CALLS }, 0);
    }
}
