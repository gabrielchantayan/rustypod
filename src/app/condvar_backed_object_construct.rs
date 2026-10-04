//! Constructor @ 0x08215c44 (`FUN_08215c44`): 24 bytes, including the
//! vtable literal at 0x08215c58; next function begins at 0x08215c5c.
//! Raw A32 decoding verifies two inbound plain BLs (0x081d951c,
//! 0x081f5068), zero predicated BLs, and one outbound plain BL.
//!
//! Calls the opaque base constructor at 0x0813eb40, replaces the returned
//! object's first word with vtable 0x08993268, and returns that same pointer.
//! The base clears word +4 and byte +8 and constructs a CondVar at +12;
//! the class identity is not recovered. The symbol describes structure only.
//!
//! Deliberate deviation: hosts replace the unported base with an explicit
//! ABI seam; target builds call its verified retailOS address directly.

const VTABLE: u32 = 0x0899_3268;
type BaseConstruct = unsafe extern "C" fn(*mut u32) -> *mut u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn base_construct(storage: *mut u32) -> *mut u32 {
    core::mem::transmute::<usize, BaseConstruct>(0x0813_eb40)(storage)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_base_construct(_storage: *mut u32) -> *mut u32 {
    panic!("retailOS base constructor at 0x0813eb40 is not installed")
}

#[cfg(not(target_os = "none"))]
pub static mut CONDVAR_BACKED_BASE_CONSTRUCT: BaseConstruct = missing_base_construct;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn base_construct(storage: *mut u32) -> *mut u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(CONDVAR_BACKED_BASE_CONSTRUCT))(storage)
}

/// Constructs the derived object in storage accepted by the retail base.
///
/// # Safety
/// The base constructor must be available and its returned pointer must refer
/// to a writable, word-aligned object. No null check exists in retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn condvar_backed_object_construct(storage: *mut u32) -> *mut u32 {
    let object = base_construct(storage);
    object.write(VTABLE);
    object
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    // The dependency owns the rest of the object; emulate observable base
    // field initialization without pretending to implement its kernel call.
    unsafe extern "C" fn initialize_base(storage: *mut u32) -> *mut u32 {
        storage.write(0x0898_5108);
        storage.add(1).write(0);
        storage.add(2).cast::<u8>().write(0);
        storage
    }
    unsafe extern "C" fn relocated_base(storage: *mut u32) -> *mut u32 {
        initialize_base(storage.add(6))
    }

    #[test]
    fn replaces_only_vtable_and_preserves_base_fields_and_padding() {
        let _lock = LOCK.lock();
        unsafe {
            let previous = CONDVAR_BACKED_BASE_CONSTRUCT;
            CONDVAR_BACKED_BASE_CONSTRUCT = initialize_base;
            let mut object = [0xa5a5_a5a5u32; 6];
            let result = condvar_backed_object_construct(object.as_mut_ptr());
            CONDVAR_BACKED_BASE_CONSTRUCT = previous;
            assert_eq!(result, object.as_mut_ptr());
            assert_eq!(object, [VTABLE, 0, 0xa5a5_a500, 0xa5a5_a5a5, 0xa5a5_a5a5, 0xa5a5_a5a5]);
        }
    }

    #[test]
    fn installs_vtable_on_returned_object_not_incoming_storage() {
        let _lock = LOCK.lock();
        unsafe {
            let previous = CONDVAR_BACKED_BASE_CONSTRUCT;
            CONDVAR_BACKED_BASE_CONSTRUCT = relocated_base;
            let mut objects = [0x5a5a_5a5au32; 12];
            let result = condvar_backed_object_construct(objects.as_mut_ptr());
            CONDVAR_BACKED_BASE_CONSTRUCT = previous;
            assert_eq!(result, objects.as_mut_ptr().add(6));
            assert_eq!(&objects[..6], &[0x5a5a_5a5a; 6]);
            assert_eq!(&objects[6..], &[VTABLE, 0, 0x5a5a_5a00, 0x5a5a_5a5a, 0x5a5a_5a5a, 0x5a5a_5a5a]);
        }
    }
}
