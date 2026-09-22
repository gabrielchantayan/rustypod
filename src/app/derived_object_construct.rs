//! `derived_object_construct` — original: `FUN_0822c494` @ 0x0822c494 (20 bytes,
//! 0x0822c494..0x0822c4a8). The literal pool is at 0x0822c4a8; the next real
//! function starts at 0x0822c4ac. Raw A32 decoding finds **one unconditional
//! plain `bl`** (`0x0822c498 -> 0x081d6380`) and no predicated `bl`
//! instructions. The image contains three incoming plain `bl` call sites and
//! no predicated incoming calls.
//!
//! # Algorithm
//!
//! Forwards the three constructor registers to the unported base constructor
//! at 0x081d6380, then replaces the returned object's first word with derived
//! vtable 0x089a09f8 and returns that pointer.
//!
//! # Deliberate deviations
//!
//! The base constructor has no recovered semantic identity. Target builds call
//! its verified retailOS address; host builds expose a narrow seam. The ARM
//! `str` is a volatile word write so LLVM cannot elide the externally visible
//! vtable installation.

pub const DERIVED_OBJECT_VTABLE: u32 = 0x089a_09f8;

/// ABI of the unported base constructor at `0x081d6380`.
pub type BaseConstruct = unsafe extern "C" fn(*mut u32, u32, u32) -> *mut u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn base_construct(storage: *mut u32, first: u32, second: u32) -> *mut u32 {
    let construct: BaseConstruct = core::mem::transmute(0x081d_6380usize);
    construct(storage, first, second)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_base_construct(storage: *mut u32, _first: u32, _second: u32) -> *mut u32 {
    storage
}

/// Host seam for unported `FUN_081d6380`.
#[cfg(not(target_os = "none"))]
pub static mut BASE_CONSTRUCT: BaseConstruct = missing_base_construct;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn base_construct(storage: *mut u32, first: u32, second: u32) -> *mut u32 {
    BASE_CONSTRUCT(storage, first, second)
}

/// Constructs the derived object in caller-provided storage.
///
/// # Safety
/// The base constructor's returned pointer must designate a writable,
/// word-aligned first word. The retail code performs no NULL or bounds checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn derived_object_construct(
    storage: *mut u32,
    first: u32,
    second: u32,
) -> *mut u32 {
    let object = base_construct(storage, first, second);
    object.write_volatile(DERIVED_OBJECT_VTABLE);
    object
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut SEEN: (*mut u32, u32, u32) = (ptr::null_mut(), 0, 0);
    static mut RETURNED: *mut u32 = ptr::null_mut();

    unsafe extern "C" fn recording_base_construct(storage: *mut u32, first: u32, second: u32) -> *mut u32 {
        SEEN = (storage, first, second);
        RETURNED
    }

    #[test]
    fn forwards_constructor_registers_and_installs_derived_vtable_on_returned_object() {
        let _guard = TEST_LOCK.lock();
        let mut storage = [0x1111_1111u32; 2];
        let mut returned = [0x2222_2222u32; 2];

        unsafe {
            SEEN = (ptr::null_mut(), 0, 0);
            RETURNED = returned.as_mut_ptr();
            BASE_CONSTRUCT = recording_base_construct;

            let result = derived_object_construct(storage.as_mut_ptr(), 0x1234_5678, 0x9abc_def0);

            assert_eq!(result, returned.as_mut_ptr());
            assert_eq!(SEEN, (storage.as_mut_ptr(), 0x1234_5678, 0x9abc_def0));
            assert_eq!(storage, [0x1111_1111, 0x1111_1111]);
            assert_eq!(returned, [DERIVED_OBJECT_VTABLE, 0x2222_2222]);

            BASE_CONSTRUCT = missing_base_construct;
            RETURNED = ptr::null_mut();
        }
    }
}
