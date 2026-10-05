//! Derived twelve-byte-state constructor — FUN_081b9710 @ 0x081b9710.
//!
//! True extent: 24 bytes, [0x081b9710, 0x081b9728): 20 code bytes and
//! vtable literal 0x0898c58c at 0x081b9724. The next function starts with
//! cmp r0,#0 at 0x081b9728. Whole-image aligned A32 decoding finds two
//! inbound plain BLs (0x081861ec, 0x081b9678), zero predicated inbound BLs,
//! one outbound plain BL to 0x081b126c, and zero predicated outbound BLs.
//!
//! Call the base constructor, overwrite the returned object's vtable, and
//! return its pointer unchanged. Raw base code constructs the framework root,
//! installs 0x0898b6f8, and clears bytes +5..+15 then +4. Both callers install
//! further derived vtables. The concrete class and state meanings are unknown;
//! the name describes only the verified twelve-byte base state at +4..+15.
//!
//! Deliberate deviation: hosts inject the unported base through an explicit
//! ABI seam; target builds call the verified retail address directly.

const VTABLE: u32 = 0x0898_c58c;
type BaseConstruct = unsafe extern "C" fn(*mut u32) -> *mut u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn base_construct(storage: *mut u32) -> *mut u32 {
    core::mem::transmute::<usize, BaseConstruct>(0x081b_126c)(storage)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_base_construct(_storage: *mut u32) -> *mut u32 {
    panic!("retailOS base constructor at 0x081b126c is not installed")
}

#[cfg(not(target_os = "none"))]
pub static mut TWELVE_BYTE_STATE_BASE_CONSTRUCT: BaseConstruct = missing_base_construct;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn base_construct(storage: *mut u32) -> *mut u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(TWELVE_BYTE_STATE_BASE_CONSTRUCT))(storage)
}

/// Install the derived vtable after constructing the twelve-byte base state.
///
/// # Safety
/// The base must be available and accept `storage`. Its returned pointer must
/// refer to a writable, word-aligned object of at least 16 bytes. RetailOS
/// provides no null check; callers must provide storage for any derived fields.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn twelve_byte_state_derived_construct(storage: *mut u32) -> *mut u32 {
    let object = base_construct(storage);
    object.write_volatile(VTABLE);
    object
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    // Binary-derived model of the unported base's observable writes.
    unsafe extern "C" fn initialize_base(storage: *mut u32) -> *mut u32 {
        storage.write(0x0898_b6f8);
        for offset in 5..16 {
            storage.cast::<u8>().add(offset).write(0);
        }
        storage.cast::<u8>().add(4).write(0);
        storage
    }

    #[test]
    fn dirty_storage_and_reconstruction_preserve_derived_state_and_guards() {
        let _lock = LOCK.lock();
        unsafe {
            let previous = TWELVE_BYTE_STATE_BASE_CONSTRUCT;
            TWELVE_BYTE_STATE_BASE_CONSTRUCT = initialize_base;
            for fill in [0xffff_ffff, 0xa5a5_a5a5, 0] {
                let mut words = [fill; 8];
                let object = words.as_mut_ptr().add(1);
                for _ in 0..2 {
                    assert_eq!(twelve_byte_state_derived_construct(object), object);
                    assert_eq!(words, [fill, VTABLE, 0, 0, 0, fill, fill, fill]);
                    object.add(2).write(fill);
                }
            }
            TWELVE_BYTE_STATE_BASE_CONSTRUCT = previous;
        }
    }
}
