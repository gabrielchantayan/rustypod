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
//! The already-ported base is called directly on both target and host.
//! No deliberate deviations.

const VTABLE: u32 = 0x0898_c58c;
use super::twelve_byte_state_base_construct::twelve_byte_state_base_construct;

/// Install the derived vtable after constructing the twelve-byte base state.
///
/// # Safety
/// `storage` must refer to a writable, word-aligned object of at least
/// 16 bytes. RetailOS provides no null check; callers must provide storage
/// for any derived fields.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn twelve_byte_state_derived_construct(storage: *mut u32) -> *mut u32 {
    let object = twelve_byte_state_base_construct(storage);
    object.write_volatile(VTABLE);
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirty_storage_and_reconstruction_preserve_derived_state_and_guards() {
        unsafe {
            for fill in [0xffff_ffff, 0xa5a5_a5a5, 0] {
                let mut words = [fill; 8];
                let object = words.as_mut_ptr().add(1);
                for _ in 0..2 {
                    assert_eq!(twelve_byte_state_derived_construct(object), object);
                    assert_eq!(words, [fill, VTABLE, 0, 0, 0, fill, fill, fill]);
                    object.add(2).write(fill);
                }
            }
        }
    }
}
