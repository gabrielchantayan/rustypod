//! Twelve-byte-state base constructor — FUN_081b126c @ 0x081b126c.
//!
//! True extent: 76 bytes, [0x081b126c, 0x081b12b8): 72 instruction
//! bytes and vtable literal 0x0898b6f8 at 0x081b12b4. The next function
//! begins with cmp r0,#0. Whole-image aligned A32 decoding verifies two
//! incoming plain BLs (0x081b9714, 0x08288fbc), no predicated incoming BLs,
//! one outgoing plain BL (0x081b1270 to framework_object_construct), and
//! no predicated outgoing BLs.
//!
//! Construct the framework root, install this base's vtable, clear bytes
//! +5..+15 followed by +4, and return the root constructor's pointer.
//! Concrete class and byte meanings remain unknown; the semantic name
//! describes the verified twelve-byte state. No deliberate deviations:
//! volatile stores retain the original byte widths and initialization order.

use crate::cxx::observable_array::framework_object_construct;

pub const TWELVE_BYTE_STATE_BASE_VTABLE: u32 = 0x0898_b6f8;

/// Initialize the vtable and twelve state bytes without touching derived fields.
///
/// # Safety
/// `storage` must address at least 16 writable, word-aligned bytes.
/// RetailOS performs no null check.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn twelve_byte_state_base_construct(storage: *mut u32) -> *mut u32 {
    let object = framework_object_construct(storage.cast()).cast::<u32>();
    object.write_volatile(TWELVE_BYTE_STATE_BASE_VTABLE);
    for offset in 5..16 {
        object.cast::<u8>().add(offset).write_volatile(0);
    }
    object.cast::<u8>().add(4).write_volatile(0);
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirty_state_is_cleared_without_touching_guards_or_derived_fields() {
        for fill in [0xffff_ffff, 0xa5a5_a5a5, 0x0102_0304, 0] {
            let mut words = [fill; 8];
            let object = unsafe { words.as_mut_ptr().add(1) };
            for _ in 0..2 {
                let returned = unsafe { twelve_byte_state_base_construct(object) };
                assert_eq!(returned, object);
                assert_eq!(words, [fill, TWELVE_BYTE_STATE_BASE_VTABLE, 0, 0, 0, fill, fill, fill]);
                unsafe { object.add(1).write(fill); object.add(3).write(fill); }
            }
        }
    }
}
