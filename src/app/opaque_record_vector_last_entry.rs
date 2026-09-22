//! Returns the final 32-byte entry in an opaque record vector.
//!
//! `opaque_record_vector_last_entry` — original: `FUN_08267f60` @
//! **0x08267f60**. Raw ARM establishes the exact **16-byte** extent
//! `0x08267f60..0x08267f70`: `ldr r0,[r0,#4]; ldr r0,[r0,#0x30]; sub r0,r0,#0x20; bx lr`.
//! The separately linked next function begins at `0x08267f70`. Decoding every
//! ARM `B`/`BL` immediate in `osos.dec` finds **three** direct call sites, all
//! unconditional plain `bl` (`0x08213dfc`, `0x082232a0`, and `0x082680a4`);
//! there are no predicated calls or direct tail branches.
//!
//! Algorithm: follow the owner word at `+0x04`, load its vector end pointer at
//! `+0x30`, and return the preceding 32-byte entry. The opaque target pointers
//! remain `u32` so target offsets do not depend on host pointer width. No
//! deliberate deviations.

use core::ptr;

/// Returns the address of the final 32-byte entry in `owner`'s vector.
///
/// # Safety
///
/// `owner_address + 4` and the referenced vector's `+0x30` word must be
/// readable target-width addresses. RetailOS performs neither null nor bounds
/// checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_record_vector_last_entry")]
#[inline(never)]
pub unsafe extern "C" fn opaque_record_vector_last_entry(owner_address: u32) -> u32 {
    let vector_address = unsafe { ptr::read((owner_address as usize + 4) as *const u32) };
    let end_address = unsafe { ptr::read((vector_address as usize + 0x30) as *const u32) };
    end_address.wrapping_sub(0x20)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn returns_the_last_32_byte_vector_entry() {
        let Some(slab) = try_map_u32_slab(hints::OPAQUE_RECORD_VECTOR_LAST_ENTRY, 0x1000) else {
            assert!(note_missing_u32_fixture("app/opaque_record_vector_last_entry"));
            return;
        };
        let owner = slab as *mut u32;
        let vector = unsafe { slab.add(0x100) as *mut u32 };
        let end = unsafe { slab.add(0x300) as *mut u32 };

        unsafe {
            ptr::write(owner.add(1), vector as usize as u32);
            ptr::write(vector.add(0x30 / 4), end as usize as u32);
        }

        assert_eq!(unsafe { opaque_record_vector_last_entry(owner as usize as u32) }, end as usize as u32 - 0x20);
    }

    #[test]
    fn wraps_like_the_arm_subtraction() {
        let Some(slab) = try_map_u32_slab(hints::OPAQUE_RECORD_VECTOR_LAST_ENTRY_WRAP, 0x1000) else {
            assert!(note_missing_u32_fixture("app/opaque_record_vector_last_entry"));
            return;
        };
        let owner = slab as *mut u32;
        let vector = unsafe { slab.add(0x100) as *mut u32 };

        unsafe {
            ptr::write(owner.add(1), vector as usize as u32);
            ptr::write(vector.add(0x30 / 4), 0x10);
        }

        assert_eq!(unsafe { opaque_record_vector_last_entry(owner as usize as u32) }, 0xffff_fff0);
    }
}
