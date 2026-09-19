//! `tagged_record_storage_address` — original: `FUN_08099b60` @ `0x08099b60`
//! (48 bytes; `0x08099b60..0x08099b90`).
//!
//! # Algorithm
//!
//! The leaf resolves a storage address from a pointer to a base-address word and
//! a descriptor.  It rejects a NULL base-word pointer, a zero base address, a
//! NULL descriptor layout pointer at descriptor word 4, and layouts without
//! flag bit 1 at layout word 1.  Otherwise it returns `base + layout[5]`, with
//! 32-bit wrapping arithmetic.
//!
//! Deliberate deviations: firmware pointers remain `u32` words rather than
//! host-sized pointers, so host fixtures use a low-address slab.
//!
//! Raw osos.dec words establish the 48-byte extent: the next independently
//! linked body begins at `0x08099b90` (`push {r0-r11,lr}`). The body has zero
//! direct `bl` instructions. A whole-image A32 decode finds four inbound plain
//! `bl` calls (`0x082b4c28`, `0x082b4c5c`, `0x082b4c90`, `0x082b4cf8`) and zero
//! predicated `bl` calls.

/// Resolves the selected tagged-record storage address, or returns NULL when
/// the base or tagged layout is unavailable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tagged_record_storage_address(
    base_address_word: *const u32,
    descriptor: *const u32,
) -> *mut u8 {
    if base_address_word.is_null() {
        return core::ptr::null_mut();
    }

    let base = base_address_word.read();
    if base == 0 {
        return core::ptr::null_mut();
    }

    let layout = descriptor.add(4).read() as usize as *const u32;
    if layout.is_null() || layout.add(1).read() & 2 == 0 {
        return core::ptr::null_mut();
    }

    base.wrapping_add(layout.add(5).read()) as usize as *mut u8
}

#[cfg(test)]
mod tests {
    use super::tagged_record_storage_address;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const SLAB_LEN: usize = 0x1000;
    const DESCRIPTOR_OFFSET: usize = 0x20;
    const LAYOUT_OFFSET: usize = 0x80;

    unsafe fn arm_reference(base_address_word: *const u32, descriptor: *const u32) -> u32 {
        if base_address_word.is_null() {
            return 0;
        }
        let base = base_address_word.read();
        if base == 0 {
            return 0;
        }
        let layout = descriptor.add(4).read() as usize as *const u32;
        if layout.is_null() || layout.add(1).read() & 2 == 0 {
            return 0;
        }
        base.wrapping_add(layout.add(5).read())
    }

    #[test]
    fn rejects_each_unavailable_record_state() {
        let Some(slab) = try_map_u32_slab(hints::TAGGED_RECORD_STORAGE_ADDRESS, SLAB_LEN) else {
            note_missing_u32_fixture(module_path!());
            return;
        };
        let base_word = slab.cast::<u32>();
        let descriptor = unsafe { slab.add(DESCRIPTOR_OFFSET).cast::<u32>() };
        let layout = unsafe { slab.add(LAYOUT_OFFSET).cast::<u32>() };

        unsafe {
            assert!(tagged_record_storage_address(core::ptr::null(), core::ptr::null()).is_null());

            base_word.write(0);
            assert!(tagged_record_storage_address(base_word, core::ptr::null()).is_null());

            base_word.write(slab as u32);
            descriptor.add(4).write(0);
            assert!(tagged_record_storage_address(base_word, descriptor).is_null());

            descriptor.add(4).write(layout as u32);
            layout.add(1).write(0);
            assert!(tagged_record_storage_address(base_word, descriptor).is_null());
        }
    }

    #[test]
    fn returns_layout_selected_storage_with_arm_wrapping() {
        let Some(slab) = try_map_u32_slab(hints::TAGGED_RECORD_STORAGE_ADDRESS_RESULT, SLAB_LEN) else {
            note_missing_u32_fixture(module_path!());
            return;
        };
        let base_word = slab.cast::<u32>();
        let descriptor = unsafe { slab.add(DESCRIPTOR_OFFSET).cast::<u32>() };
        let layout = unsafe { slab.add(LAYOUT_OFFSET).cast::<u32>() };

        unsafe {
            descriptor.add(4).write(layout as u32);
            layout.add(1).write(2);
            for (base, offset) in [(slab as u32, 0x180), (0xffff_fff0, 0x20)] {
                base_word.write(base);
                layout.add(5).write(offset);
                assert_eq!(tagged_record_storage_address(base_word, descriptor) as u32,
                           arm_reference(base_word, descriptor));
            }
        }
    }
}
