//! `refcounted_buffer_owner_destroy` — `FUN_080aa408` @ 0x080aa408.
//! True extent: 72 bytes, ending before the next function at 0x080aa450.
//! Binary-verified inbound calls: one plain BL, one BLNE, and one BEQ tail
//! entry. Body: five plain BLs, zero predicated BLs, one tail B.
//!
//! NULL returns immediately. Otherwise release the MemH handle slots named
//! by target words +0x18 and +0x1c, free the nullable buffers at +0x20,
//! +0x24, and +0x28, clear the first word, then free the owner with tag 4.
//! The constructor at 0x08044628 allocates 0x44 bytes and sets a reference
//! count at +4; the release entry at 0x08044900 tail-enters here at zero.
//!
//! Deliberate deviation: Rust does not guarantee the final tail branch.
//! Target pointer fields remain u32 words on hosts; existing MemH and tag-4
//! seams implement all callees. Ghidra's expanded heap-free chain is not
//! part of this function.

use crate::heap::memh_handle_release::memh_handle_release;
use crate::heap::veneers::{free_tag4, memh_free_if_nonnull};

/// Destroys the owned handles and buffers without decrementing the owner's count.
///
/// # Safety
/// A non-NULL owner must be an aligned, writable tag-4 allocation of at least
/// 0x44 bytes. Words 6 and 7 contain nullable pointers to readable u32 MemH
/// slots (a non-NULL slot must itself contain a valid nonzero handle pointer).
/// Words 8..=10 contain nullable tag-4 allocations. All releases must be valid
/// in order, including when both slots refer to the same handle.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn refcounted_buffer_owner_destroy(owner: *mut u32) {
    if owner.is_null() {
        return;
    }
    memh_handle_release(owner.add(6).read() as usize as *mut u32);
    memh_handle_release(owner.add(7).read() as usize as *mut u32);
    memh_free_if_nonnull(owner.add(8).read() as usize as *mut u8);
    memh_free_if_nonnull(owner.add(9).read() as usize as *mut u8);
    memh_free_if_nonnull(owner.add(10).read() as usize as *mut u8);
    owner.write(0);
    free_tag4(owner.cast());
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::memh_handle::MEMH_MAGIC;
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::REFCOUNTED_BUFFER_OWNER_DESTROY, 0x1000)
            .map(|p| p as usize)
    });

    #[test]
    fn null_owner_does_not_release_anything() {
        let _heap = mock_heap();
        unsafe { refcounted_buffer_owner_destroy(core::ptr::null_mut()); }
        assert_eq!(free_log().0, 0);
    }

    #[test]
    fn shared_handle_final_release_and_nullable_buffers() {
        let _heap = mock_heap();
        let Some(base) = *SLAB else {
            note_missing_u32_fixture("heap::refcounted_buffer_owner_destroy");
            return;
        };
        unsafe {
            let owner = base as *mut u32;
            let slot = (base + 0x100) as *mut u32;
            let handle = (base + 0x200) as *mut u32;
            for buffer_mask in 0u32..8 {
                for count in [2i16, 3, 1001] {
                    let mut expected = [0x1357_2468u32; 17];
                    expected[6] = slot as usize as u32;
                    expected[7] = slot as usize as u32;
                    for i in 0..3 {
                        expected[8 + i] = if buffer_mask & (1 << i) != 0 {
                            (base + 0x300 + i * 0x100) as u32
                        } else { 0 };
                    }
                    core::ptr::copy_nonoverlapping(expected.as_ptr(), owner, 17);
                    core::ptr::write_bytes(handle, 0, 8);
                    handle.add(1).write(MEMH_MAGIC);
                    handle.cast::<u8>().add(0x18).cast::<i16>().write(count);
                    slot.write(handle as usize as u32);
                    let before = free_log().0;
                    refcounted_buffer_owner_destroy(owner);
                    let destroyed = count == 2;
                    assert_eq!(handle.cast::<u8>().add(0x18).cast::<i16>().read(),
                        if count <= 1000 { count - 2 } else { count });
                    assert_eq!(handle.add(1).read(), if destroyed { 0 } else { MEMH_MAGIC });
                    expected[0] = 0;
                    assert_eq!(core::slice::from_raw_parts(owner, 17), &expected);
                    assert_eq!(free_log(), (before + 1 + buffer_mask.count_ones() as usize
                        + usize::from(destroyed), owner.cast(), 4));
                }
            }
            owner.write(0x1234);
            for i in 6..=10 { owner.add(i).write(0); }
            let before = free_log().0;
            refcounted_buffer_owner_destroy(owner);
            assert_eq!(owner.read(), 0);
            assert_eq!(free_log(), (before + 1, owner.cast(), 4));
        }
    }
}
