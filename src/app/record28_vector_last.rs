//! Last 28-byte record in an owner's backing vector.
//!
//! Original: `FUN_08267f88` at `0x08267f88`, 16 bytes, ending before the
//! independently entered prologue at `0x08267f98`. Raw words decode as
//! `ldr r0,[r0,#4]; ldr r0,[r0,#0x48]; sub r0,r0,#0x1c; bx lr`.
//! Whole-image aligned A32 decoding verifies two plain inbound BL sites
//! (`0x082233d0`, `0x08267e80`), zero predicated inbound BLs, and no calls
//! inside this leaf. The append caller uses 28-byte vector elements and
//! updates the end word at +0x48; the property caller writes into the result.
//!
//! Loads the backing pointer at owner +4 and returns its end word minus 28.
//! No deliberate deviations: pointer fields stay 32-bit on the host, and
//! subtraction wraps without null or empty-vector checks. Record kind and
//! field identities remain unknown.

/// # Safety
/// `owner` must be word-aligned and readable through +4; its target-width
/// backing pointer must be word-aligned and readable through +0x48.
/// The returned address is not guaranteed to identify a live record.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record28_vector_last(owner: *const u32) -> *mut u32 {
    let backing = unsafe { owner.add(1).read() } as usize as *const u32;
    let end = unsafe { backing.add(0x48 / 4).read() };
    end.wrapping_sub(28) as usize as *mut u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_backing_end_and_preserves_unchecked_word_arithmetic() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::RECORD28_VECTOR_LAST, 0x200,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("app/record28_vector_last"));
            return;
        };
        let backing = unsafe { slab.add(0x40).cast::<u32>() };
        let mut owner = [0xdead_beefu32, backing as usize as u32, 0xabcdef01];
        let end_word = unsafe { backing.add(0x48 / 4) };
        // One element, several elements, an empty range, and address underflow.
        let start = slab as usize as u32 + 0x100;
        for (end, expected) in [
            (start + 28, start), (start + 84, start + 56),
            (start, start - 28), (0, 0xffff_ffe4),
            (27, 0xffff_ffff), (28, 0), (u32::MAX, u32::MAX - 28),
        ] {
            unsafe { end_word.write(end); }
            assert_eq!(unsafe { record28_vector_last(owner.as_ptr()) } as usize, expected as usize);
            assert_eq!(unsafe { end_word.read() }, end);
        }
        // Changing the backing object must change which end word is loaded.
        let other = unsafe { slab.add(0x100).cast::<u32>() };
        unsafe { other.add(0x48 / 4).write(0x8000_001c); }
        owner[1] = other as usize as u32;
        assert_eq!(unsafe { record28_vector_last(owner.as_ptr()) } as usize, 0x8000_0000);
        assert_eq!(owner[0], 0xdead_beef);
        assert_eq!(owner[2], 0xabcdef01);
    }
}
