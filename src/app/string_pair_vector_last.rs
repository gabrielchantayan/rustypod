//! Last two-string record in an owner's backing vector.
//!
//! Original: `FUN_08267f78` at `0x08267f78`, **16 bytes**, ending at the
//! independently entered getter at `0x08267f88`. Raw words are e5900004,
//! e590003c, e2400010, e12fff1e: two loads, subtract 16, return.
//! Whole-image aligned A32 decoding verifies two plain inbound BL sites
//! (0x082233ac and 0x082681cc), zero predicated inbound BLs, and zero
//! plain or predicated calls inside this leaf.
//!
//! Loads the backing pointer at owner +4, then the pair-vector end word
//! at backing +0x3c, and returns end minus 16. The append caller at
//! 0x082680d8 uses 16-byte records containing StringObjects at +0/+8;
//! the property caller at 0x08223254 assigns the second string at +8.
//! No deliberate deviations: target pointers remain u32 words on hosts,
//! and subtraction wraps without null or empty-vector checks.

/// # Safety
/// `owner` must be word-aligned and readable through +4. Its target-width
/// backing pointer must be word-aligned and readable through +0x3c.
/// The returned address need not identify a live record.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_pair_vector_last(owner: *const u32) -> *mut u32 {
    let backing = unsafe { owner.add(1).read() } as usize as *const u32;
    let end = unsafe { backing.add(0x3c / 4).read() };
    end.wrapping_sub(16) as usize as *mut u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_pair_end_with_empty_and_wrapping_addresses() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::STRING_PAIR_VECTOR_LAST, 0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("app/string_pair_vector_last"));
            return;
        };
        unsafe {
            let backing = slab.add(0x40).cast::<u32>();
            let mut owner = [0xdead_beef, backing as usize as u32, 0xabcdef01];
            let start = slab as usize as u32 + 0x200;
            backing.add(0x38 / 4).write(start);
            backing.add(0x40 / 4).write(0xbad0_bad0);
            for (end, expected) in [
                (start + 16, start), (start + 48, start + 32),
                (start, start - 16), (0, 0xffff_fff0),
                (15, 0xffff_ffff), (16, 0), (u32::MAX, u32::MAX - 16),
            ] {
                backing.add(0x3c / 4).write(end);
                assert_eq!(string_pair_vector_last(owner.as_ptr()) as usize, expected as usize);
                assert_eq!(backing.add(0x3c / 4).read(), end);
            }
            let other = slab.add(0x100).cast::<u32>();
            other.add(0x3c / 4).write(0x8000_0010);
            owner[1] = other as usize as u32;
            assert_eq!(string_pair_vector_last(owner.as_ptr()) as usize, 0x8000_0000);
            assert_eq!(owner[0], 0xdead_beef);
            assert_eq!(owner[2], 0xabcdef01);
        }
    }
}
