//! Secondary-count accessor on an otherwise unrecovered collection-like object.
//!
//! `opaque_collection_secondary_count` — original: `FUN_08298af4` @
//! 0x08298af4 (8 bytes; **4 direct `bl` call sites**, all unconditional and
//! no predicated forms: 0x081b2398, 0x081b265c, 0x0829d4f0, and 0x0829d6e0).
//!
//! Raw ARM is `ldr r0,[r0,#0xa0]; bx lr`; the independently linked next
//! function opens at 0x08298afc, so the true extent is exactly 8 bytes.
//! Algorithm: return the 32-bit secondary-entry count at object +0xa0 without
//! a NULL guard. Callers use this word as a loop bound for the collection's
//! secondary entries. Deliberate deviation: LLVM emits a standard frame
//! prologue/epilogue around the same load body.

/// Byte offset of the opaque collection's secondary-entry count word.
const SECONDARY_ENTRY_COUNT_OFFSET: usize = 0xa0;

/// opaque_collection_secondary_count — original: `FUN_08298af4` @ 0x08298af4
/// (8 bytes).
///
/// Returns the unchecked 32-bit secondary-entry count stored at object +0xa0.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_collection_secondary_count(object: *const u8) -> u32 {
    unsafe { object.add(SECONDARY_ENTRY_COUNT_OFFSET).cast::<u32>().read() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_aligned_word_at_offset_0xa0() {
        let mut object = [0_u32; 42];
        object[39] = 0x1111_1111;
        object[40] = 0xdead_beef;
        object[41] = 0x2222_2222;

        assert_eq!(unsafe { opaque_collection_secondary_count(object.as_ptr().cast()) }, 0xdead_beef);
    }

    #[test]
    fn preserves_all_secondary_count_bits() {
        let mut object = [0_u32; 41];
        object[40] = u32::MAX;

        assert_eq!(unsafe { opaque_collection_secondary_count(object.as_ptr().cast()) }, u32::MAX);
    }
}
