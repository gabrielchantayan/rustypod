//! Count accessor on an otherwise unrecovered collection-like object.
//!
//! `opaque_collection_count` — original: `FUN_0829b3c8` @ 0x0829b3c8
//! (8 bytes; **4 direct `bl` call sites**, all unconditional and no predicated
//! forms: 0x08126f50, 0x08126f90, 0x08126fa0, and 0x081273b8).
//!
//! Raw ARM is `ldr r0,[r0,#0x58]; bx lr`; the independently linked next
//! function opens at 0x0829b3d0, so the true extent is exactly 8 bytes.
//! Algorithm: return the 32-bit count word at object +0x58 without a NULL
//! guard. The object class remains unrecovered; callers use this word as the
//! number of entries while clearing the collection. Deliberate deviation:
//! LLVM emits a standard frame prologue/epilogue around the same `ldr` body.

/// Byte offset of the opaque collection's entry-count word.
const ENTRY_COUNT_OFFSET: usize = 0x58;

/// opaque_collection_count — original: `FUN_0829b3c8` @ 0x0829b3c8 (8 bytes).
///
/// Returns the unchecked 32-bit entry count stored at object +0x58.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_collection_count(object: *const u8) -> u32 {
    unsafe { object.add(ENTRY_COUNT_OFFSET).cast::<u32>().read() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_aligned_word_at_offset_0x58() {
        let mut object = [0_u32; 24];
        object[21] = 0x1111_1111;
        object[22] = 0xdead_beef;
        object[23] = 0x2222_2222;

        assert_eq!(unsafe { opaque_collection_count(object.as_ptr().cast()) }, 0xdead_beef);
    }

    #[test]
    fn preserves_all_count_bits() {
        let mut object = [0_u32; 23];
        object[22] = u32::MAX;

        assert_eq!(unsafe { opaque_collection_count(object.as_ptr().cast()) }, u32::MAX);
    }
}
