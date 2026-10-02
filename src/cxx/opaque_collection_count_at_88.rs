//! Count accessor for an otherwise unrecovered collection-like object.
//!
//! `opaque_collection_count_at_88` — original: `FUN_08298ac0` @
//! 0x08298ac0 (true size 8 bytes; two inbound plain BL calls at 0x081b2704
//! and 0x0829d5b0, zero predicated BL calls, zero internal calls).
//!
//! Raw words are 0xe5900088 (`ldr r0,[r0,#0x88]`) and 0xe12fff1e
//! (`bx lr`). The next real function starts at 0x08298ac8 with
//! `ldr r2,[r1,#0xb4]` and is independently called at 0x08124270.
//! Return the aligned 32-bit count at object +0x88 without validation.
//! Both callers use it as a signed loop bound for collection entries;
//! the concrete entry category remains unrecovered. All result bits are
//! preserved. Deliberate deviations: none behaviorally; LLVM may add a
//! frame prologue/epilogue around the load and return.

const ENTRY_COUNT_OFFSET: usize = 0x88;

/// Returns the unchecked collection count word at +0x88.
///
/// # Safety
/// `object` must have a readable, four-byte-aligned u32 at +0x88.
/// No NULL guard or count normalization exists in retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_collection_count_at_88(object: *const u8) -> u32 {
    unsafe { object.add(ENTRY_COUNT_OFFSET).cast::<u32>().read() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_zero_signed_boundaries_and_all_count_bits() {
        let mut object = [0x1357_9bdf_u32; 36];
        object[33] = 0x2468_ace0;
        object[35] = 0xfedc_ba98;
        for count in [0, 1, 0x7fff_ffff, 0x8000_0000, 0xdead_beef, u32::MAX] {
            object[34] = count;
            let before = object;
            assert_eq!(unsafe { opaque_collection_count_at_88(object.as_ptr().cast()) }, count);
            assert_eq!(object, before);
        }
    }

    #[test]
    fn accepts_an_interior_object_with_only_the_required_words() {
        let mut storage = [0_u32; 36];
        storage[34] = 17;
        storage[35] = 29;
        let object = unsafe { storage.as_ptr().add(1).cast() };
        assert_eq!(unsafe { opaque_collection_count_at_88(object) }, 29);
    }
}
