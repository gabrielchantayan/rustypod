//! Secondary collection count accessor.
//!
//! `secondary_collection_count` — original `FUN_082a677c` at **0x082a677c**.
//! True size: 8 bytes, ending at the independently called function 0x082a6784.
//! Whole-image aligned A32 decoding verifies two inbound plain BL calls
//! (0x08299a4c, 0x08299bb4), zero predicated BL calls, and no outgoing calls.
//! Raw words e5900038/e12fff1e load the word at receiver + 0x38 and return.
//! Callers use this word as the bound for the collection accessed at +0x34;
//! the collection's domain identity is not recovered. No deliberate deviations.

/// Returns the receiver's secondary collection count without validation.
///
/// # Safety
/// `receiver` must address at least 15 readable, aligned u32 words.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn secondary_collection_count(receiver: *const u32) -> u32 {
    receiver.add(0x38 / 4).read()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_full_count_word_without_touching_receiver() {
        let mut receiver = [0xa5a5_5a5a; 15];
        receiver[3] = 17; // The other collection's count is not this count.
        for count in [0, 1, 17, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
            receiver[14] = count;
            let before = receiver;
            assert_eq!(unsafe { secondary_collection_count(receiver.as_ptr()) }, count);
            assert_eq!(receiver, before);
        }
    }
}
