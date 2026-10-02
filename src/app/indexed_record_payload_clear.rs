//! Indexed record payload clear — `FUN_0827cb9c` @ 0x0827cb9c.
//!
//! Raw ARM establishes 48 bytes, 0x0827cb9c..0x0827cbcc, ending in BX lr;
//! the next function starts at 0x0827cbcc with PUSH {r4,lr}. Whole-image
//! aligned A32 decoding finds two incoming plain BLs (0x0827cc4c and
//! 0x0827ceb0), zero predicated incoming BLs, and zero outgoing calls.
//!
//! Compute owner + index * 56 and clear eight words at offsets 0x20..0x3c.
//! The constructor and bulk-reset callers each visit indices 0, 1, and 2.
//! The concrete record type and payload interpretation remain unknown.
//! Deliberate implementation deviation: volatile word stores prevent LLVM
//! from replacing the eight ordered ARM stores with a memset call. No
//! behavioral deviations for valid writable owner/index pairs.

/// Clears the eight-word payload of an indexed 56-byte record.
///
/// # Safety
///
/// `owner` must be four-byte aligned, and the nonwrapping byte range
/// `owner + index * 56 + 32 .. owner + index * 56 + 64` must lie within
/// its writable allocation. The function does not validate the index.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_record_payload_clear(owner: *mut u32, index: u32) {
    let payload = owner.add(index as usize * 14 + 8);
    payload.write_volatile(0);
    payload.add(1).write_volatile(0);
    payload.add(2).write_volatile(0);
    payload.add(3).write_volatile(0);
    payload.add(4).write_volatile(0);
    payload.add(5).write_volatile(0);
    payload.add(6).write_volatile(0);
    payload.add(7).write_volatile(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_exact_payload_for_first_middle_last_and_unchecked_indices() {
        for index in [0u32, 1, 2, 5] {
            let mut owner = core::array::from_fn::<_, 96, _>(|word| 0xa500_0000 | word as u32);
            let mut expected = owner;
            // Independent byte-range reference from the raw STR offsets.
            for (word, value) in expected.iter_mut().enumerate() {
                let byte_offset = word * 4;
                if byte_offset >= index as usize * 56 + 32
                    && byte_offset < index as usize * 56 + 64 {
                    *value = 0;
                }
            }
            unsafe { indexed_record_payload_clear(owner.as_mut_ptr(), index) };
            assert_eq!(owner, expected, "index {index}");
        }
    }

    #[test]
    fn constructor_sequence_preserves_headers_and_trailing_state() {
        let mut owner = [u32::MAX; 46];
        for index in 0..3 {
            unsafe { indexed_record_payload_clear(owner.as_mut_ptr(), index) };
        }
        for (word, value) in owner.iter().enumerate() {
            let cleared = (8..16).contains(&word)
                || (22..30).contains(&word) || (36..44).contains(&word);
            assert_eq!(*value, if cleared { 0 } else { u32::MAX }, "word {word}");
        }
    }
}
