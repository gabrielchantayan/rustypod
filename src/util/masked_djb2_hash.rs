//! Masked DJB2 byte hash — `FUN_08075fc0` @ **0x08075fc0**.
//! True extent: **48 bytes**, `0x08075fc0..0x08075ff0`: 44 instruction
//! bytes and the seed literal at `0x08075fec`; the next function starts
//! with PUSH at `0x08075ff0`. Raw A32 decoding verifies two incoming
//! unconditional BLs (`0x080b25e4`, `0x080cb39c`), zero predicated BLs,
//! and zero outgoing BLs. The loop's `blt` is B with condition LT, not BL.
//!
//! Starting at 5381, multiply by 33, add an unsigned byte, and clear bits
//! 16..22 after EACH step, with 32-bit wrapping arithmetic. The signed
//! length comparison returns the seed without reading for length <= 0.
//! Callers use the result for hash-table insertion and lookup.
//!
//! Deliberate deviations: ordinary Rust control flow replaces predicated
//! ARM instructions; there are no semantic deviations or callee seams.

/// Hash exactly `length` bytes, or return 5381 for a nonpositive length.
///
/// # Safety
/// For positive `length`, `bytes` must point to that many readable bytes.
/// No pointer validity is required for nonpositive lengths.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn masked_djb2_hash(bytes: *const u8, length: i32) -> u32 {
    let mut hash = 5381u32;
    let mut index = 0i32;
    while index < length {
        hash = hash.wrapping_mul(33).wrapping_add(*bytes.add(index as usize) as u32)
            & 0xff80_ffff;
        index += 1;
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::masked_djb2_hash;

    fn reference(bytes: &[u8]) -> u32 {
        bytes.iter().fold(5381u64, |hash, &byte| {
            ((hash * 33 + byte as u64) % (1u64 << 32)) & 0xff80_ffff
        }) as u32
    }

    #[test]
    fn nonpositive_lengths_never_read() {
        for length in [i32::MIN, -1, 0] {
            assert_eq!(unsafe { masked_djb2_hash(core::ptr::null(), length) }, 5381);
        }
    }

    #[test]
    fn unsigned_bytes_nuls_alignments_and_wrapping() {
        let mut storage = [0u8; 1028];
        for (index, byte) in storage.iter_mut().enumerate() {
            *byte = index.wrapping_mul(197) as u8;
        }
        for alignment in 0..4 {
            for length in 0..=1024 {
                let bytes = &storage[alignment..alignment + length];
                assert_eq!(unsafe { masked_djb2_hash(bytes.as_ptr(), length as i32) },
                    reference(bytes), "alignment={alignment}, length={length}");
            }
        }
    }

    #[test]
    fn masks_each_step_not_just_final_result() {
        // Two zero bytes distinguish per-step masking from ordinary DJB2.
        assert_eq!(unsafe { masked_djb2_hash([0, 0].as_ptr(), 2) }, 27205);
        assert_eq!(unsafe { masked_djb2_hash([255].as_ptr(), 1) }, 46756);
        // Embedded NUL is data, not a terminator; bytes after length are ignored.
        let bytes = [b'A', 0, b'B', 255];
        assert_eq!(unsafe { masked_djb2_hash(bytes.as_ptr(), 3) }, reference(&bytes[..3]));
        assert_ne!(reference(&bytes[..3]), reference(&bytes[..1]));
    }
}
