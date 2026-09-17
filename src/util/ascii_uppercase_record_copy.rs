//! Copies and uppercases the leading label of a 32-byte record —
//! `FUN_082e26e8` @ 0x082e26e8 (136 bytes; 4 verified plain `bl` call sites,
//! zero predicated `bl` call sites).
//!
//! The raw ARM body occupies 0x082e26e8..0x082e2770; the `push` at
//! 0x082e2770 is the next real function boundary. It calls the unported
//! fixed-length ASCII-uppercase helper at 0x082e4764 for bytes 0..8 and
//! 8..11, then transfers bytes 11..32 with three byte, seven halfword, a
//! repeated halfword-at-20, and one word transfer. Every source unit is read
//! before its destination unit is written, preserving the retail overlap
//! behavior. Deliberate deviation: the two helper calls are transcribed
//! locally rather than creating an unverified Rust seam for 0x082e4764.

/// Copies a 32-byte record, uppercasing ASCII lowercase bytes 0 through 10.
///
/// # Safety
/// `source` must be readable and `destination` writable for 32 bytes. As on
/// retailOS, overlapping ranges observe each individual read-before-write
/// transfer in source order.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ascii_uppercase_record_copy(destination: *mut u8, source: *const u8) {
    for offset in 0..11 {
        let byte = unsafe { source.add(offset).read_volatile() };
        let folded = if byte.wrapping_sub(b'a') <= b'z' - b'a' {
            byte.wrapping_sub(0x20)
        } else {
            byte
        };
        unsafe { destination.add(offset).write_volatile(folded) };
    }

    for offset in [11usize, 12, 13] {
        let byte = unsafe { source.add(offset).read_volatile() };
        unsafe { destination.add(offset).write_volatile(byte) };
    }
    for offset in [14usize, 16, 18, 20, 22, 24, 26, 20] {
        unsafe { copy_two_bytes(destination.add(offset), source.add(offset)) };
    }
    unsafe { copy_four_bytes(destination.add(28), source.add(28)) };
}

unsafe fn copy_two_bytes(destination: *mut u8, source: *const u8) {
    let low = unsafe { source.read_volatile() };
    let high = unsafe { source.add(1).read_volatile() };
    unsafe {
        destination.write_volatile(low);
        destination.add(1).write_volatile(high);
    }
}

unsafe fn copy_four_bytes(destination: *mut u8, source: *const u8) {
    let bytes = unsafe {
        [
            source.read_volatile(),
            source.add(1).read_volatile(),
            source.add(2).read_volatile(),
            source.add(3).read_volatile(),
        ]
    };
    for (offset, byte) in bytes.into_iter().enumerate() {
        unsafe { destination.add(offset).write_volatile(byte) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(destination: &mut [u8], source: &[u8]) {
        for offset in 0..11 {
            let byte = source[offset];
            destination[offset] = if byte.wrapping_sub(b'a') <= b'z' - b'a' {
                byte - 0x20
            } else {
                byte
            };
        }
        destination[11..32].copy_from_slice(&source[11..32]);
    }

    #[test]
    fn folds_only_the_first_eleven_ascii_bytes() {
        let source = *b"aBcdefghijklmNOPQRSTUVWXYZ012345";
        let mut destination = [0xff; 32];
        unsafe { ascii_uppercase_record_copy(destination.as_mut_ptr(), source.as_ptr()) };
        let mut expected = [0; 32];
        reference(&mut expected, &source);
        assert_eq!(destination, expected);
    }

    #[test]
    fn preserves_non_ascii_and_boundary_bytes() {
        let mut source = [0; 32];
        source[..11].copy_from_slice(&[b'`', b'a', b'z', b'{', 0, 0x80, 0xff, b'A', b'0', b'-', b' ']);
        source[11..].fill(0xa5);
        let mut destination = [0xff; 32];
        unsafe { ascii_uppercase_record_copy(destination.as_mut_ptr(), source.as_ptr()) };
        assert_eq!(&destination[..11], &[b'`', b'A', b'Z', b'{', 0, 0x80, 0xff, b'A', b'0', b'-', b' ']);
        assert_eq!(&destination[11..], &[0xa5; 21]);
    }

    #[test]
    fn exact_overlap_is_safe() {
        let mut record = *b"aBcdefghijklmNOPQRSTUVWXYZ012345";
        let source = record;
        unsafe { ascii_uppercase_record_copy(record.as_mut_ptr(), record.as_ptr()) };
        let mut expected = [0; 32];
        reference(&mut expected, &source);
        assert_eq!(record, expected);
    }
}
