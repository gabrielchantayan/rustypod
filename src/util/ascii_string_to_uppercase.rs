//! NUL-terminated ASCII lowercase-to-uppercase string copy — thunk
//! `thunk_FUN_082e474c` @ 0x082e4730 (4 bytes; 4 verified plain `bl` call
//! sites, zero predicated `bl` call sites).
//!
//! Raw word `ea000005` at 0x082e4730 is an unconditional branch to the real
//! body at 0x082e474c. The next separately entered function begins at
//! 0x082e4764, so this thunk's true extent is one word. The forwarded body
//! copies source bytes through the destination, subtracting 0x20 only for
//! ASCII `a` through `z`, then writes the NUL terminator. Source is read
//! before destination is written on every iteration, including when regions
//! overlap. Deliberate deviation: volatile byte accesses prevent LLVM from
//! replacing this freestanding routine with a libc string primitive.

/// Copies a NUL-terminated ASCII string to `destination`, uppercasing only
/// lowercase ASCII bytes.
///
/// # Safety
/// `source` must be readable through its NUL terminator and `destination`
/// must be writable for the resulting bytes. As on retailOS, overlapping
/// ranges follow the byte-at-a-time read-then-write order.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ascii_string_to_uppercase(destination: *mut u8, source: *const u8) {
    let mut destination = destination;
    let mut source = source;

    loop {
        let byte = unsafe { source.read_volatile() };
        if byte == 0 {
            unsafe { destination.write_volatile(0) };
            return;
        }
        let folded = if byte.wrapping_sub(b'a') <= b'z' - b'a' {
            byte.wrapping_sub(0x20)
        } else {
            byte
        };
        source = unsafe { source.add(1) };
        unsafe { destination.write_volatile(folded) };
        destination = unsafe { destination.add(1) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn copy_into(destination: *mut u8, source: *const u8) {
        unsafe { ascii_string_to_uppercase(destination, source) };
    }

    #[test]
    fn folds_lowercase_and_preserves_other_bytes() {
        let source = b"aZ0- z\x80\0";
        let mut destination = [0xff; 16];
        unsafe { copy_into(destination.as_mut_ptr(), source.as_ptr()) };
        assert_eq!(&destination[..8], b"AZ0- Z\x80\0");
        assert_eq!(destination[8], 0xff);
    }

    #[test]
    fn stops_at_the_first_nul() {
        let source = b"a\0z";
        let mut destination = [0xff; 4];
        unsafe { copy_into(destination.as_mut_ptr(), source.as_ptr()) };
        assert_eq!(destination, [b'A', 0, 0xff, 0xff]);
    }

    #[test]
    fn backward_overlap_reads_source_before_each_write() {
        let mut bytes = [0xff, b'a', b'b', b'c', 0];
        let source = unsafe { bytes.as_ptr().add(1) };
        unsafe { copy_into(bytes.as_mut_ptr(), source) };
        assert_eq!(bytes, [b'A', b'B', b'C', 0, 0]);
    }
}
