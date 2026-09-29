//! Fixed-length ASCII lowercase-to-uppercase copy — `FUN_082e4764` @
//! 0x082e4764 (52 bytes; 2 verified plain `bl` call sites, zero predicated
//! `bl` call sites).
//!
//! Raw ARM words from 0x082e4764..0x082e4794 establish the full body; the
//! `mov r1,#2` at 0x082e4798 begins the next real function. Starting with a
//! zero byte count, retailOS reads and increments the source, folds only ASCII
//! `a` through `z` by subtracting 0x20, writes and increments the destination,
//! then repeats while the signed count remains below `len`. Every byte is read
//! before its corresponding destination write, including for overlapping
//! ranges. Deliberate deviation: volatile accesses prevent LLVM from replacing
//! this freestanding routine with a libc copy primitive.

/// Copies exactly `len` bytes to `destination`, uppercasing lowercase ASCII.
///
/// # Safety
/// `source` must be readable and `destination` writable for `len` bytes when
/// `len` is positive. As on retailOS, overlap observes forward byte-at-a-time
/// read-before-write order. Non-positive lengths copy no bytes.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ascii_uppercase_copy_n(destination: *mut u8, source: *const u8, len: i32) {
    let mut copied = 0i32;
    while copied < len {
        let byte = unsafe { source.add(copied as usize).read_volatile() };
        let folded = if byte.wrapping_sub(b'a') <= b'z' - b'a' {
            byte.wrapping_sub(0x20)
        } else {
            byte
        };
        unsafe { destination.add(copied as usize).write_volatile(folded) };
        copied = copied.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_only_lowercase_within_the_requested_length() {
        let source = [b'`', b'a', b'z', b'{', 0, 0x80, 0xff, b'q'];
        let mut destination = [0xa5; 8];
        unsafe { ascii_uppercase_copy_n(destination.as_mut_ptr(), source.as_ptr(), 7) };
        assert_eq!(destination, [b'`', b'A', b'Z', b'{', 0, 0x80, 0xff, 0xa5]);
    }

    #[test]
    fn non_positive_lengths_leave_the_destination_untouched() {
        let source = [b'a'; 4];
        for len in [0, -1, i32::MIN] {
            let mut destination = [0xa5; 4];
            unsafe { ascii_uppercase_copy_n(destination.as_mut_ptr(), source.as_ptr(), len) };
            assert_eq!(destination, [0xa5; 4], "len {len}");
        }
    }

    #[test]
    fn forward_overlap_reads_then_writes_each_byte() {
        let mut bytes = [b'a', b'b', b'c', b'd', 0xff];
        let source = bytes.as_ptr();
        unsafe { ascii_uppercase_copy_n(bytes.as_mut_ptr().add(1), source, 4) };
        assert_eq!(bytes, [b'a', b'A', b'A', b'A', b'A']);
    }
}
