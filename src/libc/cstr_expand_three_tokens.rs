//! Three-token C-string expansion — `FUN_0809fbc8` @ 0x0809fbc8.
//!
//! True span: 172 bytes through 0x0809fc74 (168 instruction bytes and the
//! table-address literal at 0x0809fc70); the next function starts with PUSH.
//! Verified outgoing calls: two plain BLs, zero predicated BLs: strlen at
//! 0x08392478 and strcpy at 0x08030ff4, both already ported.
//! Each of three runtime table strings starts with a match byte followed by
//! its NUL-terminated replacement. Reserve strlen(table[0]) bytes, then copy
//! ordinary bytes or whole replacements while output is below the unsigned
//! destination + capacity - reserve limit. Always terminate and return dst.
//! The caller at 0x08123834 uses this for XML key/string text. Table contents
//! are deliberately not guessed: 0x089cb224 is read at runtime, not treated
//! as an immutable literal in the on-disk image.
//! Deviations: hosts supply native-width table pointers; target pointers are
//! four bytes apart. Volatile loads retain the source-before-limit read and
//! prevent the output scan from becoming an unavailable libc builtin.

#[cfg(not(target_os = "none"))]
pub static mut CSTR_EXPANSION_TABLE: *const *const u8 = core::ptr::null();

/// # Safety
/// Source and the three table entries must be readable NUL-terminated strings.
/// Destination must cover every write (including the unconditional terminator).
/// Capacity uses wrapping target address arithmetic, not a checked slice bound;
/// replacement lengths are not individually checked. Strings must not overlap.
/// The ported strcpy may read three bytes beyond a replacement's terminator.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cstr_expand_three_tokens(
    mut source: *const u8, dst: *mut u8, capacity: u32,
) -> *mut u8 {
    #[cfg(target_os = "none")]
    let table = 0x089c_b224usize as *const *const u8;
    #[cfg(not(target_os = "none"))]
    let table = CSTR_EXPANSION_TABLE;
    let reserve = super::strlen::strlen(table.read_volatile());
    let limit = (dst as usize).wrapping_add(capacity as usize).wrapping_sub(reserve);
    let mut output = dst;
    loop {
        let byte = source.read_volatile();
        if byte == 0 || output as usize >= limit {
            output.write(0);
            return dst;
        }
        let mut index = 0;
        while index < 3 {
            let token = table.add(index).read_volatile();
            if byte == token.read_volatile() {
                super::strcpy::strcpy(output, token.add(1));
                while output.read_volatile() != 0 {
                    output = output.add(1);
                }
                break;
            }
            index += 1;
        }
        if index == 3 {
            output.write(byte);
            output = output.add(1);
        }
        source = source.add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    extern crate std;

    #[test]
    fn expansion_boundaries_and_first_match_precedence() {
        let _lock = LOCK.lock();
        // Padded for the aligned strcpy word load, including an empty replacement.
        let tokens: [&[u8]; 3] = [b"&amp;\0\0\0\0", b"<lt;\0\0\0\0", b">\0\0\0\0"];
        let pointers = tokens.map(|token| token.as_ptr());
        unsafe { CSTR_EXPANSION_TABLE = pointers.as_ptr(); }
        for alignment in 0..4 {
            for capacity in 5..=24 {
                for input in [b"\0".as_slice(), b"abc\0", b"&<>Z\0", b"\xff&x\0"] {
                    let mut expected = std::vec::Vec::new();
                    for &byte in input {
                        if byte == 0 || expected.len() >= capacity - 5 { break; }
                        if let Some(token) = tokens.iter().find(|token| token[0] == byte) {
                            expected.extend(token[1..].iter().copied().take_while(|&b| b != 0));
                        } else {
                            expected.push(byte);
                        }
                    }
                    expected.push(0);
                    let mut buffer = [0xa5; 64];
                    let dst = unsafe { buffer.as_mut_ptr().add(alignment) };
                    assert_eq!(unsafe { cstr_expand_three_tokens(input.as_ptr(), dst, capacity as u32) }, dst);
                    assert_eq!(&buffer[alignment..alignment + expected.len()], expected.as_slice());
                    assert!(buffer[..alignment].iter().all(|&byte| byte == 0xa5));
                    assert!(buffer[alignment + expected.len()..].iter().all(|&byte| byte == 0xa5));
                }
            }
        }
        let duplicates = [b"&first\0\0\0\0".as_ptr(), b"&second\0\0\0\0".as_ptr(), b">\0\0\0\0".as_ptr()];
        unsafe { CSTR_EXPANSION_TABLE = duplicates.as_ptr(); }
        let mut buffer = [0xa5; 32];
        unsafe { cstr_expand_three_tokens(b"&\0".as_ptr(), buffer.as_mut_ptr(), 32); }
        assert_eq!(&buffer[..6], b"first\0");
        unsafe { CSTR_EXPANSION_TABLE = core::ptr::null(); }
    }
}
