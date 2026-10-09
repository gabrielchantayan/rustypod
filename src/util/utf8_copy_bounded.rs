//! Bounded UTF-8 byte copy — `FUN_080f5238` @ 0x080f5238.
//! True extent: 168 bytes, [0x080f5238, 0x080f52e0); next raw ARM
//! instruction is the next function's PUSH. Whole-image word decoding finds
//! two inbound plain BL sites (0x0811dd70, 0x0828fe38), zero predicated;
//! the body has zero outgoing plain or predicated BL instructions.
//!
//! Copy at most capacity bytes, stopping after copying NUL. Track the last
//! non-continuation byte (initially destination[0]); classify its expected
//! width as 1, 2, 3, 4, or 0. If its end reaches or exceeds capacity, replace
//! that byte with NUL and return its offset plus one; otherwise return the
//! number of bytes copied. This is not UTF-8 validation: malformed bytes,
//! premature NUL, and missing continuations retain the firmware's behavior.
//! Deliberate deviations: native pointer arithmetic supports host fixtures;
//! volatile byte accesses prevent LLVM substituting a libc copy intrinsic.

/// # Safety
/// For nonzero capacity, destination must be writable for capacity bytes;
/// source must be readable through the first NUL or capacity bytes. Memory
/// must not wrap the target address space. Forward-copy aliasing is preserved.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn utf8_copy_bounded(
    destination: *mut u8,
    source: *const u8,
    capacity: u32,
) -> u32 {
    if capacity == 0 { return 0; }
    let mut copied = 0u32;
    let mut last_lead = 0u32;
    loop {
        let byte = source.add(copied as usize).read_volatile();
        if byte != 0 && byte & 0xc0 != 0x80 { last_lead = copied; }
        destination.add(copied as usize).write_volatile(byte);
        copied += 1;
        if byte == 0 || copied == capacity { break; }
    }
    let lead = destination.add(last_lead as usize).read_volatile();
    let width = if lead & 0x80 == 0 { 1 }
        else if lead & 0xe0 == 0xc0 { 2 }
        else if lead & 0xf0 == 0xe0 { 3 }
        else if lead & 0xf8 == 0xf0 { 4 }
        else { 0 };
    if last_lead + width >= capacity {
        destination.add(last_lead as usize).write_volatile(0);
        copied = last_lead + 1;
    }
    copied
}

#[cfg(test)]
mod tests {
    use super::utf8_copy_bounded;

    fn check(source: &[u8], capacity: u32, expected: &[u8], returned: u32) {
        let mut output = [0xa5u8; 16];
        let result = unsafe { utf8_copy_bounded(output.as_mut_ptr().add(1), source.as_ptr(), capacity) };
        assert_eq!(result, returned);
        assert_eq!(&output[1..1 + expected.len()], expected);
        assert_eq!(output[0], 0xa5);
        assert!(output[1 + capacity as usize..].iter().all(|&b| b == 0xa5));
    }

    #[test]
    fn zero_capacity_does_not_access_null() {
        assert_eq!(unsafe { utf8_copy_bounded(core::ptr::null_mut(), core::ptr::null(), 0) }, 0);
    }

    #[test]
    fn nul_ascii_and_no_padding() {
        check(b"\0", 4, &[0, 0xa5, 0xa5, 0xa5], 1);
        check(b"abc\0", 8, &[b'a', b'b', b'c', 0, 0xa5], 4);
        check(b"abc", 3, b"ab\0", 3);
        check(b"a", 1, b"\0", 1);
    }

    #[test]
    fn each_multibyte_width_requires_room_for_terminator() {
        for character in [&[0xc2, 0xa2][..], &[0xe2, 0x82, 0xac][..], &[0xf0, 0x9f, 0x98, 0x80][..]] {
            let mut source = [0u8; 8];
            source[0] = b'A';
            source[1..1 + character.len()].copy_from_slice(character);
            for capacity in 2..=1 + character.len() {
                let mut expected = source[..capacity].to_vec();
                expected[1] = 0;
                check(&source, capacity as u32, &expected, 2);
            }
            check(&source, (2 + character.len()) as u32, &source[..2 + character.len()], (2 + character.len()) as u32);
        }
    }

    #[test]
    fn malformed_sequences_are_not_validated() {
        check(&[0x80, 0x81, 0x82], 3, &[0x80, 0x81, 0x82], 3);
        check(&[0xff, 0x80], 2, &[0xff, 0x80], 2);
        check(&[0xe2, 0, 0xa5], 3, &[0, 0, 0xa5], 1);
        check(&[0xe2, 0, 0xa5, 0xa5], 4, &[0xe2, 0, 0xa5, 0xa5], 2);
        check(&[b'A', 0x80, 0x81], 3, &[b'A', 0x80, 0x81], 3);
    }

    #[test]
    fn forward_overlap_observes_prior_writes() {
        let mut bytes = [b'A', b'B', b'C', b'D', 0xa5];
        let result = unsafe { utf8_copy_bounded(bytes.as_mut_ptr().add(1), bytes.as_ptr(), 4) };
        assert_eq!(result, 4);
        assert_eq!(bytes, [b'A', b'A', b'A', b'A', 0]);
    }
}
