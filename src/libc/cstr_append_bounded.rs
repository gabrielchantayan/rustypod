//! Bounded C-string append — original: `FUN_0803c4d4` @ 0x0803c4d4 (112 bytes,
//! 3 inbound plain `bl` call sites; one outbound predicated `bls`, no outbound
//! plain `bl`; raw-binary decoded).
//!
//! If `dst` is NULL, returns zero. Otherwise, a NULL `src` or `capacity <= 1`
//! returns the full `dst` length through retailOS strlen @ 0x08392478. For a
//! non-NULL source and larger capacity, scans at most `capacity - 1` existing
//! destination bytes, appends as much source as fits, NUL-terminates only after
//! finding the original destination terminator, and returns the resulting
//! bounded destination length. Deliberate deviations: none.

use super::strlen::strlen;

/// Append `src` to `dst` within the retailOS bounded-string contract.
///
/// Load address: 0x0803c4d4. `dst` is NUL-terminated when it is scanned beyond
/// `capacity - 1`; `src` is NUL-terminated when non-NULL.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cstr_append_bounded(
    src: *const u8,
    mut dst: *mut u8,
    capacity: usize,
) -> usize {
    if dst.is_null() {
        return 0;
    }

    if src.is_null() || capacity <= 1 {
        return strlen(dst);
    }

    let mut length = 0usize;
    let limit = capacity - 1;
    while length != limit {
        if *dst == 0 {
            let mut src = src;
            while *src != 0 && length != limit {
                *dst = *src;
                length = length.wrapping_add(1);
                dst = dst.add(1);
                src = src.add(1);
            }
            *dst = 0;
            return length;
        }
        length = length.wrapping_add(1);
        dst = dst.add(1);
    }

    length
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::cstr_append_bounded;
    use core::ptr::null;
    use std::vec;

    fn reference(src: Option<&[u8]>, dst: &mut [u8], capacity: usize) -> usize {
        if src.is_none() || capacity <= 1 {
            return dst.iter().position(|&byte| byte == 0).unwrap();
        }

        let limit = capacity - 1;
        let mut length = 0;
        while length != limit {
            if dst[length] == 0 {
                let src = src.unwrap();
                let mut source_index = 0;
                while src[source_index] != 0 && length != limit {
                    dst[length] = src[source_index];
                    length += 1;
                    source_index += 1;
                }
                dst[length] = 0;
                return length;
            }
            length += 1;
        }
        length
    }

    #[test]
    fn matches_retail_bounded_append_edges() {
        for dst_len in 0..16usize {
            for src_len in 0..16usize {
                for capacity in 2..18usize {
                    let mut src = vec![0u8; src_len + 1];
                    for (index, byte) in src[..src_len].iter_mut().enumerate() {
                        *byte = (index as u8).wrapping_add(1);
                    }
                    let mut actual = vec![0xa5u8; 40];
                    actual[..dst_len].fill(b'd');
                    actual[dst_len] = 0;
                    let mut expected = actual.clone();
                    let expected_len = reference(Some(&src), &mut expected, capacity);
                    let actual_len = unsafe {
                        cstr_append_bounded(src.as_ptr(), actual.as_mut_ptr(), capacity)
                    };
                    assert_eq!(actual_len, expected_len);
                    assert_eq!(actual, expected);
                }
            }
        }
    }

    #[test]
    fn null_source_and_tiny_capacity_only_measure_destination() {
        let mut dst = *b"abc\0unchanged";
        assert_eq!(unsafe { cstr_append_bounded(null(), dst.as_mut_ptr(), 8) }, 3);
        assert_eq!(&dst, b"abc\0unchanged");
        assert_eq!(unsafe { cstr_append_bounded(b"z\0".as_ptr(), dst.as_mut_ptr(), 1) }, 3);
        assert_eq!(&dst, b"abc\0unchanged");
    }

    #[test]
    fn null_destination_returns_zero_without_reading_source() {
        assert_eq!(unsafe { cstr_append_bounded(null(), core::ptr::null_mut(), 8) }, 0);
    }
}
