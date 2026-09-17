//! cstr_find_from — original: `FUN_08297d58` @ 0x08297d58 (160 bytes).
//!
//! Verified calls: three direct, plain `bl` instructions (two to
//! `strlen_safe` @ 0x0810b610 and one to `memcmp` @ 0x08030f64); raw-image
//! decoding also finds four plain incoming `bl` sites and no predicated ones.
//!
//! Algorithm: load the C-string pointer from `haystack_slot`; if it is null,
//! return -1. Skip `start_offset` non-NUL bytes, returning -1 if the string
//! ends first. Then compare the needle at each remaining non-NUL position,
//! bounded by the precomputed haystack and needle lengths. Return the first
//! matching byte offset, or -1.
//!
//! Deliberate deviation: the retail loop calls the same `strlen_safe` and
//! `memcmp` routines through ARM `bl`; this port calls their Rust seams
//! directly. Its control flow and NULL/empty-needle behavior are preserved.

/// Finds NUL-terminated `needle` in the C string stored in `haystack_slot`,
/// starting at `start_offset`; returns the byte offset or -1.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cstr_find_from(
    haystack_slot: *const *const u8,
    needle: *const u8,
    start_offset: i32,
) -> i32 {
    let mut candidate = *haystack_slot;
    if candidate.is_null() {
        return -1;
    }

    let needle_len = super::strlen_safe::strlen_safe(needle);
    let haystack_len = super::strlen_safe::strlen_safe(candidate);
    let mut offset = 0i32;

    while offset < start_offset {
        if candidate.read_volatile() == 0 {
            return -1;
        }
        candidate = candidate.add(1);
        offset += 1;
    }

    while candidate.read_volatile() != 0 && needle_len <= haystack_len - offset as usize {
        if super::memcmp::memcmp(candidate, needle, needle_len) == 0 {
            return offset;
        }
        candidate = candidate.add(1);
        offset += 1;
    }

    -1
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn reference(haystack: Option<&[u8]>, needle: &[u8], start_offset: i32) -> i32 {
        let Some(haystack) = haystack else { return -1 };
        let haystack_len = haystack.iter().position(|&b| b == 0).unwrap();
        let needle_len = needle.iter().position(|&b| b == 0).unwrap();
        let mut offset = 0i32;
        while offset < start_offset {
            if offset as usize == haystack_len {
                return -1;
            }
            offset += 1;
        }
        while (offset as usize) < haystack_len && needle_len <= haystack_len - offset as usize {
            if haystack[offset as usize..offset as usize + needle_len] == needle[..needle_len] {
                return offset;
            }
            offset += 1;
        }
        -1
    }

    #[test]
    fn matches_reference_offsets_alignments_and_needles() {
        for alignment in 0..4usize {
            for start_offset in [-3, 0, 1, 4, 64, 65] {
                for needle in [b"\0".as_slice(), b"a\0", b"bc\0", b"zz\0"] {
                    let mut storage = Vec::from([0xA5; 4]);
                    storage.extend_from_slice(b"abcabc\0padding");
                    let haystack = unsafe { storage.as_ptr().add(alignment) };
                    let slot = haystack;
                    let expected = reference(Some(&storage[alignment..]), needle, start_offset);
                    assert_eq!(
                        unsafe { cstr_find_from(&slot, needle.as_ptr(), start_offset) },
                        expected,
                        "alignment={alignment} start_offset={start_offset} needle={needle:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn null_haystack_and_start_past_nul_return_minus_one() {
        let null_slot: *const u8 = core::ptr::null();
        assert_eq!(unsafe { cstr_find_from(&null_slot, b"\0".as_ptr(), 0) }, -1);

        let slot = b"abc\0".as_ptr();
        assert_eq!(unsafe { cstr_find_from(&slot, b"\0".as_ptr(), 3) }, -1);
        assert_eq!(unsafe { cstr_find_from(&slot, b"a\0".as_ptr(), 4) }, -1);
    }

    #[test]
    fn first_match_after_offset_wins() {
        let slot = b"ababab\0".as_ptr();
        assert_eq!(unsafe { cstr_find_from(&slot, b"ab\0".as_ptr(), 0) }, 0);
        assert_eq!(unsafe { cstr_find_from(&slot, b"ab\0".as_ptr(), 1) }, 2);
        assert_eq!(unsafe { cstr_find_from(&slot, b"ab\0".as_ptr(), -1) }, 0);
    }
}
