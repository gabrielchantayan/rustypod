//! Bounded trailing-space predicate.
//!
//! `remaining_path_bytes_are_spaces` is retailOS `thunk_FUN_082e014c` at
//! `0x082e0138`. Raw ARM establishes its exact 36-byte code extent
//! (`0x082e0138..0x082e015b`): the branch at its entry targets the loop setup
//! at `0x082e014c`, which branches back into the loop body at `0x082e013c`;
//! `0x082e015c` begins the next separately entered function. Decoding every
//! ARM B/BL word in `osos.dec` finds two inbound direct call sites, both plain
//! unconditional `bl` at `0x082e2a9c` and `0x082e2af0`, with no predicated
//! calls or tail branches.
//!
//! It returns one when `limit` bytes beginning at `bytes` are all ASCII spaces,
//! including the vacuous zero-length range; otherwise it returns zero at the
//! first non-space byte. Deliberate deviation: volatile byte reads prevent
//! LLVM from recognizing and replacing the bounded loop with a libc helper.

/// Returns whether every byte in the bounded path suffix is ASCII space.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn remaining_path_bytes_are_spaces(mut bytes: *const u8, mut limit: u32) -> u32 {
    while limit != 0 {
        if core::ptr::read_volatile(bytes) != b' ' {
            return 0;
        }
        bytes = bytes.add(1);
        limit -= 1;
    }
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::remaining_path_bytes_are_spaces;

    #[test]
    fn empty_range_succeeds_without_dereferencing_the_pointer() {
        unsafe {
            assert_eq!(remaining_path_bytes_are_spaces(core::ptr::null(), 0), 1);
        }
    }

    #[test]
    fn accepts_exactly_the_requested_space_range() {
        let bytes = b"    x";
        unsafe {
            assert_eq!(remaining_path_bytes_are_spaces(bytes.as_ptr(), 4), 1);
            assert_eq!(remaining_path_bytes_are_spaces(bytes.as_ptr(), 5), 0);
        }
    }

    #[test]
    fn rejects_non_space_at_each_range_edge() {
        unsafe {
            assert_eq!(remaining_path_bytes_are_spaces(b"x   ".as_ptr(), 4), 0);
            assert_eq!(remaining_path_bytes_are_spaces(b"   x".as_ptr(), 4), 0);
        }
    }
}
