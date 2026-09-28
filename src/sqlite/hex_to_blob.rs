//! Decoding SQLite `x'ABCD'` literals into their packed byte representation.
//!
//! - `hex_to_blob` — original: `FUN_0837b00c` @ 0x0837b00c (116 bytes;
//!   3 plain `bl` instructions, no predicated `bl` instructions). The three
//!   calls reach two targets: `db_malloc_raw` once and `hex_to_int` twice per
//!   emitted byte.
//!
//! Algorithm: allocate `len / 2 + 1` bytes through the connection-scoped
//! allocator, pack each complete input pair as `(high << 4) | low`, and write
//! a trailing NUL. The input length and pair index use ARM signed arithmetic:
//! odd trailing characters are ignored, and negative lengths allocate and
//! terminate an empty result when the allocation succeeds.
//!
//! Deliberate deviations: none. Rust expresses the ARM truncation-toward-zero
//! divide-by-two explicitly; it calls the already ported helpers directly.

use crate::sqlite::hex_to_int::hex_to_int;
use crate::sqlite::mem::db_malloc_raw;

/// `hex_to_blob` — original: `FUN_0837b00c` @ 0x0837b00c (116 bytes).
///
/// SQLite's `hexToBlob`: allocate `len / 2 + 1` bytes from `db`, decode each
/// complete adjacent hexadecimal-character pair, append a NUL byte, and
/// return the allocation. Allocation failure returns NULL. The original
/// neither validates digits nor checks `hex` before dereferencing it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hex_to_blob(db: *mut u8, hex: *const u8, len: i32) -> *mut u8 {
    // `add r1,r2,r2,lsr #31; ... add r1,#1`: signed division truncated
    // toward zero, rather than Rust's checked signed arithmetic.
    let allocation_len = (((len as u32).wrapping_add((len as u32) >> 31) as i32) >> 1).wrapping_add(1);
    let out = db_malloc_raw(db, allocation_len);
    if out.is_null() {
        return out;
    }

    let mut index = 0i32;
    let last_pair_start = len.wrapping_sub(1);
    while index < last_pair_start {
        let low = hex_to_int(core::ptr::read(hex.add(index as usize + 1)) as u32);
        let high = hex_to_int(core::ptr::read(hex.add(index as usize)) as u32);
        core::ptr::write(out.add((index / 2) as usize), (low | (high << 4)) as u8);
        index = index.wrapping_add(2);
    }
    core::ptr::write(out.add((index / 2) as usize), 0);
    out
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::mem::tests::{install_recorder, realloc_log, Connection};

    #[test]
    fn packs_complete_pairs_and_terminates_the_result() {
        let mut out = [0xa5u8; 4];
        let _guard = install_recorder(out.as_mut_ptr());
        let mut db = Connection::healthy();

        let result = unsafe { hex_to_blob(db.ptr(), b"aF09".as_ptr(), 4) };

        assert_eq!(result, out.as_mut_ptr());
        assert_eq!(&out[..3], &[0xaf, 0x09, 0]);
        assert_eq!(out[3], 0xa5, "the allocator's fourth byte is untouched");
        assert_eq!(realloc_log(), std::vec![(0, 3)]);
        assert_eq!(db.failed_flag(), 0);
    }

    #[test]
    fn ignores_an_odd_trailing_character() {
        let mut out = [0xa5u8; 3];
        let _guard = install_recorder(out.as_mut_ptr());
        let mut db = Connection::healthy();

        unsafe { hex_to_blob(db.ptr(), b"12F".as_ptr(), 3) };

        assert_eq!(&out[..2], &[0x12, 0]);
        assert_eq!(out[2], 0xa5);
        assert_eq!(realloc_log(), std::vec![(0, 2)]);
    }

    #[test]
    fn allocation_failure_returns_null_and_records_connection_oom() {
        let _guard = install_recorder(core::ptr::null_mut());
        let mut db = Connection::healthy();

        assert!(unsafe { hex_to_blob(db.ptr(), b"AB".as_ptr(), 2) }.is_null());
        assert_eq!(realloc_log(), std::vec![(0, 2)]);
        assert_eq!(db.failed_flag(), 1);
    }

    #[test]
    fn zero_and_negative_lengths_allocate_only_the_terminator() {
        for len in [0, -1] {
            let mut out = [0xa5u8; 2];
            let _guard = install_recorder(out.as_mut_ptr());
            let mut db = Connection::healthy();

            assert_eq!(unsafe { hex_to_blob(db.ptr(), b"AB".as_ptr(), len) }, out.as_mut_ptr());
            assert_eq!(out, [0, 0xa5], "len = {len}");
            assert_eq!(realloc_log(), std::vec![(0, 1)], "len = {len}");
        }
    }
}
