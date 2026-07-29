//! SQLite's token-to-name extraction helper.
//!
//! - `name_from_token` — original: `FUN_0837d7ac` @ 0x0837d7ac
//!   (48 bytes; 27 `bl` call sites, binary-scanned). SQLite's
//!   `sqlite3NameFromToken`.
//!
//! `name_from_token` algorithm: a NULL token yields NULL without
//! touching the heap. Otherwise the token's string `z` (+0x00) and
//! length are read — the length lives in a packed `dyn:1 | n:31` word
//! at +0x04 which the original shifts right by one (`ldr r2,[r1,#0x4]`
//! / `mov r2,r2,lsr #1`) — and `db_str_ndup(db, z, n)` @ 0x08374a40
//! heap-duplicates the span on connection `db`. The duplicate is then
//! unconditionally passed through `dequote` @ 0x083753d0 (a NULL
//! duplicate is `dequote`'s documented no-op case) and returned.
//!
//! Token layout pinned by this function (also documented in
//! `sqlite/mod.rs`):
//!
//! ```text
//! Token:  +0x00 z (const char *), +0x04 packed word (dyn:1 | n:31)
//! ```
//!
//! Deviations:
//! - The allocation inside `db_str_ndup` goes through its documented
//!   `DB_MEM_OPS` dispatch boundary (see `sqlite/strdup.rs`).
//! - Both fields are addressed by WORD INDEX, not by the literal
//!   target byte offset: on the 32-bit target `index * WORD` reproduces
//!   the original offsets exactly (+0x00, +0x04), while on a 64-bit
//!   host the pointer field and the packed word stay disjoint — the
//!   literal offsets would overlap them by four bytes, so a packed-word
//!   read would return the pointer's high half (precedent:
//!   `heap/block_region.rs`).

use crate::sqlite::dequote::dequote;
use crate::sqlite::strdup::db_str_ndup;

/// Width of a pointer field: 4 on the ARMv5TE target (matching the
/// original layout), 8 on a 64-bit test host.
const WORD: usize = core::mem::size_of::<*const u8>();

/// Word index of `Token.z` (byte offset +0x00 on the 32-bit target;
/// original: `ldr r1, [r1, #0x0]`).
const TOKEN_Z_INDEX: usize = 0;

/// Word index of the packed `dyn:1 | n:31` word (byte offset +0x04 on
/// the 32-bit target; original: `ldr r2, [r1, #0x4]` /
/// `mov r2, r2, lsr #1`).
const TOKEN_PACKED_INDEX: usize = 1;

/// name_from_token — original: `FUN_0837d7ac` @ 0x0837d7ac (48 bytes;
/// 27 `bl` call sites).
///
/// `sqlite3NameFromToken`: heap-duplicate the name spelled by token
/// `name` on connection `db`, dequoted. A NULL token yields NULL; a
/// failed allocation yields NULL with `db->mallocFailed` set (that is
/// `db_str_ndup`'s documented behavior). The returned pointer is owned
/// by the caller.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn name_from_token(db: *mut u8, name: *const u8) -> *mut u8 {
    if name.is_null() {
        return core::ptr::null_mut();
    }
    let z = (name.add(TOKEN_Z_INDEX * WORD) as *const *const u8).read();
    let packed = (name.add(TOKEN_PACKED_INDEX * WORD) as *const u32).read();
    let dup = db_str_ndup(db, z, (packed >> 1) as i32);
    dequote(dup);
    dup
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::sqlite::mem::tests::{install_recorder, realloc_log};
    use std::vec::Vec;

    /// A Token: pointer-aligned so the pointer and packed-word reads
    /// are aligned, as they are on target. Fields sit at word index 0
    /// and 1, matching the port's WORD-index addressing.
    #[repr(align(8))]
    struct Token {
        storage: [u8; 2 * core::mem::size_of::<*const u8>()],
    }

    impl Token {
        fn new(z: *const u8, n: u32, dyn_bit: bool) -> Self {
            let mut tok = Token {
                storage: [0; 2 * core::mem::size_of::<*const u8>()],
            };
            unsafe {
                (tok.storage.as_mut_ptr() as *mut *const u8).write(z);
                let packed = (n << 1) | dyn_bit as u32;
                (tok.storage.as_mut_ptr().add(WORD) as *mut u32).write(packed);
            }
            tok
        }
        fn ptr(&self) -> *const u8 {
            self.storage.as_ptr()
        }
    }

    /// A fake `sqlite3` connection: only the `mallocFailed` byte at
    /// +0x1e matters here.
    fn fake_db() -> Vec<u8> {
        std::vec![0u8; 0x30]
    }

    fn as_str(buf: &[u8]) -> &[u8] {
        let end = buf.iter().position(|&b| b == 0).unwrap();
        &buf[..end]
    }

    #[test]
    fn null_token_yields_null_without_touching_the_heap() {
        let mut db = fake_db();
        let _guard = install_recorder(core::ptr::null_mut());
        assert!(unsafe { name_from_token(db.as_mut_ptr(), core::ptr::null()) }.is_null());
        assert!(realloc_log().is_empty(), "the allocator must not be called");
        assert!(db.iter().all(|&b| b == 0), "mallocFailed must stay clear");
    }

    #[test]
    fn unquoted_name_is_duplicated_verbatim() {
        let src = b"abc\0";
        let tok = Token::new(src.as_ptr(), 3, false);
        let mut db = fake_db();
        let mut arena = [0xa5u8; 16];
        let _guard = install_recorder(arena.as_mut_ptr());

        let dup = unsafe { name_from_token(db.as_mut_ptr(), tok.ptr()) };
        assert_eq!(dup, arena.as_mut_ptr());
        assert_eq!(realloc_log(), std::vec![(0, 4)], "n + 1 requested");
        assert_eq!(as_str(&arena), b"abc");
        assert!(db.iter().all(|&b| b == 0), "no failure recorded on success");
    }

    #[test]
    fn quoted_name_is_duplicated_then_dequoted() {
        let src = b"\"main\"\0";
        let tok = Token::new(src.as_ptr(), 6, false);
        let mut db = fake_db();
        let mut arena = [0xa5u8; 16];
        let _guard = install_recorder(arena.as_mut_ptr());

        let dup = unsafe { name_from_token(db.as_mut_ptr(), tok.ptr()) };
        assert_eq!(dup, arena.as_mut_ptr());
        assert_eq!(realloc_log(), std::vec![(0, 7)], "n + 1 requested");
        assert_eq!(as_str(&arena), b"main", "quotes stripped in place");
    }

    #[test]
    fn length_ignores_the_dyn_bit() {
        // The low bit of the packed word is the dyn flag; the length is
        // the word shifted right by one (original: lsr r2, r2, #1).
        let src = b"it's\0";
        let tok = Token::new(src.as_ptr(), 4, true);
        let mut db = fake_db();
        let mut arena = [0xa5u8; 16];
        let _guard = install_recorder(arena.as_mut_ptr());

        let dup = unsafe { name_from_token(db.as_mut_ptr(), tok.ptr()) };
        assert_eq!(realloc_log(), std::vec![(0, 5)], "dyn bit is not length");
        assert_eq!(as_str(&arena), b"it's");
    }

    #[test]
    fn failed_allocation_yields_null_and_sets_malloc_failed() {
        let src = b"\"t\"\0";
        let tok = Token::new(src.as_ptr(), 3, false);
        let mut db = fake_db();
        let _guard = install_recorder(core::ptr::null_mut());

        assert!(unsafe { name_from_token(db.as_mut_ptr(), tok.ptr()) }.is_null());
        assert_eq!(db[0x1e], 1, "sticky mallocFailed byte at +0x1e");
        assert!(
            db.iter().enumerate().all(|(i, &b)| i == 0x1e || b == 0),
            "only the flag byte is written"
        );
    }
}
