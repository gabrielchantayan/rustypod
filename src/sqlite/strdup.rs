//! SQLite's string duplication helpers.
//!
//! - `str_dup` — original: `FUN_08384ed8` @ 0x08384ed8 (60 bytes;
//!   2 `bl` call sites, binary-scanned). SQLite's `sqlite3StrDup`.
//! - `db_str_dup` — original: `FUN_08374a14` @ 0x08374a14 (44 bytes;
//!   22 `bl` call sites, binary-scanned). SQLite's `sqlite3DbStrDup`.
//!
//! `str_dup` algorithm: a NULL input returns NULL without touching the
//! heap. Otherwise the length is measured (`strlen` @ 0x08392478), a
//! block of `len + 1` bytes is requested from `sqlite3_malloc` @
//! 0x08390b14, and — only when the allocation succeeds — the whole
//! string *including* its terminating NUL is copied over (`__rt_memcpy`
//! through the ROM veneer @ 0x08037db0). A failed allocation simply
//! yields NULL; unlike the connection-scoped wrappers in `sqlite::mem`
//! there is no `mallocFailed` flag to set (that is the caller
//! `db_str_dup`'s job).
//!
//! `db_str_dup` algorithm: tail-call `str_dup(z)`, then — only when
//! `z` was non-NULL and the duplication came back NULL — set the sticky
//! `db->mallocFailed` byte at +0x1e (original: `cmp r5,#0` /
//! `ldmiaeq` early-out, then `cmp r0,#0` / `strbeq r1,[r4,#0x1e]`).
//! The result of `str_dup` is returned unchanged either way.
//!
//! Deviations:
//! - `sqlite3_malloc` @ 0x08390b14 is not ported; the request goes
//!   through the [`DB_MEM_OPS`] dispatch boundary (house pattern, see
//!   `sqlite/mem.rs`). The default slot is a documented always-fails
//!   stub.
//! - `strlen` and `__rt_memcpy` are called directly through their
//!   ported twins (`libc::strlen`, `libc::rt_memcpy`), per the porting
//!   rules.

use crate::libc::rt_memcpy::__rt_memcpy;
use crate::libc::strlen::strlen;
use crate::sqlite::mem::{db_malloc_op, set_malloc_failed};

/// str_dup — original: `FUN_08384ed8` @ 0x08384ed8 (60 bytes;
/// 2 `bl` call sites).
///
/// `sqlite3StrDup`: heap-duplicate the NUL-terminated string `z`.
/// NULL in, NULL out; a failed allocation also yields NULL. On success
/// the returned block holds `strlen(z) + 1` bytes, terminator included.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn str_dup(z: *const u8) -> *mut u8 {
    if z.is_null() {
        return core::ptr::null_mut();
    }
    let len = strlen(z);
    let dup = (db_malloc_op())(len as i32 + 1);
    if !dup.is_null() {
        __rt_memcpy(dup, z, len + 1);
    }
    dup
}

/// db_str_dup — original: `FUN_08374a14` @ 0x08374a14 (44 bytes;
/// 22 `bl` call sites).
///
/// `sqlite3DbStrDup`: heap-duplicate the NUL-terminated string `z` on
/// connection `db`. The copy itself is `str_dup`'s; this wrapper only
/// records failure: when `z` was non-NULL and the duplication returned
/// NULL, the sticky `db->mallocFailed` byte at +0x1e is set. A NULL
/// `z` passes through as NULL without touching `db`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn db_str_dup(db: *mut u8, z: *const u8) -> *mut u8 {
    let dup = str_dup(z);
    if !z.is_null() && dup.is_null() {
        set_malloc_failed(db);
    }
    dup
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::sqlite::mem::tests::{install_recorder, realloc_log};
    use std::vec::Vec;

    /// Build a NUL-terminated string of `n` nonzero bytes at `align`
    /// offset inside a padded buffer; returns (buffer, offset).
    fn make_string(n: usize, align: usize) -> (Vec<u8>, usize) {
        let mut buf = std::vec![0xEE; align];
        for i in 0..n {
            buf.push((i as u16 * 37 % 251) as u8 | 1); // never NUL
        }
        buf.push(0);
        buf.resize(buf.len() + 8, 0xEE);
        (buf, align)
    }

    #[test]
    fn null_in_null_out_without_touching_the_heap() {
        let _guard = install_recorder(core::ptr::null_mut());
        assert!(unsafe { str_dup(core::ptr::null()) }.is_null());
        assert!(realloc_log().is_empty(), "the allocator must not be called");
    }

    #[test]
    fn duplicates_string_and_terminator_into_a_fresh_block() {
        for len in [0usize, 1, 5, 33] {
            for align in 0..4usize {
                let (src, off) = make_string(len, align);
                let mut arena = [0xa5u8; 64];
                let _guard = install_recorder(arena.as_mut_ptr());

                let dup = unsafe { str_dup(src.as_ptr().add(off)) };
                assert_eq!(dup, arena.as_mut_ptr());
                assert_eq!(
                    realloc_log(),
                    std::vec![(0, len as i32 + 1)],
                    "exactly one request of len + 1"
                );
                assert_eq!(&arena[..len], &src[off..off + len]);
                assert_eq!(arena[len], 0, "terminating NUL copied");
                assert!(
                    arena[len + 1..].iter().all(|&b| b == 0xa5),
                    "nothing past len + 1 is written"
                );
            }
        }
    }

    #[test]
    fn a_failed_allocation_returns_null_and_copies_nothing() {
        let (src, off) = make_string(7, 0);
        let _guard = install_recorder(core::ptr::null_mut());

        assert!(unsafe { str_dup(src.as_ptr().add(off)) }.is_null());
        assert_eq!(realloc_log(), std::vec![(0, 8)], "len + 1 still requested");
    }

    /// A fake `sqlite3` connection: only the `mallocFailed` byte at
    /// +0x1e matters here.
    fn fake_db() -> Vec<u8> {
        std::vec![0u8; 0x30]
    }

    #[test]
    fn db_str_dup_null_z_passes_through_without_touching_db() {
        let mut db = fake_db();
        let _guard = install_recorder(core::ptr::null_mut());

        assert!(unsafe { db_str_dup(db.as_mut_ptr(), core::ptr::null()) }.is_null());
        assert!(
            db.iter().all(|&b| b == 0),
            "mallocFailed must not be set for a NULL input"
        );
    }

    #[test]
    fn db_str_dup_success_copies_and_leaves_the_flag_clear() {
        let (src, off) = make_string(9, 1);
        let mut db = fake_db();
        let mut arena = [0xa5u8; 64];
        let _guard = install_recorder(arena.as_mut_ptr());

        let dup = unsafe { db_str_dup(db.as_mut_ptr(), src.as_ptr().add(off)) };
        assert_eq!(dup, arena.as_mut_ptr());
        assert_eq!(&arena[..9], &src[off..off + 9]);
        assert_eq!(arena[9], 0, "terminating NUL copied");
        assert!(db.iter().all(|&b| b == 0), "no failure recorded on success");
    }

    #[test]
    fn db_str_dup_failure_sets_malloc_failed() {
        let (src, off) = make_string(4, 0);
        let mut db = fake_db();
        let _guard = install_recorder(core::ptr::null_mut());

        assert!(unsafe { db_str_dup(db.as_mut_ptr(), src.as_ptr().add(off)) }.is_null());
        assert_eq!(db[0x1e], 1, "sticky mallocFailed byte at +0x1e");
        assert!(
            db.iter().enumerate().all(|(i, &b)| i == 0x1e || b == 0),
            "only the flag byte is written"
        );
    }
}
