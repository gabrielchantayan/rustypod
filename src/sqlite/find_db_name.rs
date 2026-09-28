//! Resolving an attached database name to its slot.
//!
//! `find_db_name` — original: `FUN_08378b04` @ `0x08378b04` (128 bytes;
//! raw extent `0x08378b04..0x08378b84`, ending at the next `stmdb`
//! prologue). Raw ARM-word decoding verifies two incoming direct `bl` call
//! sites (0x0836f3b8 and 0x083852ac), both unconditional; no predicated
//! `bl` targets this entry. The body has five unconditional calls:
//! `name_from_token`, `strlen` twice, `str_icmp`, and `tracked_free`.
//!
//! SQLite's `sqlite3FindDb`: duplicate and dequote the input token, then scan
//! `sqlite3.aDb` backwards through 24-byte `Db` records for an equal-length,
//! case-insensitive `zName`. The temporary name is always freed after a
//! successful allocation. Target pointer fields are read as `u32` words, so
//! host pointer width cannot alter the retail `sqlite3`/`Db` offsets.
//!
//! Deliberate deviation: the test-only helper receives the already-created
//! temporary name and its three operations, isolating the scan from allocator
//! state while the target entry calls the four ported retail services directly.

use super::name_from_token::name_from_token;
use super::stricmp::str_icmp;
use crate::heap::tracked::tracked_free;
use crate::libc::strlen::strlen;

const N_DB_OFFSET: usize = 0x04;
const A_DB_OFFSET: usize = 0x08;
const DB_RECORD_SIZE: usize = 0x18;
const DB_Z_NAME_OFFSET: usize = 0x00;

unsafe fn find_db_name_with(
    db: *const u8,
    temporary_name: *mut u8,
    string_len: unsafe extern "C" fn(*const u8) -> usize,
    string_icmp: unsafe extern "C" fn(*const u8, *const u8) -> i32,
    release: unsafe extern "C" fn(*mut u8),
) -> i32 {
    if temporary_name.is_null() {
        return -1;
    }

    let name_len = string_len(temporary_name);
    let mut index = (db.add(N_DB_OFFSET) as *const i32).read() - 1;
    let entries = (db.add(A_DB_OFFSET) as *const u32).read() as usize as *const u8;

    while index >= 0 {
        let entry = entries.add(index as usize * DB_RECORD_SIZE);
        let entry_name = (entry.add(DB_Z_NAME_OFFSET) as *const u32).read() as usize as *const u8;
        if string_len(entry_name) == name_len && string_icmp(entry_name, temporary_name) == 0 {
            break;
        }
        index -= 1;
    }

    release(temporary_name);
    index
}

/// `sqlite3FindDb` — original: `FUN_08378b04` @ 0x08378b04 (128 bytes;
/// two incoming unconditional `bl` call sites).
///
/// Return the highest-numbered `Db` entry in `db` whose name equals the
/// dequoted `name` token under SQLite's case-insensitive comparison, or -1.
///
/// # Safety
/// `db` must name a readable target-layout sqlite3 with `nDb` at +0x04 and
/// an `aDb` u32 pointer at +0x08. A positive `nDb` requires readable 24-byte
/// records with a NUL-terminated u32 `zName` at +0x00. `name` is a Token
/// accepted by [`name_from_token`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn find_db_name(db: *mut u8, name: *const u8) -> i32 {
    let temporary_name = name_from_token(db, name);
    find_db_name_with(db, temporary_name, strlen, str_icmp, tracked_free)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const DB: usize = 0x00;
    const ENTRIES: usize = 0x40;
    const FIRST: usize = 0x200;
    const SECOND: usize = 0x220;
    const THIRD: usize = 0x240;
    const QUERY: usize = 0x280;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_FIND_DB_NAME, FIXTURE_LEN).map(|p| p as usize)
    });
    static RELEASED: AtomicUsize = AtomicUsize::new(0);

    unsafe fn base() -> *mut u8 {
        SLAB.expect("fixture mapping was checked") as *mut u8
    }

    unsafe fn copy_c_string(offset: usize, value: &[u8]) {
        core::ptr::copy_nonoverlapping(value.as_ptr(), base().add(offset), value.len());
    }

    unsafe extern "C" fn length(mut value: *const u8) -> usize {
        let mut len = 0;
        while value.read() != 0 {
            len += 1;
            value = value.add(1);
        }
        len
    }

    unsafe extern "C" fn compare(mut left: *const u8, mut right: *const u8) -> i32 {
        loop {
            let a = left.read().to_ascii_lowercase();
            let b = right.read().to_ascii_lowercase();
            if a != b || a == 0 {
                return a as i32 - b as i32;
            }
            left = left.add(1);
            right = right.add(1);
        }
    }

    unsafe extern "C" fn release(value: *mut u8) {
        RELEASED.store(value as usize, Ordering::SeqCst);
    }

    #[test]
    fn searches_backwards_and_frees_temporary_name_once() {
        unsafe {
            core::ptr::write_bytes(base(), 0, FIXTURE_LEN);
            copy_c_string(FIRST, b"main\0");
            copy_c_string(SECOND, b"aux\0");
            copy_c_string(THIRD, b"AUX\0");
            copy_c_string(QUERY, b"aUx\0");
            (base().add(DB + N_DB_OFFSET) as *mut i32).write(3);
            (base().add(DB + A_DB_OFFSET) as *mut u32).write((base().add(ENTRIES)) as u32);
            for (index, name) in [FIRST, SECOND, THIRD].iter().enumerate() {
                (base().add(ENTRIES + index * DB_RECORD_SIZE) as *mut u32)
                    .write(base().add(*name) as u32);
            }
            RELEASED.store(0, Ordering::SeqCst);
            assert_eq!(find_db_name_with(base(), base().add(QUERY), length, compare, release), 2);
            assert_eq!(RELEASED.load(Ordering::SeqCst), base().add(QUERY) as usize);

            RELEASED.store(0, Ordering::SeqCst);
            assert_eq!(find_db_name_with(base(), core::ptr::null_mut(), length, compare, release), -1);
            assert_eq!(RELEASED.load(Ordering::SeqCst), 0, "failed token allocation is not freed");

            copy_c_string(QUERY, b"missing\0");
            RELEASED.store(0, Ordering::SeqCst);
            assert_eq!(find_db_name_with(base(), base().add(QUERY), length, compare, release), -1);
            assert_eq!(RELEASED.load(Ordering::SeqCst), base().add(QUERY) as usize);
        }
    }
}
