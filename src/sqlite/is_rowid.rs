//! SQLite's hidden rowid-name predicate.
//!
//! - `is_rowid` — original: `FUN_0837cd3c` @ 0x0837cd3c (76 bytes;
//!   3 unconditional `bl`, 0 predicated `bl`, independently decoded from
//!   `osos.dec`).
//!
//! SQLite accepts `"_ROWID_"`, `"ROWID"`, and `"OID"` as aliases for a
//! table's hidden rowid. The retail body compares those spellings in that
//! order with `str_icmp`, returning zero only when all three comparisons are
//! nonzero; it returns one on the first equal spelling.
//!
//! # Deliberate deviations
//!
//! None. The three literals and short-circuit comparison order are preserved.

use super::stricmp::str_icmp;

/// `sqlite3IsRowid`: returns one when `name` is a case-insensitive hidden
/// rowid alias, otherwise zero.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn is_rowid(name: *const u8) -> i32 {
    if str_icmp(name, b"_ROWID_\0".as_ptr()) == 0 {
        return 1;
    }
    if str_icmp(name, b"ROWID\0".as_ptr()) == 0 {
        return 1;
    }
    if str_icmp(name, b"OID\0".as_ptr()) == 0 {
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::is_rowid;

    #[test]
    fn recognizes_each_alias_with_ascii_case_folding() {
        for name in [b"_ROWID_\0".as_slice(), b"rowid\0", b"OiD\0"] {
            assert_eq!(unsafe { is_rowid(name.as_ptr()) }, 1);
        }
    }

    #[test]
    fn rejects_near_matches_and_suffixes() {
        for name in [
            b"row_id\0".as_slice(),
            b"_rowid\0",
            b"oid_\0",
            b"rowid_extra\0",
            b"\0",
        ] {
            assert_eq!(unsafe { is_rowid(name.as_ptr()) }, 0);
        }
    }
}
