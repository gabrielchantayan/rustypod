//! Assign a parsed collation sequence to a column.
//!
//! - `column_set_collation` — original: `FUN_083788a0` @ `0x083788a0`
//!   (92 bytes; 3 plain `bl` call sites and 0 predicated `bl` call sites,
//!   binary-decoded). The next separately linked function begins at
//!   `0x083788fc`.
//!
//! `column_set_collation` duplicates and dequotes `token`, resolves it against
//! `parse`'s connection, then writes the resulting `CollSeq` to the target
//! column and sets its `0x0100` flag. The temporary name is freed in every
//! path, including a failed lookup. Deliberate deviation: target-width pointer
//! fields use word indices so the host's 64-bit pointers cannot overlap the
//! target's +0x04 collation field.

use crate::heap::tracked::tracked_free;

use super::locate_coll_seq::{locate_coll_seq, CollSeq};
use super::name_from_token::name_from_token;

const WORD: usize = core::mem::size_of::<*mut u8>();
const COLUMN_FLAGS_OFFSET: usize = 2;
const COLUMN_COLLATION_WORD: usize = 1;
const COLUMN_HAS_COLLATION: u16 = 0x0100;

/// `column_set_collation` — original: `FUN_083788a0` @ `0x083788a0`.
///
/// # Safety
/// `parse` must point to a live target-layout Parse whose first word is its
/// database pointer. When non-NULL, `column` must expose writable flag and
/// collation fields; `token` must satisfy [`name_from_token`]'s requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn column_set_collation(
    parse: *mut u8,
    column: *mut u8,
    token: *const u8,
) -> *mut u8 {
    let db = (parse as *const *mut u8).read();
    let name = name_from_token(db, token);
    if !column.is_null() && !name.is_null() {
        let collation = locate_coll_seq(parse.cast(), name, -1);
        if !collation.is_null() {
            (column.add(COLUMN_COLLATION_WORD * WORD) as *mut *mut CollSeq).write(collation);
            let flags = (column.add(COLUMN_FLAGS_OFFSET) as *mut u16).read();
            (column.add(COLUMN_FLAGS_OFFSET) as *mut u16).write(flags | COLUMN_HAS_COLLATION);
        }
    }
    tracked_free(name);
    column
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn null_token_leaves_column_unchanged_and_returns_it() {
        let mut parse = [0u8; core::mem::size_of::<*mut u8>()];
        let mut column = [0xa5u8; 2 * WORD];
        let before = column;

        let returned = unsafe {
            column_set_collation(parse.as_mut_ptr(), column.as_mut_ptr(), core::ptr::null())
        };

        assert_eq!(returned, column.as_mut_ptr());
        assert_eq!(column, before, "a NULL token cannot resolve a collation");
    }

    #[test]
    fn null_column_is_returned_after_a_null_token() {
        let mut parse = [0u8; core::mem::size_of::<*mut u8>()];

        assert!(unsafe {
            column_set_collation(parse.as_mut_ptr(), core::ptr::null_mut(), core::ptr::null())
        }
        .is_null());
    }
}
