//! SQLite token copying.
//!
//! `token_copy` — original: `FUN_08385134` @ 0x08385134 (112 bytes;
//! 7 direct `bl` call sites: four unconditional, two `blne`, one `bleq`,
//! binary-scanned). The raw body ends at the separately linked sibling's
//! push at 0x083851a4.
//!
//! Algorithm: if the destination owns its existing token text, release it;
//! a NULL source text then only clears the destination pointer, preserving
//! its packed length/ownership word. Otherwise copy the source length bits,
//! preserve the destination ownership bit until allocation, duplicate the
//! exact non-NUL-terminated source span through `db_str_ndup`, store its
//! result, and mark the destination dynamic even on allocation failure.
//!
//! Deliberate deviations: the target's two target-width words are the shared
//! typed [`Token`] layout; the already ported `tracked_free` and `db_str_ndup`
//! are called directly rather than through a new dispatch seam.

use super::expr_new::Token;
use super::strdup::db_str_ndup;
use crate::heap::tracked::tracked_free;

/// `sqlite3TokenCopy`: replace `destination` with an owned duplicate of
/// `source`'s text, retaining the original's NULL-source packed-word state.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn token_copy(
    db: *mut u8,
    destination: *mut Token,
    source: *const Token,
) {
    if (*destination).n_dyn & 1 != 0 {
        tracked_free((*destination).z as *mut u8);
    }

    let source_text = (*source).z;
    if source_text.is_null() {
        (*destination).z = core::ptr::null();
        return;
    }

    (*destination).n_dyn = ((*destination).n_dyn & 1) | ((*source).n_dyn & !1);
    (*destination).z = db_str_ndup(db, source_text, ((*source).n_dyn >> 1) as i32);
    (*destination).n_dyn |= 1;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::mem::tests::{install_recorder, realloc_log};

    fn fake_db() -> [u8; 0x30] {
        [0; 0x30]
    }

    #[test]
    fn null_source_clears_only_the_destination_text() {
        let _guard = install_recorder(core::ptr::null_mut());
        let mut db = fake_db();
        let mut destination = Token { z: core::ptr::null(), n_dyn: 0x1234_5679 };
        let source = Token { z: core::ptr::null(), n_dyn: 0x7654_3210 };

        unsafe { token_copy(db.as_mut_ptr(), &mut destination, &source) };

        assert!(destination.z.is_null());
        assert_eq!(destination.n_dyn, 0x1234_5679, "NULL source retains packed state");
        assert!(realloc_log().is_empty(), "NULL source must not allocate");
        assert!(db.iter().all(|&byte| byte == 0), "db is not consulted");
    }

    #[test]
    fn duplicates_exact_length_and_marks_destination_owned() {
        let source_text = [0x91u8, 0x42, 0xfe, 0x37, 0x80];
        let mut arena = [0xa5u8; 16];
        let _guard = install_recorder(arena.as_mut_ptr());
        let mut db = fake_db();
        let mut destination = Token { z: 0x1234usize as *const u8, n_dyn: 0x2468_ace0 };
        let source = Token { z: source_text.as_ptr(), n_dyn: (source_text.len() as u32) << 1 | 1 };

        unsafe { token_copy(db.as_mut_ptr(), &mut destination, &source) };

        assert_eq!(destination.z, arena.as_ptr());
        assert_eq!(destination.n_dyn, (source_text.len() as u32) << 1 | 1);
        assert_eq!(realloc_log(), std::vec![(0, source_text.len() as i32 + 1)]);
        assert_eq!(&arena[..source_text.len()], &source_text);
        assert_eq!(arena[source_text.len()], 0, "copy gains one terminator");
        assert!(arena[source_text.len() + 1..].iter().all(|&byte| byte == 0xa5));
        assert!(db.iter().all(|&byte| byte == 0), "successful copy leaves db healthy");
    }

    #[test]
    fn allocation_failure_still_replaces_length_and_sets_ownership() {
        let source_text = [0x33u8, 0x44, 0x55];
        let _guard = install_recorder(core::ptr::null_mut());
        let mut db = fake_db();
        let mut destination = Token { z: core::ptr::null(), n_dyn: 0xaaaa_aaa0 };
        let source = Token { z: source_text.as_ptr(), n_dyn: (source_text.len() as u32) << 1 };

        unsafe { token_copy(db.as_mut_ptr(), &mut destination, &source) };

        assert!(destination.z.is_null());
        assert_eq!(destination.n_dyn, (source_text.len() as u32) << 1 | 1);
        assert_eq!(realloc_log(), std::vec![(0, source_text.len() as i32 + 1)]);
        assert_eq!(db[0x1e], 1, "db_str_ndup records the failed allocation");
    }
}
