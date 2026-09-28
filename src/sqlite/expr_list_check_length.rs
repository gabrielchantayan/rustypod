//! Guarding SQLite expression-list lengths.
//!
//! `sqlite_expr_list_check_length` — original: `FUN_0837864c` @
//! `0x0837864c` (32 bytes; true extent `0x0837864c..0x0837866c`). Raw ARM
//! words establish the body through `bx lr` at `0x08378668`; the word at
//! `0x0837866c` is its relocated format-string pointer, and the separately
//! linked `sqlite3ExprListDelete` begins at `0x08378670`. There are **2
//! direct `bl` call sites**, both plain/unconditional, and no predicated
//! `bl` call sites. The body itself has no `bl`: its taken `bgt` tail branch
//! targets `sqlite_error_msg` @ `0x083767a0`.
//!
//! # Algorithm
//!
//! `sqlite3ExprListCheckLength`: if a non-NULL expression list's signed
//! `nExpr` exceeds `db->aLimit[SQLITE_LIMIT_COLUMN]` at `db + 0x58`, report
//! `"too many columns in %s"` through SQLite's parser error funnel, passing
//! `object` as its sole variadic argument. A NULL list and a count equal to
//! the limit are no-ops.
//!
//! # Deliberate deviations
//!
//! The retail tail branch becomes a direct Rust call to the ported
//! `sqlite_error_msg`; its C vararg register is represented by a one-word
//! local `VaList`. Connection and expression-list fields are raw target-width
//! offsets so their 32-bit layout does not depend on host pointer width.

use super::error_msg::{sqlite_error_msg, Parse, VaList};

const COLUMN_LIMIT_OFFSET: usize = 0x58;
const TOO_MANY_COLUMNS_FORMAT: &[u8; 23] = b"too many columns in %s\0";

/// sqlite_expr_list_check_length — original: `FUN_0837864c` @ `0x0837864c`.
///
/// # Safety
/// `parse` must point to a readable `Parse` whose `db + 0x58` is readable.
/// A non-NULL `list` must point to its signed `nExpr` word. `object` must
/// satisfy the formatter's `%s` contract when the limit is exceeded.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_expr_list_check_length(
    parse: *mut Parse,
    list: *const u8,
    object: *const u8,
) {
    if list.is_null() {
        return;
    }

    let count = list.cast::<i32>().read();
    let limit = (*parse).db.add(COLUMN_LIMIT_OFFSET).cast::<i32>().read();
    if count > limit {
        let args = [object as usize as u32];
        sqlite_error_msg(parse, TOO_MANY_COLUMNS_FORMAT.as_ptr(), args.as_ptr() as VaList);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::error_msg::{VmPrintfFn, SQLITE_VM_PRINTF};
    use parking_lot::Mutex;

    static FORMATTER_LOCK: Mutex<()> = Mutex::new(());
    static mut RECORDED: Option<(*mut u8, *const u8, u32)> = None;

    unsafe extern "C" fn recording_formatter(db: *mut u8, format: *const u8, args: VaList) -> *mut u8 {
        RECORDED = Some((db, format, args.read()));
        core::ptr::null_mut()
    }

    struct Fixture {
        db: [u8; 0x5c],
        parse: Parse,
        list_count: i32,
    }

    impl Fixture {
        fn new(limit: i32, count: i32) -> Self {
            let mut db = [0u8; 0x5c];
            unsafe { db.as_mut_ptr().add(COLUMN_LIMIT_OFFSET).cast::<i32>().write(limit) };
            Self {
                parse: Parse {
                    db: core::ptr::null_mut(), rc: 0, z_err_msg: core::ptr::null_mut(),
                    _gap_0c: [0; 0x12 - 0x0c], check_schema: 0,
                    _gap_13: [0; 0x40 - 0x13], n_err: 0,
                },
                db,
                list_count: count,
            }
        }

        fn bind_parse(&mut self) {
            self.parse.db = self.db.as_mut_ptr();
        }
    }

    #[test]
    fn ignores_null_lists_and_counts_at_or_below_the_limit() {
        let _guard = FORMATTER_LOCK.lock();
        let mut fixture = Fixture::new(3, 3);
        unsafe { RECORDED = None; }
        fixture.bind_parse();
        unsafe { sqlite_expr_list_check_length(&mut fixture.parse, core::ptr::null(), b"items\0".as_ptr()) };
        unsafe { sqlite_expr_list_check_length(&mut fixture.parse, &fixture.list_count as *const i32 as *const u8, b"items\0".as_ptr()) };
        assert_eq!(fixture.parse.n_err, 0);
        assert!(unsafe { RECORDED }.is_none());
        assert_eq!(fixture.db[0x58], 3);
    }

    #[test]
    fn reports_only_a_strictly_over_limit_list_with_the_object_argument() {
        let _guard = FORMATTER_LOCK.lock();
        let mut fixture = Fixture::new(3, 4);
        fixture.bind_parse();
        let object = b"result set\0";
        unsafe {
            RECORDED = None;
            let saved: VmPrintfFn = core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_VM_PRINTF));
            core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VM_PRINTF), recording_formatter);
            sqlite_expr_list_check_length(&mut fixture.parse, &fixture.list_count as *const i32 as *const u8, object.as_ptr());
            core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VM_PRINTF), saved);
        }
        let (db, format, argument) = unsafe { RECORDED }.expect("formatter called");
        assert_eq!(db, fixture.parse.db);
        assert_eq!(format, TOO_MANY_COLUMNS_FORMAT.as_ptr());
        assert_eq!(argument, object.as_ptr() as usize as u32);
        assert_eq!(fixture.parse.n_err, 1);
        assert_eq!(fixture.parse.rc, 1);
    }
}
