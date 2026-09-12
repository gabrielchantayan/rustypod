//! Resolving a schema-qualified SQLite name — `sqlite3TwoPartName` from
//! `build.c`.
//!
//! - `sqlite_two_part_name` — original: `FUN_0838527c` @ 0x0838527c (96
//!   bytes; 7 direct `bl` call sites, binary-scanned). The exact raw extent
//!   is 0x0838527c..0x083852dc; it ends in `pop {r4-r6,pc}`, followed by the
//!   literal string `"unknown database %T"` at 0x083852dc and the separately
//!   linked `FUN_083852f0`.
//!
//! The function selects an unqualified table-name token and database index.
//! A non-NULL second token whose packed `dyn:1 | n:31` word has a nonzero
//! length names a database: it is written to the output and
//! `sqlite3FindDb(db, name1)` supplies the index. A negative lookup reports
//! `"unknown database %T"`, increments Parse.nErr a second time, and returns
//! -1. A missing or zero-length second token instead selects `name1` and
//! returns `db->init.iDb` (+0x78).
//!
//! Every inbound call is an unconditional `bl` (no predicated forms):
//! 0x0836f410, 0x0836fdb0, 0x08373d6c, 0x08374800, 0x0837f2a4, 0x08381eb0,
//! and 0x08384630.
//!
//! Deliberate deviation: `sqlite3FindDb` @ 0x08378b04 is not ported (and has
//! no ledger entry). Target builds retain that verified retail call through a
//! volatile dispatch slot; host tests install a recorder. The already ported
//! `sqlite_error_msg` is called directly. Token and `sqlite3` fields use word
//! indices, so their target offsets remain +0x04 and +0x78 without overlapping
//! widened host pointer fields.

use super::error_msg::{sqlite_error_msg, Parse};

/// Width of a target pointer field, widened on host fixtures without changing
/// the target word-index layout.
const WORD: usize = core::mem::size_of::<*const u8>();
/// `Token` word containing `dyn:1 | n:31` (target offset +0x04).
const TOKEN_PACKED_INDEX: usize = 1;
/// `sqlite3.init.iDb` word (target offset +0x78).
const INIT_DATABASE_INDEX: usize = 0x78 / 4;
/// Verified retail `sqlite3FindDb` entry used until that function is ported.
#[cfg(target_os = "none")]
const FIND_DB_RETAIL_ADDRESS: usize = 0x0837_8b04;

/// `sqlite3FindDb(sqlite3 *db, Token *name)`.
pub type FindDbFn = unsafe extern "C" fn(*mut u8, *const u8) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_find_db(db: *mut u8, name: *const u8) -> i32 {
    let find_db: FindDbFn = core::mem::transmute(FIND_DB_RETAIL_ADDRESS);
    find_db(db, name)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_find_db(_db: *mut u8, _name: *const u8) -> i32 {
    panic!("sqlite_two_part_name requires sqlite3FindDb @ 0x08378b04")
}

/// Active `sqlite3FindDb` implementation. The target default is the verified
/// retail entry because it is not yet independently ported.
#[cfg(target_os = "none")]
pub static mut SQLITE_FIND_DB: FindDbFn = retail_find_db;
#[cfg(not(target_os = "none"))]
pub static mut SQLITE_FIND_DB: FindDbFn = missing_find_db;

#[inline(always)]
unsafe fn find_db_op() -> FindDbFn {
    core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_FIND_DB))
}

/// sqlite_two_part_name — original: `FUN_0838527c` @ 0x0838527c (96 bytes;
/// 7 direct `bl` call sites).
///
/// `sqlite3TwoPartName`: choose `name2` and look up its database when it
/// spells a nonempty qualified name; otherwise choose `name1` and return the
/// connection's current initialization database index. `parse`, `out_name`,
/// and (when non-NULL) either token must meet the original's readable-pointer
/// contract. A failed lookup reports an error and returns -1.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.sqlite_two_part_name")]
#[inline(never)]
pub unsafe extern "C" fn sqlite_two_part_name(
    parse: *mut Parse,
    name1: *const u8,
    name2: *const u8,
    out_name: *mut *const u8,
) -> i32 {
    if !name2.is_null()
        && name2
            .cast::<usize>()
            .add(TOKEN_PACKED_INDEX)
            .cast::<u32>()
            .read()
            >> 1
            != 0
    {
        out_name.write(name2);
        let database_index = (find_db_op())((*parse).db, name1);
        if database_index >= 0 {
            return database_index;
        }

        let args = [name1 as u32];
        sqlite_error_msg(parse, b"unknown database %T\0".as_ptr(), args.as_ptr());
        (*parse).n_err = (*parse).n_err.wrapping_add(1);
        return -1;
    }

    out_name.write(name1);
    (*parse)
        .db
        .cast::<usize>()
        .add(INIT_DATABASE_INDEX)
        .cast::<i32>()
        .read()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static FIND_DB_LOCK: Mutex<()> = Mutex::new(());
    static mut LOOKUP_RESULT: i32 = 0;
    static mut LOOKUP_ARGS: Option<(*mut u8, *const u8)> = None;

    unsafe extern "C" fn recording_find_db(db: *mut u8, name: *const u8) -> i32 {
        LOOKUP_ARGS = Some((db, name));
        LOOKUP_RESULT
    }

    struct FindDbReset(FindDbFn);

    impl Drop for FindDbReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_FIND_DB), self.0);
            }
        }
    }

    unsafe fn install_recording_find_db(result: i32) -> FindDbReset {
        LOOKUP_RESULT = result;
        LOOKUP_ARGS = None;
        let saved = core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_FIND_DB));
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_FIND_DB), recording_find_db);
        FindDbReset(saved)
    }

    fn parse(db: *mut u8, rc: i32, n_err: i32) -> Parse {
        Parse {
            db,
            rc,
            z_err_msg: core::ptr::null_mut(),
            _gap_0c: [0; 0x12 - 0x0c],
            check_schema: 0,
            _gap_13: [0; 0x40 - 0x13],
            n_err,
        }
    }

    #[test]
    fn nonempty_second_token_looks_up_its_database_and_selects_it() {
        let _lock = FIND_DB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut db = [0usize; INIT_DATABASE_INDEX + 1];
        let name1 = [0x1111_1111usize, 0usize];
        let name2 = [0x2222_2222usize, 6usize]; // dyn=0, n=3
        let mut context = parse(db.as_mut_ptr().cast(), 0, 7);
        let mut selected = core::ptr::null();
        unsafe {
            let _reset = install_recording_find_db(4);
            assert_eq!(
                sqlite_two_part_name(
                    &mut context,
                    name1.as_ptr().cast(),
                    name2.as_ptr().cast(),
                    &mut selected,
                ),
                4,
            );
            assert_eq!(LOOKUP_ARGS, Some((db.as_mut_ptr().cast(), name1.as_ptr().cast())));
        }
        assert_eq!(selected, name2.as_ptr().cast());
        assert_eq!(context.n_err, 7);
        assert_eq!(context.rc, 0);
    }

    #[test]
    fn null_second_token_uses_the_current_initialization_database() {
        let mut db = [0usize; INIT_DATABASE_INDEX + 1];
        db[INIT_DATABASE_INDEX] = (-9_i32 as u32) as usize;
        let name1 = [0x3333_3333usize, 0usize];
        let mut context = parse(db.as_mut_ptr().cast(), 0, 1);
        let mut selected = core::ptr::null();
        unsafe {
            assert_eq!(
                sqlite_two_part_name(&mut context, name1.as_ptr().cast(), core::ptr::null(), &mut selected),
                -9,
            );
        }
        assert_eq!(selected, name1.as_ptr().cast());
    }

    #[test]
    fn zero_length_second_token_bypasses_lookup_even_with_its_dyn_bit_set() {
        let _lock = FIND_DB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut db = [0usize; INIT_DATABASE_INDEX + 1];
        db[INIT_DATABASE_INDEX] = 12;
        let name1 = [0x4444_4444usize, 0usize];
        let name2 = [0x5555_5555usize, 1usize]; // dyn=1, n=0
        let mut context = parse(db.as_mut_ptr().cast(), 0, 3);
        let mut selected = core::ptr::null();
        unsafe {
            let _reset = install_recording_find_db(91);
            assert_eq!(
                sqlite_two_part_name(
                    &mut context,
                    name1.as_ptr().cast(),
                    name2.as_ptr().cast(),
                    &mut selected,
                ),
                12,
            );
            assert_eq!(LOOKUP_ARGS, None, "packed length zero must skip sqlite3FindDb");
        }
        assert_eq!(selected, name1.as_ptr().cast());
    }

    #[test]
    fn failed_database_lookup_reports_error_and_bumps_n_err_twice() {
        let _lock = FIND_DB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut db = [0usize; INIT_DATABASE_INDEX + 1];
        let name1 = [0x6666_6666usize, 0usize];
        let name2 = [0x7777_7777usize, 2usize]; // dyn=0, n=1
        let mut context = parse(db.as_mut_ptr().cast(), 0, 40);
        let mut selected = core::ptr::null();
        unsafe {
            let _reset = install_recording_find_db(-7);
            assert_eq!(
                sqlite_two_part_name(
                    &mut context,
                    name1.as_ptr().cast(),
                    name2.as_ptr().cast(),
                    &mut selected,
                ),
                -1,
            );
        }
        assert_eq!(selected, name2.as_ptr().cast());
        assert_eq!(context.rc, 1, "sqlite_error_msg latches SQLITE_ERROR");
        assert_eq!(context.n_err, 42, "reporter and caller each increment nErr");
        assert!(context.z_err_msg.is_null());
    }
}
