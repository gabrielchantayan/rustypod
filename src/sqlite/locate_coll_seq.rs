//! Resolve a named SQLite collation sequence, registering it on demand.
//!
//! - `locate_coll_seq` — original: `FUN_0837d18c` @ `0x0837d18c` (160
//!   bytes; 4 `bl` call sites, binary-scanned — all unconditional:
//!   `0x0837434c`, `0x083788d4`, `0x0837b348`, `0x0839a1e4`).
//!
//! Raw `osos.dec` establishes the exact code extent as
//! `0x0837d18c..0x0837d22c`: the return is `pop {r3-r9,pc}` at
//! `0x0837d228`, immediately followed by the
//! `"no such collation sequence: %.*s"` format string at `0x0837d22c`.
//! This is SQLite 3.5.9's `sqlite3LocateCollSeq`:
//!
//! 1. `db = parse->db` (+0x00), `encoding = db->aDb[0].pSchema->enc`
//!    (`ldrb [[db+0x08]+0x14]+0x59`), `init_busy = ldrb [db+0x80]`
//!    (`sqlite3.init.busy`).
//! 2. `coll = find_collation_encoding(db, encoding, name, name_len,
//!    init_busy)` — the ported `sqlite3FindCollSeq` tail @ `0x08378ad0`,
//!    called with `create = init_busy` regardless of the branch.
//! 3. When `init_busy == 0` and the lookup missed or found a descriptor
//!    whose comparator word at +0x0c (`CollSeq::xCmp`) is NULL, call the
//!    collation-factory helper `sqlite3GetCollSeq` @ `0x0837a17c` with
//!    `(db, coll, name, name_len)` and keep its result.
//! 4. When the final descriptor is NULL, report
//!    `"no such collation sequence: %.*s"` through the ported
//!    `sqlite_error_msg` with a strlen fallback (`0x08392478`, the ported
//!    unguarded `libc::strlen`) when `name_len < 0`, then return NULL.
//!
//! Deliberate deviations:
//! - `sqlite3GetCollSeq` @ `0x0837a17c` is not ported (same boundary as
//!   `sqlite/expr_coll_seq.rs`): its observed
//!   `(db, coll, name, name_len) -> coll-or-NULL` contract is a volatile
//!   dispatch seam; target builds call the exact retail address and host
//!   tests install a recorder.
//! - `db`'s `aDb`/`pSchema` chain is read with target-width word indices
//!   so host pointer width cannot move the +0x08/+0x14 fields.
//! - `CollSeq` carries its +0x00 name and +0x0c comparator as `u32`
//!   words for the same reason.

use core::ptr;

use super::error_msg::{sqlite_error_msg, Parse, VaList};
use super::expr_coll_seq::GET_COLL_SEQ_ADDRESS;
use super::find_collation_encoding::find_collation_encoding;

const NO_SUCH_COLLATION_SEQUENCE: &[u8] = b"no such collation sequence: %.*s\0";

/// The prefix of SQLite's `CollSeq` as target-width words: +0x00 the
/// NUL-terminated name, +0x0c the comparator (`xCmp`). `u32` fields keep
/// the layout honest on a 64-bit host.
#[repr(C)]
pub struct CollSeq {
    pub name: u32,
    pub _gap_04: [u32; 2],
    pub x_cmp: u32,
}

/// Observed ABI of `sqlite3GetCollSeq(db, coll, name, name_len)` @
/// [`GET_COLL_SEQ_ADDRESS`].
pub type GetCollSeq = unsafe extern "C" fn(
    db: *mut u8,
    coll: *mut CollSeq,
    name: *const u8,
    name_len: i32,
) -> *mut CollSeq;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_get_coll_seq(
    db: *mut u8,
    coll: *mut CollSeq,
    name: *const u8,
    name_len: i32,
) -> *mut CollSeq {
    let get: GetCollSeq = core::mem::transmute(GET_COLL_SEQ_ADDRESS);
    get(db, coll, name, name_len)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_get_coll_seq(
    _db: *mut u8,
    _coll: *mut CollSeq,
    _name: *const u8,
    _name_len: i32,
) -> *mut CollSeq {
    panic!("locate_coll_seq requires retail helper @ 0x0837a17c")
}

/// Replaceable unported-helper dispatch.
#[derive(Clone, Copy)]
pub struct LocateCollSeqHooks {
    pub get_coll_seq: GetCollSeq,
}

#[cfg(target_os = "none")]
pub const DEFAULT_LOCATE_COLL_SEQ_HOOKS: LocateCollSeqHooks = LocateCollSeqHooks {
    get_coll_seq: retail_get_coll_seq,
};

#[cfg(not(target_os = "none"))]
pub const DEFAULT_LOCATE_COLL_SEQ_HOOKS: LocateCollSeqHooks = LocateCollSeqHooks {
    get_coll_seq: missing_get_coll_seq,
};

/// The target helper operation. A volatile load preserves the real target
/// call rather than allowing LLVM to fold the default dispatch away.
pub static mut LOCATE_COLL_SEQ_HOOKS: LocateCollSeqHooks = DEFAULT_LOCATE_COLL_SEQ_HOOKS;

#[inline(always)]
unsafe fn get_coll_seq_op() -> GetCollSeq {
    ptr::read_volatile(ptr::addr_of!(LOCATE_COLL_SEQ_HOOKS.get_coll_seq))
}

/// `sqlite3LocateCollSeq`: return the collation sequence named `name` for
/// `parse`'s connection encoding, asking the collation factory when the
/// handle is not mid-initialization. Reports
/// `"no such collation sequence: %.*s"` and returns NULL when no usable
/// descriptor exists.
///
/// # Safety
/// `parse` must be a valid [`Parse`] whose `db` is a valid SQLite handle
/// with a live `aDb[0].pSchema` chain. `name` must be readable as the
/// retail helpers require, and NUL-terminated when `name_len < 0`. On
/// target the helper at [`GET_COLL_SEQ_ADDRESS`] must be callable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn locate_coll_seq(
    parse: *mut Parse,
    name: *const u8,
    name_len: i32,
) -> *mut CollSeq {
    let db = (*parse).db;
    // `ldr r0,[r5,#8]; ldr r0,[r0,#20]; ldrb r1,[r0,#89]` — the schema
    // encoding, read as target-width words to survive host pointer width.
    let a_db = db.cast::<u32>().add(2).read() as usize as *mut u8;
    let schema = a_db.cast::<u32>().add(5).read() as usize as *const u8;
    let encoding = schema.add(0x59).read() as u32;
    // `ldrb r6,[r5,#128]` — sqlite3.init.busy.
    let init_busy = db.add(0x80).read();

    let mut coll = find_collation_encoding(db.cast(), encoding, name, name_len, init_busy as i32)
        .cast::<CollSeq>();

    if init_busy != 0 {
        return coll;
    }
    if coll.is_null() || (*coll).x_cmp == 0 {
        coll = get_coll_seq_op()(db, coll, name, name_len);
    }

    if coll.is_null() {
        let mut reported_len = name_len;
        if reported_len < 0 {
            reported_len = crate::libc::strlen::strlen(name) as i32;
        }
        let args = [reported_len as u32, name as usize as u32];
        sqlite_error_msg(parse, NO_SUCH_COLLATION_SEQUENCE.as_ptr(), args.as_ptr() as VaList);
    }
    coll
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;
    use std::vec;
    use std::vec::Vec;

    static HOOK_LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> =
        LazyLock::new(|| try_map_u32_slab(hints::SQLITE_LOCATE_COLL_SEQ, 0x1000).map(|p| p as usize));
    static mut GET_RESULT: *mut CollSeq = ptr::null_mut();
    static mut GET_CALLS: Vec<(*mut u8, *mut CollSeq, *const u8, i32)> = Vec::new();
    static mut FIND_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn recording_get_coll_seq(
        db: *mut u8,
        coll: *mut CollSeq,
        name: *const u8,
        name_len: i32,
    ) -> *mut CollSeq {
        (*ptr::addr_of_mut!(GET_CALLS)).push((db, coll, name, name_len));
        *ptr::addr_of!(GET_RESULT)
    }

    unsafe extern "C" fn recording_set_lookup(
        _db: *mut u8,
        _name: *const u8,
        _name_len: i32,
        _create: i32,
    ) -> *mut u8 {
        *ptr::addr_of!(FIND_RESULT)
    }

    struct HookGuard;
    impl Drop for HookGuard {
        fn drop(&mut self) {
            unsafe {
                LOCATE_COLL_SEQ_HOOKS = DEFAULT_LOCATE_COLL_SEQ_HOOKS;
                super::super::find_collation_encoding::FIND_COLLATION_ENCODING_HOOKS =
                    super::super::find_collation_encoding::DEFAULT_FIND_COLLATION_ENCODING_HOOKS;
            }
        }
    }

    fn install_recorder(get_result: *mut CollSeq, find_set: *mut u8) -> HookGuard {
        unsafe {
            GET_RESULT = get_result;
            FIND_RESULT = find_set;
            (*ptr::addr_of_mut!(GET_CALLS)).clear();
            LOCATE_COLL_SEQ_HOOKS = LocateCollSeqHooks {
                get_coll_seq: recording_get_coll_seq,
            };
            super::super::find_collation_encoding::FIND_COLLATION_ENCODING_HOOKS =
                super::super::find_collation_encoding::FindCollationEncodingHooks {
                    lookup: recording_set_lookup,
                };
        }
        HookGuard
    }

    /// db at slab+0x000, aDb at slab+0x100, schema at slab+0x200.
    unsafe fn db_fixture(slab: *mut u8, encoding: u8, init_busy: u8) -> *mut u8 {
        let a_db = slab.add(0x100);
        let schema = slab.add(0x200);
        slab.cast::<u32>().add(2).write(a_db as u32);
        a_db.cast::<u32>().add(5).write(schema as u32);
        schema.add(0x59).write(encoding);
        slab.add(0x80).write(init_busy);
        slab
    }

    /// A `CollSeq` fixture: name pointer word, comparator word.
    unsafe fn coll_fixture(slab: *mut u8, offset: usize, x_cmp: u32) -> *mut CollSeq {
        let coll = slab.add(offset).cast::<CollSeq>();
        (*coll).name = (slab as usize + 0x300) as u32;
        (*coll).x_cmp = x_cmp;
        coll
    }

    fn parse(db: *mut u8) -> Parse {
        Parse {
            db,
            rc: 0,
            z_err_msg: ptr::null_mut(),
            _gap_0c: [0; 0x12 - 0x0c],
            check_schema: 0,
            _gap_13: [0; 0x40 - 0x13],
            n_err: 0,
        }
    }

    fn slab_or_skip() -> Option<*mut u8> {
        if SLAB.is_none() && note_missing_u32_fixture(module_path!()) {
            return None;
        }
        (*SLAB).map(|p| p as *mut u8)
    }

    #[test]
    fn init_busy_returns_raw_lookup_without_helper_or_error() {
        let _lock = HOOK_LOCK.lock();
        let Some(slab) = slab_or_skip() else { unreachable!() };
        unsafe {
            let db = db_fixture(slab, 2, 1);
            let mut parse = parse(db);
            let _hooks = install_recorder(ptr::null_mut(), ptr::null_mut());
            // Busy handle: even a NULL lookup result comes straight back.
            assert!(locate_coll_seq(&mut parse, b"X\0".as_ptr(), -1).is_null());
            assert!(GET_CALLS.is_empty(), "busy handle skips the factory");
            assert_eq!(parse.n_err, 0, "busy handle reports nothing");
            assert_eq!(parse.rc, 0);
        }
    }

    #[test]
    fn found_with_comparator_skips_factory() {
        let _lock = HOOK_LOCK.lock();
        let Some(slab) = slab_or_skip() else { unreachable!() };
        unsafe {
            let db = db_fixture(slab, 1, 0);
            // NULL name path of find_collation_encoding: default set from
            // db word 11; encoding 1 selects the first 20-byte record.
            let set = coll_fixture(slab, 0x400, 0xdead_beef);
            slab.cast::<u32>().add(11).write(set as u32);
            let mut parse = parse(db);
            let _hooks = install_recorder(ptr::null_mut(), ptr::null_mut());
            let found = locate_coll_seq(&mut parse, ptr::null(), -1);
            assert_eq!(found, set);
            assert!(GET_CALLS.is_empty(), "usable descriptor needs no factory");
            assert_eq!(parse.n_err, 0);
        }
    }

    #[test]
    fn missing_comparator_goes_through_factory() {
        let _lock = HOOK_LOCK.lock();
        let Some(slab) = slab_or_skip() else { unreachable!() };
        unsafe {
            let db = db_fixture(slab, 1, 0);
            let set = coll_fixture(slab, 0x400, 0);
            slab.cast::<u32>().add(11).write(set as u32);
            let upgraded = coll_fixture(slab, 0x500, 0x1234_5678);
            let mut parse = parse(db);
            let _hooks = install_recorder(upgraded, set.cast());
            let found = locate_coll_seq(&mut parse, b"NOCASE\0".as_ptr(), 6);
            assert_eq!(found, upgraded);
            assert_eq!(GET_CALLS.len(), 1);
            assert_eq!(GET_CALLS[0], (db, set, b"NOCASE\0".as_ptr(), 6));
            assert_eq!(parse.n_err, 0);
        }
    }

    #[test]
    fn factory_failure_reports_name_with_given_length() {
        let _lock = HOOK_LOCK.lock();
        let Some(slab) = slab_or_skip() else { unreachable!() };
        unsafe {
            let db = db_fixture(slab, 1, 0);
            // Default set NULL: find returns NULL, helper called with NULL.
            slab.cast::<u32>().add(11).write(0);
            let mut parse = parse(db);
            let _hooks = install_recorder(ptr::null_mut(), ptr::null_mut());
            // Non-NUL-terminated name; name_len >= 0 must skip strlen.
            let found = locate_coll_seq(&mut parse, b"BOGUS".as_ptr(), 5);
            assert!(found.is_null());
            assert_eq!(GET_CALLS.len(), 1);
            assert_eq!(GET_CALLS[0], (db, ptr::null_mut(), b"BOGUS".as_ptr(), 5));
            assert_eq!(parse.n_err, 1, "error reported once");
            assert_eq!(parse.rc, super::super::error_msg::SQLITE_ERROR);
        }
    }

    #[test]
    fn negative_length_uses_strlen_for_report() {
        let _lock = HOOK_LOCK.lock();
        let Some(slab) = slab_or_skip() else { unreachable!() };
        unsafe {
            let db = db_fixture(slab, 1, 0);
            slab.cast::<u32>().add(11).write(0);
            let mut parse = parse(db);
            let _hooks = install_recorder(ptr::null_mut(), ptr::null_mut());
            let found = locate_coll_seq(&mut parse, b"BINARY\0".as_ptr(), -1);
            assert!(found.is_null());
            assert_eq!(GET_CALLS[0].3, -1, "helper sees the raw length");
            assert_eq!(parse.n_err, 1);
            assert_eq!(parse.rc, super::super::error_msg::SQLITE_ERROR);
        }
    }
}
