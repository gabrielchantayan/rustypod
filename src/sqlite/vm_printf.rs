//! The va_list printf every formatted SQLite diagnostic funnels through —
//! a stack-buffered wrapper around the conversion engine.
//!
//! - `sqlite_vm_printf` — original: `FUN_08386454` @ 0x08386454 (100
//!   bytes; 5 `bl` call sites, binary-scanned). SQLite 3.5.9's
//!   `sqlite3VMPrintf` (`char *sqlite3VMPrintf(sqlite3 *db, const char
//!   *zFormat, va_list ap)` in util.c).
//!
//! Algorithm: build a `StrAccum` (20 bytes at sp+0) over a 350-byte stack
//! base buffer (sp+0x18 — the literal `0x15e` pooled at 0x083864bc) with
//! `sqlite3StrAccumInit` @ 0x08384e84, taking `mxAlloc` from the
//! connection's length limit (`aLimit[0]` at db+0x50) or — for a NULL
//! db — the stock ceiling `SQLITE_MAX_LENGTH` = 1,000,000,000 (the
//! literal `0x3b9aca00` pooled at 0x083864b8). Run the conversion engine
//! `sqlite3VXPrintf` @ 0x0839788c with `useMalloc = 1`, then return
//! `sqlite3StrAccumFinish` @ 0x08384e14's result: a heap-owned
//! NUL-terminated copy of the formatted text, or NULL when its transfer
//! allocation failed. Finally — and only when the accumulator's
//! `mallocFailed` byte (sp+0x14) is set AND db is non-NULL — store 1
//! into `db->mallocFailed` (+0x1e): the sticky SQLITE_NOMEM latch every
//! SQLite entry point checks. A NULL db silently skips the latch (and
//! the `ldreq`/`ldrne` pair shows the limit read is skipped too, so a
//! NULL db is never dereferenced).
//!
//! Call sites (binary-scanned):
//!
//! - 0x08376754 — `sqlite_error` (`sqlite/error.rs`)
//! - 0x083767cc — `sqlite_error_msg` (`sqlite/error_msg.rs`)
//! - 0x0837d368 — `sqlite_set_string_formatted` (`sqlite/set_string_formatted.rs`)
//! - 0x0837d804 — FUN_0837d7dc = `sqlite3NestedParse` (formats nested
//!   SQL, latches `db->mallocFailed` itself on a NULL result, runs the
//!   text through the parser @ 0x08382580)
//! - 0x082c2474 — FUN_082c2438, a refcounted log-string appender; the
//!   only caller passing db == NULL, exercising the literal-default
//!   limit path.
//!
//! Connection fields pinned by the `ldrne r3,[r4,#0x50]` /
//! `strbne r1,[r4,#0x1e]` pair (both match the `sqlite3` layout in the
//! `sqlite` module header):
//!
//! ```text
//! +0x1e mallocFailed   u8   sticky OOM flag, only ever written 1 here
//! +0x50 aLimit[0]      i32  length limit (SQLITE_LIMIT_LENGTH)
//! ```
//!
//! Deviations:
//! - The conversion engine `sqlite3VXPrintf` @ 0x0839788c (3324 bytes)
//!   is not ported: it crosses the [`SQLITE_VXPRINTF`] dispatch seam
//!   (house pattern — `sqlite/error_msg.rs`'s `SQLITE_VM_PRINTF`). The
//!   documented no-op default [`missing_vx_printf`] leaves the
//!   accumulator empty, so the shipped end state is `StrAccumFinish`'s
//!   1-byte empty string — or NULL when the allocator is down, with
//!   the latch still applied. Both are states the original reaches.
//! - The other two callees *are* ported and are called directly, per
//!   the porting rules: `str_accum_init` @ 0x08384e84
//!   ([`super::vdbe_op::str_accum_init`]) and `str_accum_finish` @
//!   0x08384e14 ([`super::str_accum::str_accum_finish`]).
//! - The C `va_list` is the house explicit [`VaList`] pointer — exactly
//!   the `&spilled-arg` the callers build on their stacks (see
//!   `sqlite/error_msg.rs`).
//! - The 20-byte `StrAccum` and the 350-byte base buffer live in the
//!   Rust frame; their exact stack offsets are the compiler's business
//!   (the original's sp+0/sp+0x18 split is visible only in match.py's
//!   frame arithmetic).
//! - This port is the natural wired default of the shared
//!   `SQLITE_VM_PRINTF` dispatch static in `sqlite/error_msg.rs`; that
//!   static lives in a file this port deliberately does not touch, so
//!   its slot keeps the documented always-NULL stub until the seam's
//!   owner swaps it.

use core::mem::MaybeUninit;

use super::error_msg::VaList;
use super::mem::MALLOC_FAILED_OFFSET;
use super::str_accum::{str_accum_finish, StrAccum};
use super::vdbe_op::str_accum_init;

/// Byte offset of `sqlite3.aLimit[SQLITE_LIMIT_LENGTH]` (original:
/// `ldrne r3,[r4,#0x50]`).
pub const DB_LENGTH_LIMIT_OFFSET: usize = 0x50;

/// The stock length ceiling for a NULL db (the literal `0x3b9aca00`
/// pooled at 0x083864b8): SQLite's default `SQLITE_MAX_LENGTH`.
pub const SQLITE_MAX_LENGTH: i32 = 1_000_000_000;

/// The stack base buffer's size in bytes (the literal `0x15e` pooled at
/// 0x083864bc): SQLite's `SQLITE_PRINT_BUF_SIZE`.
pub const PRINT_BUF_SIZE: i32 = 350;

/// The conversion engine: `sqlite3VXPrintf(accum, use_malloc, format,
/// ap)` @ 0x0839788c. Appends `format`, expanded with the variadic words
/// at `ap`, to `accum`; `use_malloc` is 1 when the accumulator may grow
/// on the heap.
pub type VxPrintfFn =
    unsafe extern "C" fn(accum: *mut StrAccum, use_malloc: i32, format: *const u8, ap: VaList);

/// Default stub: no engine wired, so nothing is appended — the empty
/// accumulator makes `str_accum_finish` produce a 1-byte empty string
/// (or NULL when the allocator is down). Both are states the original
/// reaches for an empty format.
pub(crate) unsafe extern "C" fn missing_vx_printf(
    _accum: *mut StrAccum,
    _use_malloc: i32,
    _format: *const u8,
    _ap: VaList,
) {
}

/// The active conversion engine. Host tests install recording mocks;
/// the real port replaces the default when 0x0839788c lands.
pub static mut SQLITE_VXPRINTF: VxPrintfFn = missing_vx_printf;

/// Reads the engine slot (volatile — the slot is meant to be swapped
/// at runtime, and a plain read lets LLVM const-fold the default away).
#[inline(always)]
pub(crate) fn vx_printf_op() -> VxPrintfFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_VXPRINTF)) }
}

/// sqlite_vm_printf — original: `FUN_08386454` @ 0x08386454 (100 bytes;
/// 5 `bl` call sites).
///
/// `sqlite3VMPrintf`: format `format` with the variadic words at `ap` on
/// behalf of connection `db` and return the heap-owned NUL-terminated
/// result (NULL when the accumulator's allocation fails, with
/// `db->mallocFailed` latched). A NULL db formats against the stock
/// length ceiling and is never dereferenced.
///
/// Register usage: r0 = db, r1 = format, r2 = ap (the caller-built
/// va_list pointer — see the module header).
///
/// # Safety
/// When `db` is non-NULL it must name a live `sqlite3` connection whose
/// `aLimit[0]` (+0x50) and `mallocFailed` (+0x1e) bytes are readable /
/// writable. `format` and `ap` are only forwarded to the active
/// [`SQLITE_VXPRINTF`] engine; their requirements are the engine's.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_vm_printf(db: *mut u8, format: *const u8, ap: VaList) -> *mut u8 {
    // Original: raw stack (sp+0x18), never cleared — only the bytes
    // the engine writes are ever copied out by the finish.
    let mut base = MaybeUninit::<[u8; PRINT_BUF_SIZE as usize]>::uninit();
    let mut accum = MaybeUninit::<StrAccum>::uninit();
    // Original: `movs r4,r0` sets the flags once; `ldreq` takes the
    // stock ceiling, `ldrne r3,[r4,#0x50]` the connection's limit — a
    // NULL db is never dereferenced.
    let max_length = if db.is_null() {
        SQLITE_MAX_LENGTH
    } else {
        db.add(DB_LENGTH_LIMIT_OFFSET).cast::<i32>().read()
    };
    let accum = accum.as_mut_ptr();
    str_accum_init(accum, base.as_mut_ptr().cast::<u8>(), PRINT_BUF_SIZE, max_length);
    // Original: `mov r1,#0x1` — the accumulator may grow on the heap.
    (vx_printf_op())(accum, 1, format, ap);
    let text = str_accum_finish(accum);
    // Original: `ldrb r1,[sp,#0x14]` reloads mallocFailed AFTER the
    // finish (the finish itself can set it); `cmpne r4,#0` keeps a NULL
    // db untouched; `strbne` only ever writes 1.
    if (*accum).malloc_failed != 0 && !db.is_null() {
        db.add(MALLOC_FAILED_OFFSET).write(1);
    }
    text
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::sqlite::mem::tests::{install_recorder, realloc_log};
    use std::sync::Mutex;

    /// Serializes tests that swap the engine slot.
    static SLOT_LOCK: Mutex<()> = Mutex::new(());

    /// (use_malloc, format, ap, n_alloc, mx_alloc) the engine observed.
    static mut RECORDED: Option<(i32, *const u8, VaList, i32, i32)> = None;

    /// A stand-in `sqlite3` connection covering the length-limit word
    /// (+0x50) and the `mallocFailed` byte (+0x1e). 4-aligned so the
    /// port's limit word load matches the original's aligned `ldr`.
    #[repr(align(4))]
    struct Db([u8; DB_LENGTH_LIMIT_OFFSET + 4]);

    impl Db {
        fn with_limit(limit: i32) -> Self {
            let mut db = Db([0; DB_LENGTH_LIMIT_OFFSET + 4]);
            db.0[DB_LENGTH_LIMIT_OFFSET..].copy_from_slice(&limit.to_le_bytes());
            db
        }
        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn malloc_failed_flag(&self) -> u8 {
            self.0[MALLOC_FAILED_OFFSET]
        }
    }

    /// Engine that records its arguments and the accumulator's
    /// capacities, then appends the canned text as a formatter would.
    unsafe extern "C" fn recording_vx_printf(
        accum: *mut StrAccum,
        use_malloc: i32,
        format: *const u8,
        ap: VaList,
    ) {
        RECORDED = Some((use_malloc, format, ap, (*accum).n_alloc, (*accum).mx_alloc));
        const TEXT: &[u8] = b"hi";
        (*accum).z_base.copy_from_nonoverlapping(TEXT.as_ptr(), TEXT.len());
        (*accum).n_char = TEXT.len() as i32;
    }

    /// Engine that appends nothing but reports an internal failure —
    /// the too-big / OOM path inside the real conversion engine. Points
    /// zText at static text so the finish takes its no-transfer branch.
    unsafe extern "C" fn failing_vx_printf(
        accum: *mut StrAccum,
        _use_malloc: i32,
        _format: *const u8,
        _ap: VaList,
    ) {
        static mut STATIC_TEXT: [u8; 4] = *b"bad\0";
        (*accum).z_text = core::ptr::addr_of_mut!(STATIC_TEXT).cast::<u8>();
        (*accum).n_char = 3;
        (*accum).malloc_failed = 1;
    }

    /// Serializes and installs `engine` in the slot; restores the
    /// documented default at the end so a failed assert cannot leak the
    /// mock into another test.
    fn with_engine(engine: VxPrintfFn, body: impl FnOnce()) {
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            RECORDED = None;
            core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VXPRINTF), engine);
        }
        body();
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(SQLITE_VXPRINTF),
                missing_vx_printf,
            );
        }
    }

    #[test]
    fn formatted_text_comes_back_as_a_heap_copy_with_the_connection_limit() {
        let mut canned = [0xCCu8; 8];
        let _allocator = install_recorder(canned.as_mut_ptr());
        let mut db = Db::with_limit(4096);
        let format = b"SELECT %d\0".as_ptr();
        let args: [u32; 1] = [7];
        let mut result = core::ptr::null_mut();
        with_engine(recording_vx_printf, || unsafe {
            result = sqlite_vm_printf(db.ptr(), format, args.as_ptr());
            let recorded = core::ptr::read(core::ptr::addr_of!(RECORDED));
            assert_eq!(
                recorded,
                Some((1, format, args.as_ptr(), PRINT_BUF_SIZE, 4096)),
                "engine saw (use_malloc=1, format, ap), accumulator got the buffer size and the db limit"
            );
        });
        assert_eq!(result, canned.as_mut_ptr(), "finish's heap copy is returned verbatim");
        assert_eq!(&canned[..3], b"hi\0", "the transfer copied the text plus terminator");
        assert_eq!(realloc_log(), std::vec![(0, 3)], "request is n_char + 1");
        assert_eq!(db.malloc_failed_flag(), 0, "a clean format never latches the db");
    }

    #[test]
    fn a_null_db_formats_against_the_stock_ceiling_and_is_never_touched() {
        let mut canned = [0xCCu8; 8];
        let _allocator = install_recorder(canned.as_mut_ptr());
        let mut result = core::ptr::null_mut();
        with_engine(recording_vx_printf, || unsafe {
            result = sqlite_vm_printf(
                core::ptr::null_mut(),
                b"log: %s\0".as_ptr(),
                [0u32; 1].as_ptr(),
            );
            let recorded = core::ptr::read(core::ptr::addr_of!(RECORDED));
            assert_eq!(
                recorded.map(|r| r.4),
                Some(SQLITE_MAX_LENGTH),
                "NULL db takes the 1,000,000,000 literal, not a dereference"
            );
        });
        assert_eq!(result, canned.as_mut_ptr());
    }

    #[test]
    fn an_allocator_failure_returns_null_and_latches_db_malloc_failed() {
        let _allocator = install_recorder(core::ptr::null_mut());
        let mut db = Db::with_limit(4096);
        let mut result = 1usize as *mut u8;
        with_engine(recording_vx_printf, || unsafe {
            result = sqlite_vm_printf(db.ptr(), b"x\0".as_ptr(), core::ptr::null());
        });
        assert!(result.is_null(), "the failed transfer is the NULL the callers test for");
        assert_eq!(realloc_log(), std::vec![(0, 3)]);
        assert_eq!(db.malloc_failed_flag(), 1, "SQLITE_NOMEM latch — the original's strbne r1,[r4,#0x1e]");
    }

    #[test]
    fn the_latch_is_never_cleared_once_set() {
        let mut canned = [0xCCu8; 8];
        let _allocator = install_recorder(canned.as_mut_ptr());
        let mut db = Db::with_limit(4096);
        db.0[MALLOC_FAILED_OFFSET] = 1;
        with_engine(recording_vx_printf, || unsafe {
            sqlite_vm_printf(db.ptr(), b"x\0".as_ptr(), core::ptr::null());
        });
        assert_eq!(db.malloc_failed_flag(), 1, "the store only ever writes 1");
    }

    #[test]
    fn a_formatter_reported_failure_latches_the_db_without_allocating() {
        let _allocator = install_recorder(core::ptr::null_mut());
        let mut db = Db::with_limit(4096);
        let mut result = core::ptr::null_mut();
        with_engine(failing_vx_printf, || unsafe {
            result = sqlite_vm_printf(db.ptr(), b"%q\0".as_ptr(), [0u32; 1].as_ptr());
        });
        assert_eq!(db.malloc_failed_flag(), 1, "mallocFailed raised inside the engine still latches");
        assert!(realloc_log().is_empty(), "non-base zText takes the finish's no-transfer branch");
        assert!(!result.is_null(), "the static text is returned as-is");
    }

    #[test]
    fn a_null_db_tolerates_a_formatter_reported_failure() {
        let _allocator = install_recorder(core::ptr::null_mut());
        with_engine(failing_vx_printf, || unsafe {
            let result = sqlite_vm_printf(core::ptr::null_mut(), b"%q\0".as_ptr(), [0u32; 1].as_ptr());
            assert!(!result.is_null(), "no latch store, no crash — the cmpne r4,#0 guard");
        });
    }

    #[test]
    fn the_default_engine_produces_a_one_byte_empty_string() {
        let mut canned = [0xCCu8; 8];
        let _allocator = install_recorder(canned.as_mut_ptr());
        let mut db = Db::with_limit(4096);
        let result = unsafe { sqlite_vm_printf(db.ptr(), b"\0".as_ptr(), core::ptr::null()) };
        assert_eq!(result, canned.as_mut_ptr());
        assert_eq!(canned[0], 0, "an untouched accumulator finishes to \"\\0\"");
        assert_eq!(realloc_log(), std::vec![(0, 1)], "request is 0 + 1");
        assert_eq!(db.malloc_failed_flag(), 0);
    }

    #[test]
    fn the_default_engine_with_a_down_allocator_is_the_shaped_failure() {
        let _allocator = install_recorder(core::ptr::null_mut());
        let mut db = Db::with_limit(4096);
        let result = unsafe { sqlite_vm_printf(db.ptr(), b"\0".as_ptr(), core::ptr::null()) };
        assert!(result.is_null());
        assert_eq!(db.malloc_failed_flag(), 1, "the shipped stub reaches the same latch the original does");
    }
}
