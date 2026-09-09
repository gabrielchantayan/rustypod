//! SQLite's nested-SQL parser wrapper.
//!
//! - `sqlite_nested_parse` — original: `FUN_0837d7dc` @ 0x0837d7dc
//!   (168 bytes; 17 direct `bl` call sites, binary-scanned). SQLite 3.5.9's
//!   `sqlite3NestedParse`.
//!
//! Algorithm: if `Parse.nested` (+0x13) is already nonzero, return without
//! touching the format, connection, or parser state. Otherwise format the
//! nested SQL through `sqlite_vm_printf` @ 0x08386454. A NULL result latches
//! `db->mallocFailed` (+0x1e) and returns. For text, increment `nested`, save
//! the 92-byte parser state at +0x14c, run `sqlite3RunParser` @ 0x08382580
//! with a NULL error-message out pointer, free the formatted text, restore
//! that state, then decrement `nested`.
//!
//! Binary call-site scan decoded every ARM B/BL word in `osos.dec`: 14 are
//! unconditional `bl` (0x082c6028, 0x082dc158, 0x082dc180, 0x0836eda4,
//! 0x0836f0e4, 0x0836f118, 0x0836f144, 0x083745b4, 0x083755f8,
//! 0x0837595c, 0x083760ac, 0x08379434, 0x0838d5c4) and three are predicated
//! `blne` (0x08375628, 0x08375938, 0x08375988); there are no tail branches.
//! The predicated sites gate nested SQL on a caller flag; this function itself
//! contains no NULL guard for `parse` or its `db` word.
//!
//! Deliberate deviation: the 764-byte `sqlite3RunParser` is unported, so this
//! module exposes the `SQLITE_RUN_PARSER` dispatch seam. Its default is a
//! no-op, the successful parser outcome with no parser-owned state changes.
//! The ported formatter and tracked free are called directly, as their raw
//! `bl` instructions require.

use crate::heap::tracked::tracked_free;

use super::error_msg::VaList;
use super::mem::MALLOC_FAILED_OFFSET;
use super::vm_printf::sqlite_vm_printf;

/// The `Parse` portion that `sqlite3NestedParse` accesses. Pointer-valued
/// fields stay target-width words, so every declared offset is exact on host
/// and ARM; host tests map it below 4 GiB before converting `db` back.
#[repr(C)]
pub struct NestedParse {
    /// +0x00: owning `sqlite3 *` as the target's 32-bit pointer word.
    pub db: u32,
    /// +0x04..+0x12: fields this wrapper does not inspect.
    pub _before_nested: [u8; 0x0f],
    /// +0x13: recursive parser-depth guard.
    pub nested: u8,
    /// +0x14..+0x14b: fields this wrapper does not inspect.
    pub _before_parser_state: [u8; 0x138],
    /// +0x14c..+0x1a7: parser state preserved across nested parsing.
    pub parser_state: [u8; PARSER_STATE_SIZE],
}

/// Bytes copied by each of the two `memcpy` calls (`mov r2,#0x5c`).
pub const PARSER_STATE_SIZE: usize = 0x5c;

const _: [u8; 0x13] = [0; core::mem::offset_of!(NestedParse, nested)];
const _: [u8; 0x14c] = [0; core::mem::offset_of!(NestedParse, parser_state)];
const _: [u8; 0x1a8] = [0; core::mem::size_of::<NestedParse>()];

/// `sqlite3RunParser(parse, sql, pz_err_msg)` @ 0x08382580. The stock wrapper
/// always passes NULL for `pz_err_msg` (`mov r2,#0`).
pub type RunParserFn =
    unsafe extern "C" fn(parse: *mut NestedParse, sql: *const u8, pz_err_msg: *mut u8);

/// Default until the full 764-byte parser lands. It represents the parser's
/// successful no-state-change outcome and, like that outcome, leaves all
/// arguments untouched.
pub(crate) unsafe extern "C" fn missing_run_parser(
    _parse: *mut NestedParse,
    _sql: *const u8,
    _pz_err_msg: *mut u8,
) {
}

/// Active `sqlite3RunParser` operation. Host tests install a recorder; the
/// parser port will replace this default.
pub static mut SQLITE_RUN_PARSER: RunParserFn = missing_run_parser;

/// Volatile read keeps the replaceable parser seam from being const-folded.
#[inline(always)]
pub(crate) fn run_parser_op() -> RunParserFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_RUN_PARSER)) }
}

/// sqlite_nested_parse — original: `FUN_0837d7dc` @ 0x0837d7dc (168 bytes;
/// 17 direct `bl` call sites).
///
/// `sqlite3NestedParse`: format and parse SQL generated while another
/// statement is compiling. Recursion is suppressed; a formatting failure
/// latches the connection's sticky OOM byte. The parser may change ordinary
/// parse fields, but the 92-byte parser-state tail is restored exactly before
/// this wrapper returns.
///
/// Register usage: r0 = `parse`, r1 = `format`, r2/r3/stack = variadic words;
/// `args` is the explicit AAPCS va-list pointer used throughout this crate.
///
/// # Safety
/// `parse` must be a live [`NestedParse`], and its `db` word must be either a
/// live target-width `sqlite3 *` or NULL only when `nested != 0`. The active
/// formatter's and parser seam's pointer requirements also apply.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_nested_parse(
    parse: *mut NestedParse,
    format: *const u8,
    args: VaList,
) {
    let parse = &mut *parse;
    if parse.nested != 0 {
        return;
    }

    let db = parse.db as usize as *mut u8;
    let sql = sqlite_vm_printf(db, format, args);
    if sql.is_null() {
        db.add(MALLOC_FAILED_OFFSET).write(1);
        return;
    }

    parse.nested = parse.nested.wrapping_add(1);
    let parser_state = parse.parser_state;
    (run_parser_op())(parse, sql, core::ptr::null_mut());
    tracked_free(sql);
    parse.parser_state = parser_state;
    parse.nested = parse.nested.wrapping_sub(1);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::tracked::{BLOCK_HEADER_SIZE, TAG_TRACKED};
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use crate::sqlite::mem::tests::install_recorder;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex, MutexGuard};

    const SLAB_LEN: usize = 0x1000;
    const DB_OFFSET: usize = 0x400;

    static SLAB: LazyLock<Option<usize>> =
        LazyLock::new(|| try_map_u32_slab(hints::SQLITE_NESTED_PARSE, SLAB_LEN).map(|p| p as usize));
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut PARSER_CALLS: usize = 0;
    static mut PARSER_NESTED: u8 = 0;
    static mut PARSER_SQL_IS_EMPTY: bool = false;

    /// A tracked allocation with payload at raw+32, suitable for the direct
    /// `tracked_free` call after the parser returns.
    #[repr(align(32))]
    struct TrackedBlock([u8; 64]);

    impl TrackedBlock {
        fn new() -> Self {
            let mut block = Self([0; 64]);
            block.0[0..4].copy_from_slice(&0i32.to_le_bytes());
            block.0[28..32].copy_from_slice(&((32 - BLOCK_HEADER_SIZE) as u32).to_le_bytes());
            block
        }

        fn payload(&mut self) -> *mut u8 {
            unsafe { self.0.as_mut_ptr().add(32) }
        }

        fn raw(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
    }

    unsafe extern "C" fn recording_run_parser(
        parse: *mut NestedParse,
        sql: *const u8,
        pz_err_msg: *mut u8,
    ) {
        assert!(pz_err_msg.is_null(), "stock passes a NULL error-message out pointer");
        PARSER_CALLS += 1;
        PARSER_NESTED = (*parse).nested;
        PARSER_SQL_IS_EMPTY = sql.read() == 0;
        (*parse).parser_state.fill(0xee);
    }

    /// Installs the parser recorder and restores the shipped default on drop.
    struct ParserFixture {
        _guard: MutexGuard<'static, ()>,
    }

    impl ParserFixture {
        fn new() -> Self {
            let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            unsafe {
                PARSER_CALLS = 0;
                PARSER_NESTED = 0;
                PARSER_SQL_IS_EMPTY = false;
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(SQLITE_RUN_PARSER),
                    recording_run_parser,
                );
            }
            Self { _guard: guard }
        }
    }

    impl Drop for ParserFixture {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(SQLITE_RUN_PARSER),
                    missing_run_parser,
                );
            }
        }
    }

    unsafe fn reset_parse(base: *mut u8, nested: u8, state: u8) -> *mut NestedParse {
        ptr::write_bytes(base, 0, SLAB_LEN);
        let parse = base.cast::<NestedParse>();
        parse.write(NestedParse {
            db: base.add(DB_OFFSET) as usize as u32,
            _before_nested: [0; 0x0f],
            nested,
            _before_parser_state: [0; 0x138],
            parser_state: [state; PARSER_STATE_SIZE],
        });
        parse
    }

    #[test]
    fn recursion_guard_skips_formatter_parser_and_every_write() {
        let _parser = ParserFixture::new();
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("sqlite/nested_parse"));
            return;
        };
        unsafe {
            let parse = reset_parse(base as *mut u8, 0xff, 0x3c);
            sqlite_nested_parse(parse, b"ignored\0".as_ptr(), ptr::null());
            assert_eq!((*parse).nested, 0xff);
            assert_eq!((*parse).parser_state, [0x3c; PARSER_STATE_SIZE]);
            assert_eq!(PARSER_CALLS, 0);
        }
    }

    #[test]
    fn formatter_failure_latches_oom_without_running_parser() {
        let _parser = ParserFixture::new();
        let _allocator = install_recorder(ptr::null_mut());
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("sqlite/nested_parse"));
            return;
        };
        unsafe {
            let parse = reset_parse(base as *mut u8, 0, 0x6d);
            sqlite_nested_parse(parse, b"ignored\0".as_ptr(), ptr::null());
            let db = base as *mut u8;
            assert_eq!(db.add(DB_OFFSET + MALLOC_FAILED_OFFSET).read(), 1);
            assert_eq!((*parse).nested, 0);
            assert_eq!((*parse).parser_state, [0x6d; PARSER_STATE_SIZE]);
            assert_eq!(PARSER_CALLS, 0);
        }
    }

    #[test]
    fn parses_then_restores_state_and_frees_formatted_sql() {
        let _parser = ParserFixture::new();
        let _heap = mock_heap();
        let mut allocation = TrackedBlock::new();
        let payload = allocation.payload();
        let raw = allocation.raw();
        let _allocator = install_recorder(payload);
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("sqlite/nested_parse"));
            return;
        };
        unsafe {
            let parse = reset_parse(base as *mut u8, 0, 0x3c);
            sqlite_nested_parse(parse, b"ignored\0".as_ptr(), ptr::null());
            assert_eq!(PARSER_CALLS, 1);
            assert_eq!(PARSER_NESTED, 1, "depth increments before parser entry");
            assert!(PARSER_SQL_IS_EMPTY, "default formatter supplies a NUL string");
            assert_eq!((*parse).nested, 0, "depth decrements after parser return");
            assert_eq!((*parse).parser_state, [0x3c; PARSER_STATE_SIZE]);
            assert_eq!(free_log(), (1, raw, TAG_TRACKED));
        }
    }
}
