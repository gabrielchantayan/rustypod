//! The parser's error reporter — the single funnel every SQL diagnostic
//! in osos goes through.
//!
//! - `sqlite_error_msg` — original: `FUN_083767a0` @ 0x083767a0 (76
//!   bytes; 86 `bl` + 4 tail `b` call sites, binary-scanned). SQLite's
//!   `sqlite3ErrorMsg`.
//!
//! Algorithm: bump the parse context's error counter (`nErr` at +0x40),
//! release the previous message (`zErrMsg` at +0x08) through
//! `sqlite3_free` @ 0x083906f4, format the replacement with
//! `sqlite3VMPrintf` @ 0x08386454 on the owning connection (`db` at
//! +0x00), store the result back into `zErrMsg`, and — only when the
//! result code (`rc` at +0x04) is still `SQLITE_OK` — set it to
//! `SQLITE_ERROR`. So the *first* error on a statement keeps the result
//! code, while the *message* is always the latest one. The counter
//! increments unconditionally, even when the format comes back NULL
//! (out of memory inside the formatter) — an error was reported either
//! way.
//!
//! `Parse` fields used (all pinned by this one function's
//! `ldr/str [r4, #off]` sequence and cross-checked against the SQLite
//! 3.5.x sources):
//!
//! ```text
//! +0x00 db         (*mut u8)  the owning connection
//! +0x04 rc         (i32)      statement result code (SQLITE_*)
//! +0x08 z_err_msg  (*mut u8)  heap-owned message, replaced per error
//! +0x40 n_err      (i32)      error counter
//! ```
//!
//! Deviations:
//! - `sqlite3VMPrintf` @ 0x08386454 is not ported: its 100 bytes are a
//!   wrapper around the whole SQLite printf chain (StrAccum init
//!   @ 0x08384e84, the conversion engine @ 0x0839788c, StrAccum finish
//!   @ 0x08384e14), a batch of its own. It is the [`SQLITE_VM_PRINTF`]
//!   dispatch boundary (house pattern, see `sqlite/mem.rs`). The default
//!   slot is a documented always-NULL stub — the same end state the
//!   original reaches when the formatter's allocation fails: no message,
//!   but the counter is bumped and `rc` is set.
//! - `sqlite3_free` @ 0x083906f4 *is* ported
//!   (`heap::tracked::tracked_free`) and is called directly, per the
//!   porting rules. LLVM inlines it into the body (as in
//!   `sqlite/mem.rs`); same bytes written, different shape in the
//!   match.py diff.
//! - The original is C-variadic (`void sqlite3ErrorMsg(Parse *, const
//!   char *, ...)`); its prologue spills r0-r3 and passes `&spilled-r2`
//!   as the va_list. The Rust signature replaces the `...` with an
//!   explicit `args: VaList` — exactly the pointer the original builds
//!   (house convention, see `printf/printf_api.rs` for the full
//!   rationale and the trampoline note for calling from firmware code).
//! - `Parse` is a typed `#[repr(C)]` struct rather than raw byte
//!   offsets, so the two pointer fields stay disjoint on a 64-bit test
//!   host. The original byte offsets are statically asserted on 32-bit
//!   targets (`_PARSE_*_OFFSET`).

use crate::heap::tracked::tracked_free;

/// `va_list` as the original builds it: a pointer to the next variadic
/// argument word (AAPCS: variadic args are consecutive 32-bit words in
/// the spilled registers / on the stack). Same convention as
/// `printf::printf_api::VaList`.
pub type VaList = *const u32;

/// Statement result code "no error so far" (original: `cmp r0, #0`).
pub const SQLITE_OK: i32 = 0;

/// Statement result code for a generic SQL error (original:
/// `moveq r0, #1`).
pub const SQLITE_ERROR: i32 = 1;

/// A parse context (`sqlite3Parse`), only the fields this reporter
/// touches. See the module header for the original byte offsets.
#[repr(C)]
pub struct Parse {
    /// +0x00: the owning connection (`sqlite3 *`).
    pub db: *mut u8,
    /// +0x04: statement result code; first error wins.
    pub rc: i32,
    /// +0x08: heap-owned error message, replaced on every report.
    pub z_err_msg: *mut u8,
    /// +0x0c..+0x40: unmodeled.
    pub _gap_0c: [u8; 0x40 - 0x0c],
    /// +0x40: error counter, bumped on every report.
    pub n_err: i32,
}

// The original's byte offsets, asserted on the 32-bit target. On a
// 64-bit host the pointer fields widen and these shift — harmless,
// because all access goes through the typed struct.
#[cfg(target_pointer_width = "32")]
const _PARSE_RC_OFFSET: [u8; 0x04] = [0; core::mem::offset_of!(Parse, rc)];
#[cfg(target_pointer_width = "32")]
const _PARSE_Z_ERR_MSG_OFFSET: [u8; 0x08] = [0; core::mem::offset_of!(Parse, z_err_msg)];
#[cfg(target_pointer_width = "32")]
const _PARSE_N_ERR_OFFSET: [u8; 0x40] = [0; core::mem::offset_of!(Parse, n_err)];

/// The message formatter: `sqlite3VMPrintf(db, format, ap)` @
/// 0x08386454. Returns a heap-owned NUL-terminated string, or NULL when
/// its allocation fails.
pub type VmPrintfFn = unsafe extern "C" fn(db: *mut u8, format: *const u8, ap: VaList) -> *mut u8;

/// Default stub: no formatter wired, so the message comes back NULL —
/// the same shape as a failed allocation inside the real formatter (see
/// the module header).
pub(crate) unsafe extern "C" fn missing_vm_printf(
    _db: *mut u8,
    _format: *const u8,
    _ap: VaList,
) -> *mut u8 {
    core::ptr::null_mut()
}

/// The active formatter. Host tests install recording mocks; the real
/// port replaces the default when 0x08386454 lands.
pub static mut SQLITE_VM_PRINTF: VmPrintfFn = missing_vm_printf;

/// Reads the formatter slot (volatile — the slot is meant to be swapped
/// at runtime, and a plain read lets LLVM const-fold the default away).
#[inline(always)]
pub(crate) fn vm_printf_op() -> VmPrintfFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_VM_PRINTF)) }
}

/// sqlite_error_msg — original: `FUN_083767a0` @ 0x083767a0 (76 bytes;
/// 86 `bl` + 4 tail `b` call sites).
///
/// `sqlite3ErrorMsg`: record an error on the parse context. Bumps
/// `n_err`, frees the previous `z_err_msg` (a NULL old message is a
/// no-op inside `tracked_free`), formats the replacement through the
/// [`SQLITE_VM_PRINTF`] formatter and installs it, and sets `rc` to
/// [`SQLITE_ERROR`] unless a result code is already latched.
///
/// Register usage: r0 = parse, r1 = format, r2/r3/stack = varargs
/// (original builds `ap` = &spilled-r2; here `args` IS that pointer).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_error_msg(parse: *mut Parse, format: *const u8, args: VaList) {
    let parse = &mut *parse;
    // Original: `ldr/add/str [r4, #0x40]` — a plain ARM add, it wraps.
    parse.n_err = parse.n_err.wrapping_add(1);
    tracked_free(parse.z_err_msg);
    parse.z_err_msg = (vm_printf_op())(parse.db, format, args);
    if parse.rc == SQLITE_OK {
        parse.rc = SQLITE_ERROR;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::tracked::{BLOCK_HEADER_SIZE, TAG_TRACKED};
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{tests::mock_heap, HEAP_OPS};
    use std::sync::MutexGuard;

    /// (db, format, ap) of the last formatter invocation.
    static mut RECORDED: Option<(*mut u8, *const u8, VaList)> = None;
    /// Message the recording formatter hands back.
    static mut NEXT_MESSAGE: *mut u8 = core::ptr::null_mut();
    /// (raw block, tag) of the last free the mock heap saw.
    static mut FREED: Option<(*mut u8, usize)> = None;

    unsafe extern "C" fn recording_vm_printf(db: *mut u8, format: *const u8, ap: VaList) -> *mut u8 {
        RECORDED = Some((db, format, ap));
        NEXT_MESSAGE
    }

    unsafe extern "C" fn recording_free(
        _heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        FREED = Some((ptr, tag));
    }

    /// Serializes against every other heap-ops-swapping test and installs
    /// the mock heap table. The returned guard must stay alive for the
    /// whole test.
    fn bench() -> MutexGuard<'static, ()> {
        let guard = mock_heap();
        unsafe {
            RECORDED = None;
            FREED = None;
        }
        guard
    }

    /// Swaps in the recording formatter for `body`, then restores the
    /// documented default so a failed assertion cannot leak the mock
    /// into the next test.
    unsafe fn with_formatter(message: *mut u8, body: impl FnOnce()) {
        NEXT_MESSAGE = message;
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VM_PRINTF), recording_vm_printf);
        body();
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VM_PRINTF), missing_vm_printf);
    }

    /// Routes frees into [`recording_free`] (the mock heap's `create` is
    /// what `lazy_init_default_heap` needs; the free slot is the only one
    /// replaced).
    unsafe fn with_recording_free(body: impl FnOnce()) {
        (*core::ptr::addr_of_mut!(HEAP_OPS)).free = recording_free;
        body();
    }

    fn parse(db: *mut u8, rc: i32, message: *mut u8, n_err: i32) -> Parse {
        Parse { db, rc, z_err_msg: message, _gap_0c: [0xa5; 0x40 - 0x0c], n_err }
    }

    /// A hand-built tag-57 tracked block (layout: `heap::tracked`). Raw
    /// block at offset 0 of a 32-aligned buffer, payload at raw + 32,
    /// pad word 32 - 8 = 24.
    #[repr(align(32))]
    struct TrackedBlock([u8; 64]);

    impl TrackedBlock {
        fn new(size: i32) -> Self {
            let mut block = TrackedBlock([0; 64]);
            block.0[0..4].copy_from_slice(&size.to_le_bytes());
            let pad = (32 - BLOCK_HEADER_SIZE) as u32;
            block.0[28..32].copy_from_slice(&pad.to_le_bytes());
            block
        }
        fn raw(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn payload(&mut self) -> *mut u8 {
            // In-bounds by construction (64-byte block, payload at 32).
            unsafe { self.0.as_mut_ptr().add(32) }
        }
    }

    #[test]
    fn the_first_error_latches_the_result_code_and_installs_the_message() {
        let _guard = bench();
        let mut db = [0u8; 8];
        let mut canned = b"near \"x\": syntax error\0".to_vec();
        let message = canned.as_mut_ptr();
        let format = b"near \"%T\": syntax error\0".as_ptr();
        let args: [u32; 1] = [0xc0ff_ee00];
        let mut parse = parse(db.as_mut_ptr(), SQLITE_OK, core::ptr::null_mut(), 41);
        unsafe {
            with_formatter(message, || {
                sqlite_error_msg(&mut parse, format, args.as_ptr());
            });
            assert_eq!(parse.n_err, 42, "counter bumped");
            assert_eq!(parse.z_err_msg, message, "formatted message installed");
            assert_eq!(parse.rc, SQLITE_ERROR, "SQLITE_ERROR latched");
            let recorded = core::ptr::read(core::ptr::addr_of!(RECORDED));
            assert_eq!(
                recorded,
                Some((db.as_mut_ptr(), format, args.as_ptr())),
                "formatter saw (db, format, ap)"
            );
        }
    }

    #[test]
    fn an_existing_result_code_is_kept_but_the_message_is_replaced() {
        let _guard = bench();
        let mut db = [0u8; 8];
        let mut canned = b"new\0".to_vec();
        let message = canned.as_mut_ptr();
        let mut parse = parse(db.as_mut_ptr(), 5, core::ptr::null_mut(), 1);
        unsafe {
            with_formatter(message, || {
                sqlite_error_msg(&mut parse, b"x\0".as_ptr(), core::ptr::null());
            });
            assert_eq!(parse.rc, 5, "first error keeps the result code");
            assert_eq!(parse.z_err_msg, message, "message is the latest one");
            assert_eq!(parse.n_err, 2);
        }
    }

    #[test]
    fn the_old_message_is_released_with_tag_fifty_seven() {
        let _guard = bench();
        let mut db = [0u8; 8];
        let mut old = TrackedBlock::new(24);
        let raw = old.raw();
        let payload = old.payload();
        let mut parse = parse(db.as_mut_ptr(), SQLITE_OK, payload, 0);
        unsafe {
            with_recording_free(|| {
                with_formatter(core::ptr::null_mut(), || {
                    sqlite_error_msg(&mut parse, b"x\0".as_ptr(), core::ptr::null());
                });
            });
            let freed = core::ptr::read(core::ptr::addr_of!(FREED));
            assert_eq!(freed, Some((raw, TAG_TRACKED)), "raw block freed with tag 57");
            assert_eq!(parse.n_err, 1);
        }
    }

    #[test]
    fn a_null_old_message_releases_nothing() {
        let _guard = bench();
        let mut db = [0u8; 8];
        let mut parse = parse(db.as_mut_ptr(), SQLITE_OK, core::ptr::null_mut(), 0);
        unsafe {
            with_recording_free(|| {
                with_formatter(core::ptr::null_mut(), || {
                    sqlite_error_msg(&mut parse, b"x\0".as_ptr(), core::ptr::null());
                });
            });
            let freed = core::ptr::read(core::ptr::addr_of!(FREED));
            assert_eq!(freed, None, "tracked_free(NULL) is a documented no-op");
            assert_eq!(parse.rc, SQLITE_ERROR);
        }
    }

    #[test]
    fn the_error_counter_wraps_like_the_original() {
        let _guard = bench();
        let mut db = [0u8; 8];
        let mut parse = parse(db.as_mut_ptr(), SQLITE_OK, core::ptr::null_mut(), i32::MAX);
        unsafe {
            with_formatter(core::ptr::null_mut(), || {
                sqlite_error_msg(&mut parse, b"x\0".as_ptr(), core::ptr::null());
            });
            assert_eq!(parse.n_err, i32::MIN, "plain ARM add, no saturation");
        }
    }

    #[test]
    fn the_default_formatter_reports_the_error_without_a_message() {
        let _guard = bench();
        let mut db = [0u8; 8];
        let mut parse = parse(db.as_mut_ptr(), SQLITE_OK, core::ptr::null_mut(), 9);
        unsafe {
            sqlite_error_msg(&mut parse, b"x\0".as_ptr(), core::ptr::null());
            assert_eq!(parse.n_err, 10, "counter bumped even with no message");
            assert!(parse.z_err_msg.is_null(), "default stub: no message");
            assert_eq!(parse.rc, SQLITE_ERROR, "the error is still recorded");
        }
    }

    #[test]
    fn nothing_outside_the_four_fields_is_written() {
        let _guard = bench();
        let mut db = [0u8; 8];
        let mut canned = b"msg\0".to_vec();
        let message = canned.as_mut_ptr();
        let mut parse = parse(db.as_mut_ptr(), 3, core::ptr::null_mut(), 7);
        unsafe {
            with_formatter(message, || {
                sqlite_error_msg(&mut parse, b"x\0".as_ptr(), core::ptr::null());
            });
            assert!(parse._gap_0c.iter().all(|b| *b == 0xa5), "gap clobbered");
        }
    }
}
