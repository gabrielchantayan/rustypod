//! Ports of the ADS 1.0.1 stdio open/close/init cluster — `_initio` (the
//! stdio arm of `__rt_lib_init`, runtime/lib_init.rs) and the
//! freopen/fclose machinery it is built on:
//!
//! - `fclose_core` — original: `FUN_08030238` @ 0x08030238 (152 bytes).
//!   The fclose engine minus FILE-object deallocation; see its docs.
//!   Callers (binary-verified): the locked wrapper @ 0x080302d0
//!   (another agent's port) and `freopen_core`.
//! - `fseek` — original: `FUN_0802fef0` @ 0x0802fef0 (72 bytes). The
//!   public fseek entry: a (patched-out) lock bracket around the seek
//!   core @ 0x0802fd04 — unported, dispatched through [`STREAM_SEEK_CORE`].
//!   Six callers (scanf/stdio/C++ layers + `freopen_core`'s append path).
//! - `freopen_core` — original: `FUN_08030300` @ 0x08030300 (252 bytes).
//!   fclose + mode-string parse + `_sys_open` + stream re-init; see docs.
//!   Callers: `fopen` @ 0x080303fc (unported) and `stdio_init` (x3).
//! - `stdio_init` — original: `FUN_080304a0` @ 0x080304a0 (388 bytes);
//!   the ADS `_initio`. Sole caller: `rt_lib_init_for_abort` @ 0x08035788.
//!   Zeroes the three static FILE objects, chains stdin -> stdout ->
//!   stderr, reopens each on the ARM semihosting console device ":tt"
//!   (modes "r"/"w"/"w"; rodata name copies @ 0x08985ee4/e8/ec), then
//!   line-buffers them via `setvbuf_core` (sizes 0x40/0x40/0x10). Every
//!   failure raises SIGRTRED (8) with the ":tt" name as the detail
//!   string (`__rt_raise`, raise.rs).
//!
//! The `bl 0x08037db8` the originals clear memory with is an 8-byte
//! veneer (`ldr pc, [pc, #-4]` -> 0x2200027c): the IRAM-relocated copy of
//! `memzero_aligned` @ 0x0800027c (the whole veneer block
//! 0x08037db8..0x08037e40 jumps into the 0x22000000 IRAM image of the
//! low-address libc block — offsets match: 0x220000d4 = memmove
//! @ 0x080000d4, 0x220002d4 = memzero @ 0x080002d4). The ports replace
//! those byte-length clears (0x3c on close, 0x44 at init — exact on the
//! 32-bit device layout) with typed field/struct resets over the same
//! fields, which stay correct on wider test hosts where the pointer
//! fields inflate the struct.
//!
//! The per-stream lock brackets (`mov r0, lock; mov r0, r0`) are the
//! patched-out mutex hooks — omitted, house precedent (stream_flags.rs).
//! The per-stream/list "lock init" calls in `stdio_init` go to
//! 0x080320a0, which retailOS links as the return-0 stub
//! `sys_stub_ret0_2` (semihost.rs, ported) — the port keeps the calls and
//! the (dead, stub returns 0) string-mode fallback marking.
//!
//! Deviations:
//! - Unported callees dispatch through hooks (house pattern):
//!   [`STREAM_SYNC_CORE`] (original 0x0802fc00 — the flush/position-sync
//!   core shared with fflush @ 0x0802fcb0/0x0802fcd4 and 0x08030118;
//!   stream_file.rs reaches the same routine as its `STREAM_CLOSE_CORE`
//!   hook) and [`STREAM_SEEK_CORE`] (original 0x0802fd04). Defaults:
//!   sync reports success (nothing buffered in a fresh port), seek
//!   reports failure (-1 — it cannot move a real file cursor).
//! - The linked-out post-close hook at 0x080302a4 (called when
//!   `flags & 0xfe000000 == 0xac000000`, a nop'd `bl` whose result the
//!   original would return) is dropped; the return value stays 0 exactly
//!   as the nop'd code computes.
//! - `__rt_raise`'s detail argument is an i32 word that carries a string
//!   pointer for SIGRTRED; on 64-bit hosts the pointer is truncated
//!   (documented raise.rs deviation — meaningful on the 32-bit target).
//! - The heap-allocated-buffer free goes through stream_file.rs's
//!   [`crate::stream_file::STDIO_FREE`] slot (defaults to the ported
//!   `free`) for the same test-isolation reason documented there.

use crate::fread::{AdsStream, FLAG_STRING_MODE};
use crate::raise::{__rt_raise, SIGRTRED};
use crate::semihost::{_sys_close, _sys_open, sys_stub_ret0_2};
use crate::stream_file::{stderr_file, stdin_file, stdout_file, AdsFile, ADS_FILE_ZERO, STDIO_FREE};
use crate::stream_flags::setvbuf_core;

/// flags mask: stream is open for reading (0x1) and/or writing (0x2).
const FLAG_OPEN_MASK: u32 = 0x3;
/// flags bit: binary mode ('b' in the mode string).
const FLAG_BINARY: u32 = 0x4;
/// flags bit: when set, `fclose_core` skips the sync/`_sys_close`/free
/// sequence and only resets the stream (producer not yet identified —
/// never set by `freopen_core`; a pseudo/string-stream marker).
const FLAG_SKIP_CLOSE: u32 = 0x8;
/// flags bit: the stream buffer was heap-allocated and is freed on close.
const FLAG_HEAP_BUFFER: u32 = 0x800;
/// flags value for mode 'a': write + the 0x8000 append marker (literal
/// pool @ 0x08030694).
const FLAGS_APPEND: u32 = 0x8002;
/// High-byte signature gating the linked-out post-close hook
/// (`flags & 0xfe000000 == 0xac000000`; see module docs).
const CLOSE_HOOK_SIGNATURE_MASK: u32 = 0xfe00_0000;
/// See [`CLOSE_HOOK_SIGNATURE_MASK`].
const CLOSE_HOOK_SIGNATURE: u32 = 0xac00_0000;
// (The close-path reset covers the first 0x3c bytes of the FILE — the
// 48-byte stream prefix plus the three words to +0x3c, sparing lock and
// chain link; the init-path clear covers the full 0x44 object. Both are
// typed field resets here — see the module deviations.)
/// setvbuf mode 0x200: line-buffered (_IOLBF), the init default.
const IOLBF: u32 = 0x200;
/// Default buffer size installed by `freopen_core` at +0x1c before
/// setvbuf overrides it (ADS BUFSIZ' companion default).
const DEFAULT_BULK_THRESHOLD: i32 = 0x200;
/// The ARM semihosting console device name (rodata copies
/// @ 0x08985ee4/0x08985ee8/0x08985eec — one per static stream; a single
/// copy here). Also the SIGRTRED detail string on init failure.
static TT_CONSOLE_NAME: [u8; 4] = *b":tt\0";

/// The flush/position-sync core — original 0x0802fc00, ported in
/// `seek_core.rs`. `take_lock` is the original's r1: nonzero brackets
/// the work in the (patched-out) stream lock.
pub type StreamSyncFn = unsafe extern "C" fn(file: *mut AdsFile, take_lock: i32) -> i32;
/// The seek core — original 0x0802fd04, ported in `seek_core.rs`.
/// whence: 0 = set, 1 = cur, 2 = end (ISO C values, `freopen_core` uses 2).
pub type StreamSeekFn = unsafe extern "C" fn(file: *mut AdsFile, offset: i32, whence: i32) -> i32;

/// Test double: report success without touching the stream, so the
/// `stdio_init` tests observe this module's behavior in isolation from
/// the real sync engine.
#[cfg(test)]
unsafe extern "C" fn stream_sync_stub(_file: *mut AdsFile, _take_lock: i32) -> i32 {
    0
}

/// Test double: report failure — cannot move a file cursor.
#[cfg(test)]
unsafe extern "C" fn stream_seek_stub(_file: *mut AdsFile, _offset: i32, _whence: i32) -> i32 {
    -1
}

/// Flush/position-sync entry — the real port @ 0x0802fc00, so the
/// firmware build links the original call graph.
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut STREAM_SYNC_CORE: StreamSyncFn = crate::seek_core::stream_sync_core;

/// Seek-core entry — the real port @ 0x0802fd04.
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut STREAM_SEEK_CORE: StreamSeekFn = crate::seek_core::fseek_core;

/// Volatile hook read (keeps runtime swapping alive; house pattern).
#[inline(always)]
unsafe fn hook<T: Copy>(slot: *const T) -> T {
    core::ptr::read_volatile(slot)
}

/// fclose_core — original: `FUN_08030238` @ 0x08030238 (152 bytes).
///
/// The fclose engine minus deallocation of the FILE object itself:
/// - not open (`flags & 3 == 0`): return -1, stream untouched;
/// - unless [`FLAG_SKIP_CLOSE`]: sync via [`STREAM_SYNC_CORE`]`(file, 0)`,
///   `_sys_close(handle)` — a negative result returns -1 with the stream
///   NOT reset — and free the buffer when [`FLAG_HEAP_BUFFER`] is set
///   (the linked-out 0xac-signature post-close hook is dropped, see
///   module docs);
/// - reset: zero the first 0x3c bytes (lock and chain link survive) and
///   rewrite flags as `flags & 0x1000000` (only the string-mode bit
///   survives). Returns 0.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fclose_core(file: *mut AdsFile) -> i32 {
    let flags = (*file).stream.flags;
    if flags & FLAG_OPEN_MASK == 0 {
        return -1;
    }
    if flags & FLAG_SKIP_CLOSE == 0 {
        hook(core::ptr::addr_of!(STREAM_SYNC_CORE))(file, 0);
        let buffer = (*file).stream.base;
        if _sys_close((*file).stream.handle) < 0 {
            return -1;
        }
        if flags & FLAG_HEAP_BUFFER != 0 {
            hook(core::ptr::addr_of!(STDIO_FREE))(buffer);
        }
        // Linked-out post-close hook (CLOSE_HOOK_SIGNATURE): nop'd, and
        // the result word it would produce is already 0.
        let _ = flags & CLOSE_HOOK_SIGNATURE_MASK == CLOSE_HOOK_SIGNATURE;
    }
    // Original: IRAM memclr of the first 0x3c bytes (lock and chain link
    // at +0x3c/+0x40 survive) — a typed reset here (module deviations).
    (*file).stream = ADS_FILE_ZERO.stream;
    (*file).field_30 = 0;
    (*file).field_34 = 0;
    (*file).field_38 = 0;
    (*file).stream.flags = flags & FLAG_STRING_MODE;
    0
}

/// fseek — original: `FUN_0802fef0` @ 0x0802fef0 (72 bytes).
///
/// The public fseek entry: the (patched-out) per-stream lock bracket
/// around the seek core @ 0x0802fd04 ([`STREAM_SEEK_CORE`]), whose
/// result passes through.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fseek(file: *mut AdsFile, offset: i32, whence: i32) -> i32 {
    hook(core::ptr::addr_of!(STREAM_SEEK_CORE))(file, offset, whence)
}

/// freopen_core — original: `FUN_08030300` @ 0x08030300 (252 bytes).
///
/// 1. `fclose_core(file)` — result ignored (a never-opened stream just
///    returns -1).
/// 2. Parse the mode string: 'r' -> flags 1 / open-mode 0, 'w' -> 2 / 4,
///    'a' -> 0x8002 / 8, anything else -> return NULL. Then any run of
///    '+' (flags |= 3, mode |= 2) and 'b' (flags |= 4, mode |= 1); a
///    final 't' adds 0x10 to the open mode. (The open mode is the ARM
///    semihosting SYS_OPEN mode index.)
/// 3. `_sys_open(name, mode)`; a result of exactly -1 returns NULL.
/// 4. Re-init: buffer base and read cursor NULL, +0x1c = 0x200 (default
///    bulk threshold), handle installed, flags = (old & string-mode bit)
///    | parsed flags. Append mode then seeks to the end (`fseek(file, 0,
///    2)`, result ignored). Returns `file`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn freopen_core(
    name: *const u8,
    mode: *const u8,
    file: *mut AdsFile,
) -> *mut AdsFile {
    fclose_core(file);
    let mut p = mode;
    let first = *p;
    p = p.add(1);
    let (mut flags, mut open_mode) = match first {
        b'a' => (FLAGS_APPEND, 8u32),
        b'r' => (1, 0),
        b'w' => (2, 4),
        _ => return core::ptr::null_mut(),
    };
    let last = loop {
        let c = *p;
        p = p.add(1);
        match c {
            b'+' => {
                flags |= 3;
                open_mode |= 2;
            }
            b'b' => {
                flags |= FLAG_BINARY;
                open_mode |= 1;
            }
            _ => break c,
        }
    };
    if last == b't' {
        open_mode |= 0x10;
    }
    let handle = _sys_open(name, open_mode as i32);
    if handle == -1 {
        return core::ptr::null_mut();
    }
    (*file).stream.base = core::ptr::null_mut();
    (*file).stream.ptr = core::ptr::null_mut();
    (*file).stream.bulk_threshold = DEFAULT_BULK_THRESHOLD;
    let old_flags = (*file).stream.flags;
    (*file).stream.handle = handle;
    (*file).stream.flags = (old_flags & FLAG_STRING_MODE) | flags;
    if open_mode & 8 != 0 {
        fseek(file, 0, 2);
    }
    file
}

/// stdio_init — original: `FUN_080304a0` @ 0x080304a0 (388 bytes); the
/// ADS `_initio`. Sole caller: `rt_lib_init_for_abort` @ 0x08035788.
///
/// Zeroes the three static FILE objects (0x44 bytes each), chains
/// stdin -> stdout -> stderr, runs the per-stream and list lock-init
/// calls (retailOS links them to the return-0 stub @ 0x080320a0; a
/// nonzero return would mark the stream string-mode — dead), reopens
/// each stream on the semihosting console ":tt" ("r"/"w"/"w") and
/// line-buffers it (`setvbuf_core`, sizes 0x40/0x40/0x10). Any freopen
/// NULL or setvbuf nonzero raises SIGRTRED (8) with the ":tt" pointer as
/// detail; execution continues after a handled raise, exactly like the
/// original's fall-through.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stdio_init() {
    let streams = [stdin_file(), stdout_file(), stderr_file()];
    for file in streams {
        // Original: IRAM memclr of the full 0x44-byte FILE object — a
        // typed reset here (module deviations).
        *file = ADS_FILE_ZERO;
    }
    (*streams[0]).link = streams[1];
    (*streams[1]).link = streams[2];
    // Per-stream lock init (return-0 stub on this build; the original
    // passes &file.lock, dropped by the ported stub's signature).
    for file in streams {
        if sys_stub_ret0_2() != 0 {
            (*file).stream.flags |= FLAG_STRING_MODE;
        }
    }
    // Stream-list lock init (original arg: the list lock @ 0x08a0fc04).
    sys_stub_ret0_2();
    let tt = TT_CONSOLE_NAME.as_ptr();
    // SIGRTRED detail: the ":tt" pointer in the i32 code word (truncated
    // on 64-bit hosts — see module docs).
    let tt_detail = tt as usize as i32;
    for (file, mode) in [
        (streams[0], b"r\0".as_ptr()),
        (streams[1], b"w\0".as_ptr()),
        (streams[2], b"w\0".as_ptr()),
    ] {
        if freopen_core(tt, mode, file).is_null() {
            __rt_raise(SIGRTRED, tt_detail);
        }
    }
    for (file, size) in [(streams[0], 0x40u32), (streams[1], 0x40), (streams[2], 0x10)] {
        if setvbuf_core(file as *mut AdsStream, core::ptr::null_mut(), IOLBF, size) != 0 {
            __rt_raise(SIGRTRED, tt_detail);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::semihost::tests::{mock_swi, restore_swi, SWI_LOG, SWI_RESULTS};
    use crate::semihost::{SYS_CLOSE, SYS_OPEN};
    use crate::stream_file::ADS_FILE_ZERO;
    use std::sync::MutexGuard;
    use std::vec::Vec;

    /// Event log for the hook/free mocks.
    static mut EVENTS: Vec<(&'static str, usize, usize)> = Vec::new();

    unsafe extern "C" fn recording_sync(file: *mut AdsFile, take_lock: i32) -> i32 {
        (*core::ptr::addr_of_mut!(EVENTS)).push(("sync", file as usize, take_lock as usize));
        0
    }

    unsafe extern "C" fn recording_seek(file: *mut AdsFile, offset: i32, whence: i32) -> i32 {
        let _ = file;
        (*core::ptr::addr_of_mut!(EVENTS)).push(("seek", offset as usize, whence as usize));
        7
    }

    unsafe extern "C" fn recording_free(ptr: *mut u8) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(("free", ptr as usize, 0));
    }

    /// Locks the SWI boundary (shared with semihost/stream_file tests),
    /// scripts its results, and resets this module's hooks + the static
    /// FILE objects.
    fn lock_and_reset(results: &[i32]) -> MutexGuard<'static, ()> {
        let guard = mock_swi(results);
        unsafe {
            STREAM_SYNC_CORE = stream_sync_stub;
            STREAM_SEEK_CORE = stream_seek_stub;
            crate::stream_file::STDIO_FREE = crate::malloc_rt::free;
            *stdin_file() = ADS_FILE_ZERO;
            *stdout_file() = ADS_FILE_ZERO;
            *stderr_file() = ADS_FILE_ZERO;
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
        }
        guard
    }

    fn events() -> Vec<(&'static str, usize, usize)> {
        unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
    }

    fn swi_ops() -> Vec<usize> {
        unsafe { (*core::ptr::addr_of!(SWI_LOG)).iter().map(|(op, _)| *op).collect() }
    }

    /// An open FILE with recognizable field values for reset checks.
    unsafe fn open_file(flags: u32, handle: i32) -> AdsFile {
        let mut f = ADS_FILE_ZERO;
        f.stream.flags = flags;
        f.stream.handle = handle;
        f.stream.count = 11;
        f.stream.offset_end = 22;
        f.lock = 0x77;
        f.link = 0x1234 as *mut AdsFile;
        f
    }

    // --- fclose_core -----------------------------------------------------

    #[test]
    fn fclose_not_open_stream_fails_untouched() {
        let _guard = lock_and_reset(&[]);
        unsafe {
            let mut f = open_file(0, 5);
            f.stream.flags = FLAG_BINARY; // not open: no 0x1/0x2 bit
            assert_eq!(fclose_core(&mut f), -1);
            assert_eq!(f.stream.flags, FLAG_BINARY, "untouched");
            assert_eq!(f.stream.count, 11);
            assert!(events().is_empty());
            assert!(swi_ops().is_empty(), "no _sys_close issued");
            restore_swi();
        }
    }

    #[test]
    fn fclose_success_syncs_closes_and_resets() {
        let _guard = lock_and_reset(&[0]); // _sys_close -> 0
        unsafe {
            STREAM_SYNC_CORE = recording_sync;
            let mut f = open_file(1, 5);
            assert_eq!(fclose_core(&mut f), 0);
            assert_eq!(events(), std::vec![("sync", &f as *const _ as usize, 0)]);
            assert_eq!(swi_ops(), std::vec![SYS_CLOSE]);
            let log = &(*core::ptr::addr_of!(SWI_LOG));
            assert_eq!(log[0].1[0], 5, "handle 5 closed");
            // First 0x3c bytes cleared, lock/link survive, flags reset.
            assert_eq!(f.stream.count, 0);
            assert_eq!(f.stream.offset_end, 0);
            assert_eq!(f.stream.handle, 0);
            assert_eq!(f.stream.flags, 0);
            assert_eq!(f.lock, 0x77, "lock word survives");
            assert_eq!(f.link as usize, 0x1234, "chain link survives");
            restore_swi();
        }
    }

    #[test]
    fn fclose_preserves_only_the_string_mode_bit() {
        let _guard = lock_and_reset(&[0]);
        unsafe {
            let mut f = open_file(FLAG_STRING_MODE | 2 | FLAG_BINARY, 3);
            assert_eq!(fclose_core(&mut f), 0);
            assert_eq!(f.stream.flags, FLAG_STRING_MODE);
            restore_swi();
        }
    }

    #[test]
    fn fclose_failure_leaves_stream_unreset() {
        let _guard = lock_and_reset(&[-1]); // _sys_close fails
        unsafe {
            let mut f = open_file(1, 5);
            assert_eq!(fclose_core(&mut f), -1);
            assert_eq!(f.stream.count, 11, "no reset on close failure");
            assert_eq!(f.stream.flags, 1);
            restore_swi();
        }
    }

    #[test]
    fn fclose_frees_heap_buffer_only_when_flagged() {
        let _guard = lock_and_reset(&[0, 0]);
        unsafe {
            crate::stream_file::STDIO_FREE = recording_free;
            let mut buf = [0u8; 4];
            let mut f = open_file(1 | FLAG_HEAP_BUFFER, 5);
            f.stream.base = buf.as_mut_ptr();
            assert_eq!(fclose_core(&mut f), 0);
            assert_eq!(events(), std::vec![("free", buf.as_mut_ptr() as usize, 0)]);
            // Without the flag: no free.
            let mut g = open_file(1, 6);
            g.stream.base = buf.as_mut_ptr();
            assert_eq!(fclose_core(&mut g), 0);
            assert_eq!(events().len(), 1);
            restore_swi();
        }
    }

    #[test]
    fn fclose_skip_close_flag_resets_without_closing() {
        let _guard = lock_and_reset(&[]);
        unsafe {
            STREAM_SYNC_CORE = recording_sync;
            let mut f = open_file(1 | FLAG_SKIP_CLOSE, 5);
            assert_eq!(fclose_core(&mut f), 0);
            assert!(events().is_empty(), "no sync");
            assert!(swi_ops().is_empty(), "no _sys_close");
            assert_eq!(f.stream.count, 0, "still reset");
            assert_eq!(f.stream.flags, 0);
            restore_swi();
        }
    }

    // --- fseek -----------------------------------------------------------

    #[test]
    fn fseek_dispatches_the_seek_core() {
        let _guard = lock_and_reset(&[]);
        unsafe {
            let mut f = ADS_FILE_ZERO;
            assert_eq!(fseek(&mut f, 0, 2), -1, "default stub fails");
            STREAM_SEEK_CORE = recording_seek;
            assert_eq!(fseek(&mut f, 40, 1), 7, "core result passes through");
            assert_eq!(events(), std::vec![("seek", 40, 1)]);
            restore_swi();
        }
    }

    // --- freopen_core ----------------------------------------------------

    /// Mode-string table: (mode, expected SYS_OPEN mode index, flags).
    const MODE_TABLE: &[(&[u8], u32, u32)] = &[
        (b"r\0", 0, 1),
        (b"rb\0", 1, 1 | FLAG_BINARY),
        (b"r+\0", 2, 3),
        (b"r+b\0", 3, 3 | FLAG_BINARY),
        (b"rb+\0", 3, 3 | FLAG_BINARY),
        (b"w\0", 4, 2),
        (b"wb\0", 5, 2 | FLAG_BINARY),
        (b"w+\0", 6, 3),
        (b"a\0", 8, FLAGS_APPEND),
        (b"a+b\0", 11, FLAGS_APPEND | 3 | FLAG_BINARY),
        (b"rt\0", 0x10, 1),
        (b"wt\0", 0x14, 2),
    ];

    #[test]
    fn freopen_parses_every_mode_spelling() {
        for (mode, open_mode, flags) in MODE_TABLE {
            let _guard = lock_and_reset(&[9, 9]); // open handle (+seek path closes nothing)
            unsafe {
                STREAM_SEEK_CORE = recording_seek;
                let mut f = ADS_FILE_ZERO;
                let ret = freopen_core(b"x\0".as_ptr(), mode.as_ptr(), &mut f);
                assert_eq!(ret, &mut f as *mut _, "mode {:?}", mode);
                let log = &(*core::ptr::addr_of!(SWI_LOG));
                assert_eq!(log[0].0, SYS_OPEN);
                assert_eq!(log[0].1[1], *open_mode as usize, "mode {:?}", mode);
                assert_eq!(f.stream.flags, *flags, "mode {:?}", mode);
                assert_eq!(f.stream.handle, 9);
                assert_eq!(f.stream.bulk_threshold, DEFAULT_BULK_THRESHOLD);
                // Append modes seek to the end, others do not.
                let expect_seek = open_mode & 8 != 0;
                assert_eq!(
                    events().contains(&("seek", 0, 2)),
                    expect_seek,
                    "mode {:?}",
                    mode
                );
                restore_swi();
            }
        }
    }

    #[test]
    fn freopen_rejects_unknown_first_mode_char_after_closing() {
        let _guard = lock_and_reset(&[0]); // fclose's _sys_close
        unsafe {
            let mut f = open_file(1, 5);
            let ret = freopen_core(b"x\0".as_ptr(), b"x\0".as_ptr(), &mut f);
            assert!(ret.is_null());
            // The close ran first, exactly like the original.
            assert_eq!(f.stream.count, 0, "stream was still closed/reset");
            assert_eq!(swi_ops(), std::vec![SYS_CLOSE], "no open issued");
            restore_swi();
        }
    }

    #[test]
    fn freopen_open_failure_returns_null() {
        let _guard = lock_and_reset(&[]); // every SWI -> -1
        unsafe {
            let mut f = ADS_FILE_ZERO;
            assert!(freopen_core(b"x\0".as_ptr(), b"r\0".as_ptr(), &mut f).is_null());
            assert_eq!(f.stream.handle, 0, "stream not re-armed");
            restore_swi();
        }
    }

    #[test]
    fn freopen_preserves_the_string_mode_bit_and_clears_buffer_fields() {
        let _guard = lock_and_reset(&[8]);
        unsafe {
            let mut buf = [0u8; 4];
            let mut f = ADS_FILE_ZERO;
            f.stream.flags = FLAG_STRING_MODE | FLAG_SKIP_CLOSE; // skip-close path
            f.stream.base = buf.as_mut_ptr();
            f.stream.ptr = buf.as_mut_ptr();
            let ret = freopen_core(b"x\0".as_ptr(), b"w\0".as_ptr(), &mut f);
            assert_eq!(ret, &mut f as *mut _);
            assert_eq!(f.stream.flags, FLAG_STRING_MODE | 2);
            assert!(f.stream.base.is_null());
            assert!(f.stream.ptr.is_null());
            restore_swi();
        }
    }

    // --- stdio_init ------------------------------------------------------

    #[test]
    fn stdio_init_reopens_and_line_buffers_the_console_streams() {
        let _guard = lock_and_reset(&[3, 4, 5]);
        unsafe {
            // Pre-poison the statics: init must fully re-establish them.
            *stdin_file() = open_file(FLAG_SKIP_CLOSE | 1, 9);
            *stdout_file() = open_file(FLAG_SKIP_CLOSE | 2, 9);
            *stderr_file() = open_file(FLAG_SKIP_CLOSE | 2, 9);
            stdio_init();
            // Three ":tt" opens with modes r(0)/w(4)/w(4), nothing else.
            let log = &(*core::ptr::addr_of!(SWI_LOG));
            assert_eq!(swi_ops(), std::vec![SYS_OPEN, SYS_OPEN, SYS_OPEN]);
            for (entry, mode) in log.iter().zip([0usize, 4, 4]) {
                assert_eq!(entry.1[0], TT_CONSOLE_NAME.as_ptr() as usize);
                assert_eq!(entry.1[1], mode);
                assert_eq!(entry.1[2], 3, "strlen(\":tt\")");
            }
            let cases = [
                (stdin_file(), 3, 1, 0x40),
                (stdout_file(), 4, 2, 0x40),
                (stderr_file(), 5, 2, 0x10),
            ];
            for (file, handle, rw, size) in cases {
                assert_eq!((*file).stream.handle, handle);
                assert_eq!((*file).stream.flags, rw | IOLBF, "open + line-buffered");
                assert_eq!((*file).stream.bulk_threshold, size, "setvbuf size");
                assert!((*file).stream.base.is_null(), "deferred buffer");
            }
            assert_eq!((*stdin_file()).link, stdout_file());
            assert_eq!((*stdout_file()).link, stderr_file());
            assert!((*stderr_file()).link.is_null());
            restore_swi();
        }
    }

    #[test]
    fn stdio_init_raises_sigrtred_on_every_failure() {
        // No scripted SWI results: every open fails, so each freopen
        // raises, the streams stay closed, and each setvbuf raises too.
        let _guard = lock_and_reset(&[]);
        let _sig_guard = crate::raise::TEST_SIGNAL_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            static mut RAISED: Vec<i32> = Vec::new();
            unsafe extern "C" fn log_signal(sig: i32, _code: i32) {
                (*core::ptr::addr_of_mut!(RAISED)).push(sig);
            }
            (*core::ptr::addr_of_mut!(RAISED)).clear();
            let previous = crate::raise::signal(SIGRTRED, log_signal as usize as isize);
            stdio_init();
            crate::raise::signal(SIGRTRED, previous);
            assert_eq!(
                *core::ptr::addr_of!(RAISED),
                std::vec![SIGRTRED; 6],
                "3 freopen + 3 setvbuf failures"
            );
            assert_eq!((*stdin_file()).stream.flags, 0, "stream left closed");
            restore_swi();
        }
    }
}
