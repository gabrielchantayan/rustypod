//! The ADS 1.0.1 buffered-stdio FILE-object maintenance cluster from osos:
//! error reset, physical writeback, the raw read refill, the close/flush
//! walkers over the stream chain, FILE allocation, and the exit-path
//! cleanup. Everything here operates on the ADS FILE object — the 48-byte
//! [`AdsStream`] prefix (see `fread.rs`) extended with a lock word at +0x3c
//! and the stream-chain link at +0x40 ([`AdsFile`]).
//!
//! Ports:
//! - `stdio_stream_error_reset` @ 0x08030004 (64 bytes) — flags become
//!   `(flags & !0x200000) | 0x80` (dirty bit dropped, error bit set) and,
//!   unless the stream is a string/pseudo stream (bit 0x1000000), the
//!   buffered-count words at +0x00 and +0x08 are cleared.
//! - `stdio_writeback` @ 0x08030044 (152 bytes) — the physical write core:
//!   seeks to the stream position (+0x18) first when a bit of
//!   [`SEEK_BEFORE_WRITE_MASK`] is set (clearing those bits on success),
//!   writes via `_sys_write`, sets [`FLAG_LAST_OP_WRITE`], advances the
//!   position by the bytes actually written, and returns 0 on full success
//!   or -1 (after `stdio_stream_error_reset`) on any seek/write failure.
//! - `stream_raw_read` @ 0x08034f88 (100 bytes; previously the
//!   uncharacterized `stdio_helper_08034f88`) — the raw read refill:
//!   `_sys_read` into `dest` (passing the stream's flag word as the block's
//!   mode word), clears [`FLAG_LAST_OP_WRITE`], and decodes the semihost
//!   result: -1 = error (error reset, return -1); bit 31 set = EOF
//!   (sets [`FLAG_EOF_REACHED`], remaining = result & 0x7fffffff);
//!   returns `len - remaining` = bytes actually read. This is exactly the
//!   `STREAM_REFILL` contract in `fread.rs`.
//! - `stdio_foreach_close` @ 0x080300dc (92 bytes) — walks the stream
//!   chain from stdin, calling the fclose core (hook [`STREAM_CLOSE_CORE`],
//!   original 0x0802fc00) on every stream whose flags contain all of
//!   [`CLOSE_LIVE_MASK`], with a second argument of 0 for the `excluded`
//!   stream and 1 for every other.
//! - `stdio_flush_all` @ 0x08030624 (96 bytes) — flushes the three static
//!   streams (stdin, stdout, stderr) through the per-stream flush (hook
//!   [`STREAM_FLUSH`], original 0x080302d0 — a locked wrapper around the
//!   flush core @ 0x08030238), then walks the dynamic chain hanging off
//!   stderr's link, flushing and then FREEING each node (`free`
//!   @ 0x0802edc8). The chain head is captured BEFORE the static flushes,
//!   exactly like the original's early `ldr r4, [stderr, #0x40]`.
//! - `stdio_stream_alloc` @ 0x08035924 (32 bytes) — `malloc(0x88)`
//!   (@ 0x0802edac) and clears the FIRST BYTE only; returns NULL on
//!   allocation failure. (0x88 covers the 0x44-byte FILE object plus
//!   buffer slack.)
//! - `exit_stdio_cleanup` @ 0x08035878 (24 bytes) — runs the libspace+0x38
//!   shutdown-handler chain (hook [`LIB_SHUTDOWN_CHAIN`], original
//!   0x082ab2b0, called with 0 = run every handler and free its node),
//!   then `stdio_flush_all`, then the no-op @ 0x0802ecc0 (`mov pc, lr` —
//!   nothing to port). Reached from `__rt_sys_exit` and heap_panic.
//!
//! The paired `mov r0, r0` sequences around each operation in the
//! originals are the patched-out stream-lock/unlock hooks (they receive
//! `&file.lock`, the address of FILE+0x3c, and the list lock object
//! @ 0x08a0fc04); they are omitted, which also drops the originals'
//! incidental register return values (the lock addresses left in r0 by
//! `stdio_stream_error_reset` / `stdio_foreach_close`) — every caller
//! ignores them.
//!
//! Deviations:
//! - The static stdin/stdout/stderr FILE objects live at 0x08b2f820 /
//!   0x08b2f864 / 0x08b2f8a8 in osos DRAM; here they are zero-initialized
//!   `static mut` blocks reached through `stdin_file()` /`stdout_file()` /
//!   `stderr_file()` (same modeling as `errno.rs`'s libspace).
//! - Unported callees dispatch through function-pointer hooks (the house
//!   `STREAM_GETC`/`HEAP_OPS` pattern): [`STREAM_FLUSH`] (0x080302d0),
//!   [`STREAM_CLOSE_CORE`] (0x0802fc00), [`LIB_SHUTDOWN_CHAIN`]
//!   (0x082ab2b0). Defaults are documented no-ops.
//! - malloc/free ARE ported (`malloc_rt.rs`), but they dispatch through
//!   the global `HEAP_OPS` table, which host tests of that module swap
//!   under a lock private to it; to keep this module's tests isolated
//!   (and race-free), its allocator boundary goes through the
//!   module-local [`STDIO_ALLOC`]/[`STDIO_FREE`] slots, which DEFAULT to
//!   the ported `malloc`/`free` — the firmware build therefore links the
//!   same call graph as the original.
//! - `stream_raw_read` takes `*mut AdsStream` (it touches only prefix
//!   fields) so it is directly installable into `fread.rs`'s
//!   `STREAM_REFILL` slot; installation is an init-time concern, the
//!   default stub there is unchanged.

use crate::fread::{AdsStream, FLAG_STRING_MODE};
use crate::semihost::{_sys_read, _sys_seek, _sys_write};

/// flags bit: stream error indicator, set by [`stdio_stream_error_reset`]
/// (read by the ferror-family accessor @ 0x080333f8, another port).
pub const FLAG_ERROR_SET: u32 = 0x80;
/// flags bit: dropped by the error reset together with the buffered-count
/// words — inferred to mark "buffer holds pending (dirty) write data".
pub const FLAG_BUF_DIRTY: u32 = 0x0020_0000;
/// flags bit: the last physical operation was a write — set by
/// [`stdio_writeback`], cleared by [`stream_raw_read`].
pub const FLAG_LAST_OP_WRITE: u32 = 0x0004_0000;
/// flags bit: semihost read reported end-of-file (bit 31 of the
/// `_sys_read` result), set by [`stream_raw_read`]; cleared by the
/// clearerr core @ 0x080333c8 (another port).
pub const FLAG_EOF_REACHED: u32 = 0x4000;
/// Writeback seeks to the stream position before writing when any of
/// these flag bits is set, then clears them: 0x20000 is `FLAG_GOT_REFILL`
/// (set by `fread` after a direct read refill — the file offset no longer
/// matches the write position), 0x10 is its unidentified companion.
/// The original loads this mask from the literal pool @ 0x08030684.
pub const SEEK_BEFORE_WRITE_MASK: u32 = 0x0002_0010;
/// [`stdio_foreach_close`] calls the close core only on streams whose
/// flags contain ALL of these bits (the "live open stream" state; the
/// original loads the mask from the literal pool @ 0x08030690).
pub const CLOSE_LIVE_MASK: u32 = 0x202;
/// Allocation size of a fresh FILE object (`stdio_stream_alloc`).
pub const ADS_FILE_ALLOC_SIZE: usize = 0x88;

/// The full ADS FILE object: the 48-byte [`AdsStream`] prefix plus the
/// tail the maintenance cluster uses. Offsets (32-bit target): +0x3c
/// `lock`, +0x40 `link`; pinned by the layout test below.
#[repr(C)]
pub struct AdsFile {
    /// +0x00..+0x30: the buffered-stream prefix (see `fread.rs`).
    pub stream: AdsStream,
    /// +0x30..+0x3c: not touched by this cluster.
    pub field_30: u32,
    /// See [`AdsFile::field_30`].
    pub field_34: u32,
    /// See [`AdsFile::field_30`].
    pub field_38: u32,
    /// +0x3c: per-stream lock word — the patched-out lock/unlock hooks
    /// receive its address (see module docs).
    pub lock: u32,
    /// +0x40: next FILE in the stream chain (stdin -> stdout -> stderr ->
    /// dynamically allocated streams; null-terminated).
    pub link: *mut AdsFile,
}

/// A zeroed FILE object (the statics' initial state; osos zero-fills its
/// static FILE area at startup).
pub const ADS_FILE_ZERO: AdsFile = AdsFile {
    stream: AdsStream {
        count: 0,
        ptr: core::ptr::null_mut(),
        field_08: 0,
        flags: 0,
        base: core::ptr::null_mut(),
        handle: 0,
        offset_end: 0,
        bulk_threshold: 0,
        field_20: 0,
        field_24: 0,
        alt_offset: 0,
        lim: core::ptr::null_mut(),
    },
    field_30: 0,
    field_34: 0,
    field_38: 0,
    lock: 0,
    link: core::ptr::null_mut(),
};

// The three static streams — original DRAM addresses 0x08b2f820 (stdin),
// 0x08b2f864 (stdout), 0x08b2f8a8 (stderr); modeled as crate statics like
// errno.rs's libspace (see module docs).
static mut STDIN_FILE: AdsFile = ADS_FILE_ZERO;
static mut STDOUT_FILE: AdsFile = ADS_FILE_ZERO;
static mut STDERR_FILE: AdsFile = ADS_FILE_ZERO;

/// The static stdin FILE (original @ 0x08b2f820); head of the stream chain.
pub fn stdin_file() -> *mut AdsFile {
    unsafe { core::ptr::addr_of_mut!(STDIN_FILE) }
}

/// The static stdout FILE (original @ 0x08b2f864).
pub fn stdout_file() -> *mut AdsFile {
    unsafe { core::ptr::addr_of_mut!(STDOUT_FILE) }
}

/// The static stderr FILE (original @ 0x08b2f8a8); dynamically allocated
/// streams chain off its `link`.
pub fn stderr_file() -> *mut AdsFile {
    unsafe { core::ptr::addr_of_mut!(STDERR_FILE) }
}

/// Per-stream flush — original 0x080302d0, the locked wrapper around the
/// flush core @ 0x08030238 (not yet ported).
pub type StreamFlushFn = unsafe extern "C" fn(file: *mut AdsFile) -> i32;
/// fclose core — original 0x0802fc00 (not yet ported). `not_excluded` is
/// 0 for the stream `stdio_foreach_close` was told to spare, 1 otherwise.
pub type StreamCloseFn = unsafe extern "C" fn(file: *mut AdsFile, not_excluded: i32) -> i32;
/// libspace+0x38 shutdown-handler chain runner — original 0x082ab2b0 (not
/// yet ported): walks the node list `{next, arg, fn, key}`, and with
/// `mode == 0` calls every `fn(arg)`, unlinks and frees each node.
pub type ShutdownChainFn = unsafe extern "C" fn(mode: i32);
/// Allocator slot (see the module-docs deviation note).
pub type AllocFn = unsafe extern "C" fn(size: usize) -> *mut u8;
/// See [`AllocFn`].
pub type FreeFn = unsafe extern "C" fn(ptr: *mut u8);

/// Default flush stand-in: reports success without touching the stream
/// (the real per-stream flush is a later port).
unsafe extern "C" fn stream_flush_stub(_file: *mut AdsFile) -> i32 {
    0
}

/// Default close stand-in: reports success (the real fclose core is a
/// later port).
unsafe extern "C" fn stream_close_stub(_file: *mut AdsFile, _not_excluded: i32) -> i32 {
    0
}

/// Default shutdown-chain stand-in: no handlers registered, nothing to run.
unsafe extern "C" fn shutdown_chain_stub(_mode: i32) {}

/// Per-stream flush entry (original 0x080302d0); swap in the real port
/// when it lands.
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut STREAM_FLUSH: StreamFlushFn = stream_flush_stub;

/// fclose-core entry (original 0x0802fc00); swap in the real port when it
/// lands.
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut STREAM_CLOSE_CORE: StreamCloseFn = stream_close_stub;

/// Shutdown-chain entry (original 0x082ab2b0); swap in the real port when
/// it lands.
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut LIB_SHUTDOWN_CHAIN: ShutdownChainFn = shutdown_chain_stub;

/// Allocator boundary; defaults to the ported `malloc` @ 0x0802edac.
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut STDIO_ALLOC: AllocFn = crate::malloc_rt::malloc;

/// Allocator boundary; defaults to the ported `free` @ 0x0802edc8.
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut STDIO_FREE: FreeFn = crate::malloc_rt::free;

/// Reads a hook slot. Volatile so a build in which nothing rewrites the
/// slot does not constant-fold the default in and delete the dispatch.
#[inline(always)]
fn hook<T: Copy>(slot: *const T) -> T {
    unsafe { core::ptr::read_volatile(slot) }
}

/// stdio_stream_error_reset — original @ 0x08030004 (64 bytes).
///
/// Marks the stream broken: drops [`FLAG_BUF_DIRTY`], sets
/// [`FLAG_ERROR_SET`], and — unless the stream is a string/pseudo stream
/// ([`FLAG_STRING_MODE`]) — clears the buffered-count words at +0x00
/// (`count`) and +0x08.
///
/// The original returns `&file.lock` in r0 (residue of the patched-out
/// unlock hook); every caller ignores it, so the port returns nothing.
/// (`inline(never)` keeps the in-crate callers' `bl` structure matching
/// the original's.)
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stdio_stream_error_reset(file: *mut AdsFile) {
    let flags = ((*file).stream.flags & !FLAG_BUF_DIRTY) | FLAG_ERROR_SET;
    (*file).stream.flags = flags;
    if flags & FLAG_STRING_MODE == 0 {
        (*file).stream.field_08 = 0;
        (*file).stream.count = 0;
    }
}

/// stdio_writeback — original @ 0x08030044 (152 bytes).
///
/// Physically writes `len` bytes of `buf` to the stream's semihost
/// handle. When a [`SEEK_BEFORE_WRITE_MASK`] bit is set, the handle is
/// first repositioned to the stream position (+0x18) via `_sys_seek` —
/// failure takes the error exit before anything is written; success
/// clears those bits. Then `_sys_write` runs; [`FLAG_LAST_OP_WRITE`] is
/// set and the position advanced by `len - (result & 0x7fffffff)` (the
/// semihost result counts bytes NOT written) whether or not the write
/// completed. Returns 0 when everything was written; otherwise the error
/// exit runs [`stdio_stream_error_reset`] and returns -1.
///
/// The original also passes its (stale) flags copy as `_sys_write`'s
/// fourth register argument; `_sys_write` never reads r3, so the port
/// drops it. (`inline(never)` keeps the in-crate callers' — the flush
/// core's — `bl` structure matching the original's.)
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stdio_writeback(buf: *const u8, len: i32, file: *mut AdsFile) -> i32 {
    let mut flags = (*file).stream.flags;
    let handle = (*file).stream.handle;
    if flags & SEEK_BEFORE_WRITE_MASK != 0 {
        if _sys_seek(handle, (*file).stream.offset_end) < 0 {
            stdio_stream_error_reset(file);
            return -1;
        }
        flags &= !SEEK_BEFORE_WRITE_MASK;
        (*file).stream.flags = flags;
    }
    let not_written = _sys_write(handle, buf, len as u32);
    (*file).stream.flags |= FLAG_LAST_OP_WRITE;
    let written = len.wrapping_sub((not_written & 0x7fff_ffff) as i32);
    (*file).stream.offset_end = (*file).stream.offset_end.wrapping_add(written);
    if not_written == 0 {
        return 0;
    }
    stdio_stream_error_reset(file);
    -1
}

/// stream_raw_read — original @ 0x08034f88 (100 bytes).
///
/// The raw read refill shared by the buffered getc core (0x08034fec) and
/// `fread`'s `STREAM_REFILL` slot: reads up to `len` bytes from the
/// stream's semihost handle straight into `dest` (the stream's flag word
/// rides along as the read block's mode word), then clears
/// [`FLAG_LAST_OP_WRITE`]. The semihost result counts bytes NOT read:
/// -1 is a hard error (error reset, returns -1); any other value with
/// bit 31 set means EOF was reached ([`FLAG_EOF_REACHED`] is set and the
/// remainder is `result & 0x7fffffff`). Returns `len - remainder` =
/// bytes actually read (0 = clean EOF).
///
/// Takes `*mut AdsStream` — only prefix fields are touched — so the
/// function matches `fread.rs`'s `StreamRefillFn` exactly; the error
/// reset receives the same object as a FILE (its accesses also stay
/// within the prefix for a non-string stream... the flags path never
/// reaches past +0x0c). (`inline(never)` keeps the getc core's `bl`
/// structure matching the original's.)
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stream_raw_read(dest: *mut u8, len: i32, stream: *mut AdsStream) -> i32 {
    let not_read = _sys_read((*stream).handle, dest, len as u32, (*stream).flags);
    let flags = (*stream).flags & !FLAG_LAST_OP_WRITE;
    (*stream).flags = flags;
    if not_read < 0 {
        if not_read == -1 {
            stdio_stream_error_reset(stream as *mut AdsFile);
            return -1;
        }
        (*stream).flags = flags | FLAG_EOF_REACHED;
        return len.wrapping_sub(not_read & 0x7fff_ffff);
    }
    len.wrapping_sub(not_read)
}

/// stdio_foreach_close — original @ 0x080300dc (92 bytes).
///
/// Walks the stream chain from the static stdin, calling the fclose core
/// ([`STREAM_CLOSE_CORE`]) on every stream whose flags contain all of
/// [`CLOSE_LIVE_MASK`]; the core's second argument is 0 for `excluded`
/// and 1 for every other stream. (The original returns the list lock
/// object in r0 — patched-out unlock residue, ignored by all callers.
/// `inline(never)` keeps the getc core's `bl` structure matching the
/// original's.)
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stdio_foreach_close(excluded: *mut AdsFile) {
    let close = hook(core::ptr::addr_of!(STREAM_CLOSE_CORE));
    let mut file = stdin_file();
    while !file.is_null() {
        if CLOSE_LIVE_MASK & !(*file).stream.flags == 0 {
            close(file, (file != excluded) as i32);
        }
        file = (*file).link;
    }
}

/// stdio_flush_all — original @ 0x08030624 (96 bytes).
///
/// Flushes stdin, stdout and stderr through the per-stream flush
/// ([`STREAM_FLUSH`]), then walks the dynamic chain that was hanging off
/// stderr's link — captured BEFORE the static flushes, like the
/// original's early `ldr r4, [stderr, #0x40]` — flushing and then
/// freeing every node. Reached from `exit_stdio_cleanup` on the
/// termination path. (`inline(never)` keeps `exit_stdio_cleanup`'s `bl`
/// structure matching the original's.)
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stdio_flush_all() {
    let flush = hook(core::ptr::addr_of!(STREAM_FLUSH));
    let free = hook(core::ptr::addr_of!(STDIO_FREE));
    let mut file = (*stderr_file()).link;
    flush(stdin_file());
    flush(stdout_file());
    flush(stderr_file());
    while !file.is_null() {
        let next = (*file).link;
        flush(file);
        free(file as *mut u8);
        file = next;
    }
}

/// stdio_stream_alloc — original @ 0x08035924 (32 bytes).
///
/// Allocates a fresh FILE object (`malloc(0x88)`) and clears its FIRST
/// BYTE only (the low byte of `count`); the rest is left uninitialized
/// for the caller (fopen core) to fill. Returns NULL on allocation
/// failure.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stdio_stream_alloc() -> *mut AdsFile {
    let alloc = hook(core::ptr::addr_of!(STDIO_ALLOC));
    let p = alloc(ADS_FILE_ALLOC_SIZE);
    if !p.is_null() {
        *p = 0;
    }
    p as *mut AdsFile
}

/// exit_stdio_cleanup — original @ 0x08035878 (24 bytes).
///
/// The termination-path stdio teardown, reached from `__rt_sys_exit` and
/// heap_panic: runs the libspace+0x38 shutdown-handler chain
/// ([`LIB_SHUTDOWN_CHAIN`] with mode 0 = run and free every handler),
/// then [`stdio_flush_all`], then the no-op @ 0x0802ecc0 (`mov pc, lr`).
///
/// `exit.rs` currently reaches the original's behavior through its own
/// (deliberately no-op) private stub; pointing it here is an init-time /
/// unification concern (see that module's docs).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn exit_stdio_cleanup() {
    hook(core::ptr::addr_of!(LIB_SHUTDOWN_CHAIN))(0);
    stdio_flush_all();
    // Original tail: bl 0x0802ecc0, a `mov pc, lr` no-op.
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::semihost::tests::{mock_swi, restore_swi, SWI_LOCK, SWI_LOG};
    use crate::semihost::{SYS_SEEK, SYS_WRITE};
    use std::sync::MutexGuard;
    use std::vec::Vec;

    /// Event log for hook-order tests: pointers (as usize) and sentinels.
    static mut EVENTS: Vec<(&'static str, usize)> = Vec::new();

    fn events() -> Vec<(&'static str, usize)> {
        unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
    }

    unsafe extern "C" fn logging_flush(file: *mut AdsFile) -> i32 {
        (*core::ptr::addr_of_mut!(EVENTS)).push(("flush", file as usize));
        0
    }

    unsafe extern "C" fn logging_close(file: *mut AdsFile, not_excluded: i32) -> i32 {
        (*core::ptr::addr_of_mut!(EVENTS)).push(("close", file as usize));
        (*core::ptr::addr_of_mut!(EVENTS)).push(("close_arg", not_excluded as usize));
        0
    }

    unsafe extern "C" fn logging_shutdown(mode: i32) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(("shutdown", mode as usize));
    }

    unsafe extern "C" fn logging_free(ptr: *mut u8) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(("free", ptr as usize));
    }

    /// Fixed-buffer mock allocator (returns ALLOC_BUF, poisoned 0xaa).
    static mut ALLOC_BUF: [u8; ADS_FILE_ALLOC_SIZE] = [0xaa; ADS_FILE_ALLOC_SIZE];
    unsafe extern "C" fn buf_alloc(size: usize) -> *mut u8 {
        (*core::ptr::addr_of_mut!(EVENTS)).push(("alloc", size));
        core::ptr::addr_of_mut!(ALLOC_BUF) as *mut u8
    }
    unsafe extern "C" fn null_alloc(size: usize) -> *mut u8 {
        (*core::ptr::addr_of_mut!(EVENTS)).push(("alloc", size));
        core::ptr::null_mut()
    }

    /// Takes the shared SWI lock (all tests in this module mutate the
    /// static FILE objects and hook slots), resets every static/hook to
    /// its pristine state, and clears the event log.
    fn lock_and_reset() -> MutexGuard<'static, ()> {
        let guard = SWI_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_state();
        guard
    }

    fn reset_state() {
        unsafe {
            restore_swi();
            *stdin_file() = ADS_FILE_ZERO;
            *stdout_file() = ADS_FILE_ZERO;
            *stderr_file() = ADS_FILE_ZERO;
            STREAM_FLUSH = stream_flush_stub;
            STREAM_CLOSE_CORE = stream_close_stub;
            LIB_SHUTDOWN_CHAIN = shutdown_chain_stub;
            STDIO_ALLOC = crate::malloc_rt::malloc;
            STDIO_FREE = crate::malloc_rt::free;
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
        }
    }

    fn swi_log() -> Vec<(usize, Vec<usize>)> {
        unsafe { (*core::ptr::addr_of!(SWI_LOG)).clone() }
    }

    fn file_with(flags: u32, handle: i32, pos: i32) -> AdsFile {
        let mut f = ADS_FILE_ZERO;
        f.stream.flags = flags;
        f.stream.handle = handle;
        f.stream.offset_end = pos;
        f
    }

    // --- stdio_stream_error_reset ---------------------------------------

    #[test]
    fn error_reset_normal_stream_sets_error_and_clears_counts() {
        let _guard = lock_and_reset();
        let mut f = file_with(FLAG_BUF_DIRTY | 0x4, 3, 0);
        f.stream.count = 17;
        f.stream.field_08 = 23;
        unsafe {
            stdio_stream_error_reset(&mut f);
        }
        assert_eq!(f.stream.flags, 0x4 | FLAG_ERROR_SET, "dirty dropped, error set");
        assert_eq!(f.stream.count, 0);
        assert_eq!(f.stream.field_08, 0);
    }

    #[test]
    fn error_reset_string_stream_keeps_counts() {
        let _guard = lock_and_reset();
        let mut f = file_with(FLAG_STRING_MODE | FLAG_BUF_DIRTY, 0, 0);
        f.stream.count = 9;
        f.stream.field_08 = 5;
        unsafe {
            stdio_stream_error_reset(&mut f);
        }
        assert_eq!(f.stream.flags, FLAG_STRING_MODE | FLAG_ERROR_SET);
        assert_eq!(f.stream.count, 9, "string mode: count untouched");
        assert_eq!(f.stream.field_08, 5);
    }

    // --- stdio_writeback -------------------------------------------------

    #[test]
    fn writeback_plain_write_success() {
        let _guard = lock_and_reset();
        let _swi = {
            // mock_swi would re-lock; install by hand under our guard.
            unsafe {
                crate::semihost::SEMIHOST_SWI = crate::semihost::tests::recording_swi;
                (*core::ptr::addr_of_mut!(SWI_LOG)).clear();
                *core::ptr::addr_of_mut!(crate::semihost::tests::SWI_RESULTS) = std::vec![0];
            }
        };
        let mut f = file_with(0, 8, 100);
        let buf = b"payload!";
        unsafe {
            assert_eq!(stdio_writeback(buf.as_ptr(), 8, &mut f), 0);
        }
        // No seek bit set: single SYS_WRITE, no SYS_SEEK.
        assert_eq!(swi_log(), std::vec![(SYS_WRITE, std::vec![8, buf.as_ptr() as usize, 8])]);
        assert_eq!(f.stream.offset_end, 108, "position advanced by len");
        assert_eq!(f.stream.flags, FLAG_LAST_OP_WRITE);
    }

    #[test]
    fn writeback_seeks_first_and_clears_the_seek_bits() {
        let _guard = lock_and_reset();
        unsafe {
            crate::semihost::SEMIHOST_SWI = crate::semihost::tests::recording_swi;
            (*core::ptr::addr_of_mut!(SWI_LOG)).clear();
            // seek ok, write ok.
            *core::ptr::addr_of_mut!(crate::semihost::tests::SWI_RESULTS) = std::vec![0, 0];
        }
        let mut f = file_with(0x10 | 0x2_0000 | 0x4, 5, 64);
        let buf = b"abcd";
        unsafe {
            assert_eq!(stdio_writeback(buf.as_ptr(), 4, &mut f), 0);
        }
        assert_eq!(
            swi_log(),
            std::vec![
                (SYS_SEEK, std::vec![5, 64]),
                (SYS_WRITE, std::vec![5, buf.as_ptr() as usize, 4]),
            ]
        );
        assert_eq!(
            f.stream.flags,
            0x4 | FLAG_LAST_OP_WRITE,
            "both seek bits cleared before the write"
        );
        assert_eq!(f.stream.offset_end, 68);
    }

    #[test]
    fn writeback_seek_failure_is_an_error_before_writing() {
        let _guard = lock_and_reset();
        unsafe {
            crate::semihost::SEMIHOST_SWI = crate::semihost::tests::recording_swi;
            (*core::ptr::addr_of_mut!(SWI_LOG)).clear();
            *core::ptr::addr_of_mut!(crate::semihost::tests::SWI_RESULTS) = std::vec![-1];
        }
        let mut f = file_with(0x10, 5, 64);
        f.stream.count = 3;
        let buf = b"abcd";
        unsafe {
            assert_eq!(stdio_writeback(buf.as_ptr(), 4, &mut f), -1);
        }
        let log = swi_log();
        assert_eq!(log.len(), 1, "no write after a failed seek");
        assert_eq!(log[0].0, SYS_SEEK);
        assert_eq!(f.stream.offset_end, 64, "position untouched");
        // Error reset ran: error bit set, seek bit NOT cleared (the store
        // is skipped on the failure path), write marker NOT set.
        assert_eq!(f.stream.flags, 0x10 | FLAG_ERROR_SET);
        assert_eq!(f.stream.count, 0);
    }

    #[test]
    fn writeback_partial_write_advances_pos_and_errors() {
        let _guard = lock_and_reset();
        unsafe {
            crate::semihost::SEMIHOST_SWI = crate::semihost::tests::recording_swi;
            (*core::ptr::addr_of_mut!(SWI_LOG)).clear();
            // 3 of 10 bytes NOT written.
            *core::ptr::addr_of_mut!(crate::semihost::tests::SWI_RESULTS) = std::vec![3];
        }
        let mut f = file_with(0, 2, 50);
        let buf = b"0123456789";
        unsafe {
            assert_eq!(stdio_writeback(buf.as_ptr(), 10, &mut f), -1);
        }
        assert_eq!(f.stream.offset_end, 57, "advanced by the 7 written bytes");
        // FLAG_LAST_OP_WRITE was set, then the error reset added the error
        // bit (and dropped nothing else here).
        assert_eq!(f.stream.flags, FLAG_LAST_OP_WRITE | FLAG_ERROR_SET);
    }

    #[test]
    fn writeback_masks_bit31_of_the_write_result() {
        let _guard = lock_and_reset();
        unsafe {
            crate::semihost::SEMIHOST_SWI = crate::semihost::tests::recording_swi;
            (*core::ptr::addr_of_mut!(SWI_LOG)).clear();
            // Result with bit 31 set: masked remainder is 5.
            *core::ptr::addr_of_mut!(crate::semihost::tests::SWI_RESULTS) =
                std::vec![0x8000_0005u32 as i32];
        }
        let mut f = file_with(0, 2, 0);
        let buf = b"0123456789";
        unsafe {
            assert_eq!(stdio_writeback(buf.as_ptr(), 10, &mut f), -1);
        }
        assert_eq!(f.stream.offset_end, 5, "pos += 10 - (result & 0x7fffffff)");
    }

    // --- stream_raw_read -------------------------------------------------

    #[test]
    fn raw_read_is_refill_slot_compatible() {
        // Signature contract with fread.rs's STREAM_REFILL slot.
        let _f: crate::fread::StreamRefillFn = stream_raw_read;
    }

    #[test]
    fn raw_read_full_success_clears_write_marker() {
        let _guard = lock_and_reset();
        unsafe {
            crate::semihost::SEMIHOST_SWI = crate::semihost::tests::recording_swi;
            (*core::ptr::addr_of_mut!(SWI_LOG)).clear();
            *core::ptr::addr_of_mut!(crate::semihost::tests::SWI_RESULTS) = std::vec![0];
        }
        let mut f = file_with(FLAG_LAST_OP_WRITE | 0x8, 6, 0);
        let mut dest = [0u8; 8];
        unsafe {
            assert_eq!(stream_raw_read(dest.as_mut_ptr(), 8, &mut f.stream), 8);
        }
        // The read block carries the PRE-call flags as its mode word.
        assert_eq!(
            swi_log(),
            std::vec![(
                crate::semihost::SYS_READ,
                std::vec![6, dest.as_mut_ptr() as usize, 8, (FLAG_LAST_OP_WRITE | 0x8) as usize]
            )]
        );
        assert_eq!(f.stream.flags, 0x8, "write marker cleared, no EOF/error");
    }

    #[test]
    fn raw_read_short_read_without_eof_bit() {
        let _guard = lock_and_reset();
        unsafe {
            crate::semihost::SEMIHOST_SWI = crate::semihost::tests::recording_swi;
            (*core::ptr::addr_of_mut!(SWI_LOG)).clear();
            *core::ptr::addr_of_mut!(crate::semihost::tests::SWI_RESULTS) = std::vec![3];
        }
        let mut f = file_with(0, 6, 0);
        let mut dest = [0u8; 8];
        unsafe {
            assert_eq!(stream_raw_read(dest.as_mut_ptr(), 8, &mut f.stream), 5);
        }
        assert_eq!(f.stream.flags, 0, "no EOF flag without bit 31");
    }

    #[test]
    fn raw_read_eof_sets_flag_and_returns_partial_count() {
        let _guard = lock_and_reset();
        unsafe {
            crate::semihost::SEMIHOST_SWI = crate::semihost::tests::recording_swi;
            (*core::ptr::addr_of_mut!(SWI_LOG)).clear();
            // Bit 31 + 2 bytes not read: 6 of 8 delivered, EOF reached.
            *core::ptr::addr_of_mut!(crate::semihost::tests::SWI_RESULTS) =
                std::vec![0x8000_0002u32 as i32];
        }
        let mut f = file_with(FLAG_LAST_OP_WRITE, 6, 0);
        let mut dest = [0u8; 8];
        unsafe {
            assert_eq!(stream_raw_read(dest.as_mut_ptr(), 8, &mut f.stream), 6);
        }
        assert_eq!(f.stream.flags, FLAG_EOF_REACHED, "EOF flagged, write marker cleared");
    }

    #[test]
    fn raw_read_clean_eof_returns_zero() {
        let _guard = lock_and_reset();
        unsafe {
            crate::semihost::SEMIHOST_SWI = crate::semihost::tests::recording_swi;
            (*core::ptr::addr_of_mut!(SWI_LOG)).clear();
            // Bit 31 + all 8 not read: nothing delivered.
            *core::ptr::addr_of_mut!(crate::semihost::tests::SWI_RESULTS) =
                std::vec![0x8000_0008u32 as i32];
        }
        let mut f = file_with(0, 6, 0);
        let mut dest = [0u8; 8];
        unsafe {
            assert_eq!(stream_raw_read(dest.as_mut_ptr(), 8, &mut f.stream), 0);
        }
        assert_eq!(f.stream.flags, FLAG_EOF_REACHED);
    }

    #[test]
    fn raw_read_error_runs_error_reset() {
        let _guard = lock_and_reset();
        unsafe {
            crate::semihost::SEMIHOST_SWI = crate::semihost::tests::recording_swi;
            (*core::ptr::addr_of_mut!(SWI_LOG)).clear();
            *core::ptr::addr_of_mut!(crate::semihost::tests::SWI_RESULTS) = std::vec![-1];
        }
        let mut f = file_with(FLAG_BUF_DIRTY, 6, 0);
        f.stream.count = 4;
        let mut dest = [0u8; 8];
        unsafe {
            assert_eq!(stream_raw_read(dest.as_mut_ptr(), 8, &mut f.stream), -1);
        }
        assert_eq!(f.stream.flags, FLAG_ERROR_SET, "error reset ran");
        assert_eq!(f.stream.count, 0);
    }

    // --- stdio_foreach_close ---------------------------------------------

    #[test]
    fn foreach_close_walks_chain_and_flags_the_excluded_stream() {
        let _guard = lock_and_reset();
        unsafe {
            STREAM_CLOSE_CORE = logging_close;
        }
        let mut live_a = file_with(CLOSE_LIVE_MASK | 0x40, 0, 0);
        let mut dead = file_with(0x200, 0, 0); // only half the live mask
        let mut live_b = file_with(CLOSE_LIVE_MASK, 0, 0);
        unsafe {
            // stdin (not live) -> live_a -> dead -> live_b -> null.
            (*stdin_file()).link = &mut live_a;
            live_a.link = &mut dead;
            dead.link = &mut live_b;
            stdio_foreach_close(&mut live_b);
        }
        assert_eq!(
            events(),
            std::vec![
                ("close", core::ptr::addr_of!(live_a) as usize),
                ("close_arg", 1),
                ("close", core::ptr::addr_of!(live_b) as usize),
                ("close_arg", 0), // the excluded stream gets 0
            ],
            "stdin (flags 0) and the half-live stream are skipped"
        );
    }

    #[test]
    fn foreach_close_null_excluded_marks_every_live_stream_1() {
        let _guard = lock_and_reset();
        unsafe {
            STREAM_CLOSE_CORE = logging_close;
            (*stdin_file()).stream.flags = CLOSE_LIVE_MASK;
            stdio_foreach_close(core::ptr::null_mut());
        }
        assert_eq!(
            events(),
            std::vec![("close", stdin_file() as usize), ("close_arg", 1)]
        );
    }

    // --- stdio_flush_all -------------------------------------------------

    #[test]
    fn flush_all_flushes_statics_then_flushes_and_frees_the_chain() {
        let _guard = lock_and_reset();
        unsafe {
            STREAM_FLUSH = logging_flush;
            STDIO_FREE = logging_free;
        }
        let mut dyn_a = ADS_FILE_ZERO;
        let mut dyn_b = ADS_FILE_ZERO;
        unsafe {
            (*stderr_file()).link = &mut dyn_a;
            dyn_a.link = &mut dyn_b;
            stdio_flush_all();
        }
        let a = core::ptr::addr_of!(dyn_a) as usize;
        let b = core::ptr::addr_of!(dyn_b) as usize;
        assert_eq!(
            events(),
            std::vec![
                ("flush", stdin_file() as usize),
                ("flush", stdout_file() as usize),
                ("flush", stderr_file() as usize),
                ("flush", a),
                ("free", a),
                ("flush", b),
                ("free", b),
            ]
        );
    }

    /// The chain head is read BEFORE the static streams are flushed: a
    /// flush that rewrites stderr's link must not change the walk.
    #[test]
    fn flush_all_captures_the_chain_before_flushing() {
        let _guard = lock_and_reset();
        unsafe extern "C" fn link_clearing_flush(file: *mut AdsFile) -> i32 {
            (*file).link = core::ptr::null_mut();
            logging_flush(file)
        }
        unsafe {
            STREAM_FLUSH = link_clearing_flush;
            STDIO_FREE = logging_free;
        }
        let mut dyn_a = ADS_FILE_ZERO;
        unsafe {
            (*stderr_file()).link = &mut dyn_a;
            stdio_flush_all();
        }
        let a = core::ptr::addr_of!(dyn_a) as usize;
        assert!(
            events().contains(&("flush", a)) && events().contains(&("free", a)),
            "captured chain still walked after stderr.link was cleared"
        );
    }

    // --- stdio_stream_alloc ----------------------------------------------

    #[test]
    fn stream_alloc_clears_only_the_first_byte() {
        let _guard = lock_and_reset();
        unsafe {
            STDIO_ALLOC = buf_alloc;
            *core::ptr::addr_of_mut!(ALLOC_BUF) = [0xaa; ADS_FILE_ALLOC_SIZE];
            let p = stdio_stream_alloc();
            assert_eq!(p as *mut u8, core::ptr::addr_of_mut!(ALLOC_BUF) as *mut u8);
            let bytes = &*core::ptr::addr_of!(ALLOC_BUF);
            assert_eq!(bytes[0], 0, "first byte cleared");
            assert!(bytes[1..].iter().all(|&b| b == 0xaa), "rest untouched");
        }
        assert_eq!(events(), std::vec![("alloc", ADS_FILE_ALLOC_SIZE)]);
    }

    #[test]
    fn stream_alloc_failure_returns_null() {
        let _guard = lock_and_reset();
        unsafe {
            STDIO_ALLOC = null_alloc;
            assert!(stdio_stream_alloc().is_null());
        }
    }

    // --- exit_stdio_cleanup ----------------------------------------------

    #[test]
    fn exit_cleanup_runs_shutdown_chain_then_flush_all() {
        let _guard = lock_and_reset();
        unsafe {
            LIB_SHUTDOWN_CHAIN = logging_shutdown;
            STREAM_FLUSH = logging_flush;
            exit_stdio_cleanup();
        }
        assert_eq!(
            events(),
            std::vec![
                ("shutdown", 0), // mode 0 = run and free every handler
                ("flush", stdin_file() as usize),
                ("flush", stdout_file() as usize),
                ("flush", stderr_file() as usize),
            ]
        );
    }

    // --- layout -----------------------------------------------------------

    /// Raw offsets only hold on the 32-bit ARM target (the prefix widens
    /// with 64-bit pointers on hosts); all access is by field name.
    #[test]
    #[cfg(target_pointer_width = "32")]
    fn ads_file_layout_matches_original() {
        assert_eq!(core::mem::size_of::<AdsFile>(), 0x44);
        assert_eq!(core::mem::offset_of!(AdsFile, stream), 0x00);
        assert_eq!(core::mem::offset_of!(AdsFile, lock), 0x3c);
        assert_eq!(core::mem::offset_of!(AdsFile, link), 0x40);
    }
}
