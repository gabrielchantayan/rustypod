//! printf public API veneers for the stock firmware's printf core
//! (ARM ADS 1.0.1): six thin entry points that bind an output sink,
//! build the sink state, and dispatch to the conversion engine. The
//! engine chain itself (the `_printf` state-building prologue
//! @ 0x08032f14 and the conversion engine @ 0x08034374 it tail-calls)
//! is a separate batch and is reached here through [`PRINTF_ENGINE`].
//!
//! Ports:
//! - `vsprintf`  @ 0x0802f654 (60 bytes) — builds `{cursor = dest}` on
//!   the stack, calls the engine as `engine(fmt, mem_putc, &cursor, ap)`,
//!   then NUL-terminates with `mem_putc(0, &cursor)`. Returns the count.
//! - `printf`    @ 0x0802f694 (64 bytes) — calls the engine as
//!   `engine(fmt, file_putc, stdout, ap)` with `stdout` the FILE object
//!   @ 0x08b2f864, then post-flushes: returns the count when
//!   `flush(stdout) == 0`, else -1.
//! - `fprintf`   @ 0x0802f6dc (68 bytes) — same with a caller FILE*:
//!   `engine(fmt, file_putc, file, ap)`, then `flush(file)` gates the
//!   return value the same way.
//! - `sprintf`   @ 0x0802f724 (64 bytes) — vsprintf with the variadic
//!   arguments captured into `ap` (body otherwise identical).
//! - `snprintf`  @ 0x0802f768 (88 bytes) — builds a
//!   [`BoundedCursor`] `{cursor = buf, end = buf + size - 1}` (when
//!   `size == 0` the bound stays `buf`, so nothing is ever stored) and
//!   calls `engine(fmt, bounded_putc, &bounds, ap)`. When `size != 0`
//!   the NUL is written with `mem_putc` at the clamped cursor — since
//!   [`bounded_putc`] never advances past `end`, the terminator lands at
//!   worst on the last buffer byte, giving the C99 "at most size-1 chars
//!   plus NUL" semantics. Returns the engine count, which is the
//!   WOULD-BE length: [`bounded_putc`] drops overflow characters but the
//!   core's count field increments per emitted character regardless
//!   (verified against the original: the count lives in the engine's
//!   state, not in the sink).
//! - `vsnprintf` @ 0x08032f94 (84 bytes) — snprintf with an explicit
//!   `ap` (body otherwise identical).
//!
//! [`PrintfState`]-level detail: the veneers' dispatch target in the
//! original is the prologue @ 0x08032f14, called as
//! `prologue(fmt, putc, putc_ctx, ap)`; it builds the 68-byte state
//! (`putc` @ 0x1c, `emit_str` = 0x08034804 @ 0x20, `putc_ctx` @ 0x24,
//! `fmt_getc` = 0x08034838 @ 0x28, `&fmt` @ 0x2c, 0 @ 0x30) and calls
//! the engine @ 0x08034374 as `engine(state, ap)`. [`PRINTF_ENGINE`]
//! stands in for that whole chain, so it takes the prologue's four
//! register-level arguments.
//!
//! Simplifications vs. the original:
//! - The variadic functions (`printf`, `fprintf`, `sprintf`, `snprintf`)
//!   capture their `...` arguments by spilling r0-r3 and pointing `ap`
//!   into the spill. Stable Rust cannot define C-variadic functions, so
//!   the Rust signatures replace the `...` with an explicit
//!   `args: *const u32` — exactly the va_list the original builds (a
//!   pointer to the first variadic argument word). AAPCS note: the fixed
//!   parameters keep their standard r0/r1(/r2) registers, but a real
//!   variadic C caller cannot pass a pointer in the vararg slot, so
//!   calling these symbols from existing firmware code needs a small asm
//!   trampoline that captures r2/r3 (+ stack args) into a word buffer
//!   and passes its address — the same wiring the engine batch needs for
//!   va_list. `vsprintf`/`vsnprintf` take an explicit va_list in C
//!   already, so their Rust signatures are ABI-exact.
//! - The stdio FILE layer is NOT ported. The original file putc
//!   @ 0x082cf2c8 appends to a line buffer (0x08b31720, flush on `'\n'`
//!   or 80 chars) and flushes through semihosting `svc 0x123456`
//!   (angel SYS_WRITE) — dead on retail hardware with no debugger
//!   attached. [`file_putc`] here is a documented discard stub. The
//!   post-flush @ 0x080333f8 returns `file->flags & 0x80` after two
//!   patched-out/semihost calls; [`file_flush`] is a stub returning 0
//!   (success), so `printf`/`fprintf` return the conversion count.
//!   `stdout` is the raw firmware load address [`STDOUT`]; the FILE
//!   object itself lives in firmware RAM.
//! - `sprintf`/`snprintf` duplicate their v-twins' bodies instead of
//!   tail-calling them, matching the originals (which duplicate the
//!   body, differing only in the vararg spill). Since the explicit
//!   `args`/`ap` parameters are identical, LLVM folds the pairs into one
//!   body with two global symbols each (`vsprintf` aliases `sprintf`,
//!   `vsnprintf` aliases `snprintf`) — byte-identical code either way.
//! - With the always-successful [`file_flush`] stub, LLVM constant-folds
//!   the post-flush gate (`if flush != 0 { -1 } else { count }`) and
//!   `printf`/`fprintf` compile to tail calls through [`PRINTF_ENGINE`].
//!   The gate is in the source and materializes as soon as a real FILE
//!   layer makes the flush fallible.

use core::ffi::c_void;

use crate::printf_helpers::{bounded_putc, mem_putc, BoundedCursor, PutcFn};

/// Opaque stdio `FILE` handle. The FILE layer is not ported (it is
/// semihost-dead on retail hardware — see module docs); this is a raw
/// pointer to the original firmware's FILE objects.
pub type File = c_void;

/// va_list as the original veneers build it: a pointer to the next
/// variadic argument word (AAPCS: variadic args are consecutive 32-bit
/// words in the spilled registers / on the stack).
pub type VaList = *const u32;

/// Load address of the stock firmware's `stdout` FILE object (bound by
/// the original `printf` via literal pool).
pub const STDOUT: *mut File = 0x08b2f864 as *mut File;

/// Register-level engine entry. Stands in for the original's dispatch
/// target: the `_printf` prologue @ 0x08032f14 (which builds the
/// [`crate::printf_helpers::PrintfState`] and tail-calls the conversion
/// engine @ 0x08034374). Called as `engine(fmt, putc, putc_ctx, ap)`;
/// returns the number of characters emitted (the would-be length for
/// bounded sinks).
pub type PrintfEngineFn =
    unsafe extern "C" fn(fmt: *const u8, putc: PutcFn, putc_ctx: *mut c_void, ap: VaList) -> i32;

/// Placeholder for the printf engine chain (prologue @ 0x08032f14 +
/// conversion engine @ 0x08034374, ported in the printf_core batch).
/// Emits nothing and reports 0 characters; the veneers still
/// NUL-terminate their buffers.
unsafe extern "C" fn printf_engine_stub(
    _fmt: *const u8,
    _putc: PutcFn,
    _putc_ctx: *mut c_void,
    _ap: VaList,
) -> i32 {
    0
}

/// Engine entry point called by all six veneers; swap in the real
/// engine when its batch lands. Defaults to [`printf_engine_stub`].
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut PRINTF_ENGINE: PrintfEngineFn = printf_engine_stub;

/// The unbounded string sink ([`mem_putc`]) viewed as the engine's
/// opaque [`PutcFn`]: same calling convention, the context is a raw
/// pointer in both views (the original passes the raw address too).
#[inline(always)]
fn mem_sink() -> PutcFn {
    unsafe { core::mem::transmute::<unsafe extern "C" fn(u8, *mut *mut u8), PutcFn>(mem_putc) }
}

/// The bounded string sink ([`bounded_putc`]) viewed as [`PutcFn`].
#[inline(always)]
fn bounded_sink() -> PutcFn {
    unsafe { core::mem::transmute::<unsafe extern "C" fn(u8, *mut BoundedCursor), PutcFn>(bounded_putc) }
}

/// Stub for the stdio FILE putc @ 0x082cf2c8. The original buffers into
/// a line buffer and flushes via semihosting `svc 0x123456`, which is
/// dead on retail hardware without a debugger; this stub discards the
/// character. Bound by `printf`/`fprintf` until the FILE layer is
/// ported (if ever — retailOS only used it for debug console output).
unsafe extern "C" fn file_putc(_c: u8, _file: *mut c_void) {}

/// Stub for the post-write flush @ 0x080333f8. The original returns
/// `file->flags & 0x80` (nonzero = error, mapped to -1 by the callers);
/// with the FILE layer unported this stub reports success so
/// `printf`/`fprintf` return the conversion count.
unsafe extern "C" fn file_flush(_file: *mut File) -> i32 {
    0
}

/// `vsprintf` — original: `FUN_0802f654` @ 0x0802f654 (60 bytes).
///
/// Formats into `dest` with the unbounded [`mem_putc`] sink, then
/// NUL-terminates (the terminator goes through `mem_putc` too, advancing
/// the cursor past it without touching the returned count). Returns the
/// engine's character count. No bounds checking, like the original.
///
/// Register usage: r0 = dest, r1 = fmt, r2 = ap (a real va_list — this
/// signature is ABI-exact).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vsprintf(dest: *mut u8, fmt: *const u8, ap: VaList) -> i32 {
    let mut cursor = dest;
    let engine = PRINTF_ENGINE;
    let count = engine(
        fmt,
        mem_sink(),
        &mut cursor as *mut *mut u8 as *mut c_void,
        ap,
    );
    mem_putc(0, &mut cursor);
    count
}

/// `sprintf` — original: `FUN_0802f724` @ 0x0802f724 (64 bytes).
///
/// Identical to [`vsprintf`] except the variadic arguments are captured
/// into `ap` (see the module docs for why the Rust signature takes an
/// explicit `args` pointer instead of `...`).
///
/// Register usage: r0 = buf, r1 = fmt, r2/r3/stack = varargs (original
/// builds `ap` = &spilled-r2; here `args` IS that pointer).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sprintf(buf: *mut u8, fmt: *const u8, args: VaList) -> i32 {
    let mut cursor = buf;
    let engine = PRINTF_ENGINE;
    let count = engine(
        fmt,
        mem_sink(),
        &mut cursor as *mut *mut u8 as *mut c_void,
        args,
    );
    mem_putc(0, &mut cursor);
    count
}

/// `vsnprintf` — original: `FUN_08032f94` @ 0x08032f94 (84 bytes).
///
/// Formats into `buf` through the [`bounded_putc`] sink clamped at
/// `buf + size - 1` (bound = `buf` when `size == 0`, so nothing is
/// stored), then — only when `size != 0` — writes the NUL at the clamped
/// cursor via `mem_putc`. Returns the engine's count, the WOULD-BE
/// length excluding the terminator (overflow chars are dropped by the
/// sink but still counted), matching C99 snprintf.
///
/// Register usage: r0 = buf, r1 = size, r2 = fmt, r3 = ap (a real
/// va_list — this signature is ABI-exact).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vsnprintf(buf: *mut u8, size: usize, fmt: *const u8, ap: VaList) -> i32 {
    let mut bounds = BoundedCursor {
        cursor: buf,
        // Original: `addne r0, r0, r4; subne r0, r0, #1` — with
        // size == 0 the bound stays `buf`, making cursor == end.
        end: if size != 0 { buf.add(size - 1) } else { buf },
    };
    let engine = PRINTF_ENGINE;
    let count = engine(
        fmt,
        bounded_sink(),
        &mut bounds as *mut BoundedCursor as *mut c_void,
        ap,
    );
    if size != 0 {
        mem_putc(0, &mut bounds.cursor);
    }
    count
}

/// `snprintf` — original: `FUN_0802f768` @ 0x0802f768 (88 bytes).
///
/// Identical to [`vsnprintf`] except the variadic arguments are captured
/// into `ap` (see the module docs for the explicit-`args` simplification).
///
/// Register usage: r0 = buf, r1 = size, r2 = fmt, r3/stack = varargs
/// (original builds `ap` = &spilled-r3; here `args` IS that pointer).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn snprintf(buf: *mut u8, size: usize, fmt: *const u8, args: VaList) -> i32 {
    let mut bounds = BoundedCursor {
        cursor: buf,
        end: if size != 0 { buf.add(size - 1) } else { buf },
    };
    let engine = PRINTF_ENGINE;
    let count = engine(
        fmt,
        bounded_sink(),
        &mut bounds as *mut BoundedCursor as *mut c_void,
        args,
    );
    if size != 0 {
        mem_putc(0, &mut bounds.cursor);
    }
    count
}

/// `printf` — original: `FUN_0802f694` @ 0x0802f694 (64 bytes).
///
/// Formats to `stdout` (the firmware FILE object [`STDOUT`]) through the
/// FILE-layer sink — stubbed here, see the module docs: on retail
/// hardware the original sink's semihosting flush is dead, so output
/// goes nowhere. After the engine run the original post-flushes the FILE
/// and returns -1 when the flush reports an error, else the engine's
/// character count.
///
/// Register usage: r0 = fmt, r1/r2/r3/stack = varargs (original builds
/// `ap` = &spilled-r1; here `args` IS that pointer).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn printf(fmt: *const u8, args: VaList) -> i32 {
    let engine = PRINTF_ENGINE;
    let count = engine(fmt, file_putc, STDOUT as *mut c_void, args);
    if file_flush(STDOUT) != 0 {
        -1
    } else {
        count
    }
}

/// `fprintf` — original: `FUN_0802f6dc` @ 0x0802f6dc (68 bytes).
///
/// `printf` to a caller-supplied FILE*: `engine(fmt, file_putc, file,
/// ap)` then the same post-flush return gate (stubbed FILE layer — see
/// the module docs).
///
/// Register usage: r0 = file, r1 = fmt, r2/r3/stack = varargs (original
/// builds `ap` = &spilled-r2; here `args` IS that pointer).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fprintf(file: *mut File, fmt: *const u8, args: VaList) -> i32 {
    let engine = PRINTF_ENGINE;
    let count = engine(fmt, file_putc, file as *mut c_void, args);
    if file_flush(file) != 0 {
        -1
    } else {
        count
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;
    use std::vec::Vec;

    /// Serializes tests that swap PRINTF_ENGINE (and the default-stub
    /// test, which must not observe a swapped engine).
    static ENGINE_LOCK: Mutex<()> = Mutex::new(());

    fn engine_lock() -> std::sync::MutexGuard<'static, ()> {
        // Stay usable even if an earlier test panicked mid-call.
        ENGINE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Contract-faithful fake engine: emits the format bytes verbatim
    /// (no `%` handling) through the bound sink, returning the count —
    /// exactly what the real engine does for literal text. Lets the
    /// veneer plumbing (sink binding, NUL, count, clamping) be tested
    /// without the printf_core batch.
    unsafe extern "C" fn echo_engine(fmt: *const u8, putc: PutcFn, ctx: *mut c_void, _ap: VaList) -> i32 {
        let mut p = fmt;
        let mut n = 0;
        while *p != 0 {
            putc(*p, ctx);
            p = p.add(1);
            n += 1;
        }
        n
    }

    /// Recording engines for the state-contract tests: capture the
    /// register-level arguments the veneer passes. `recording_engine`
    /// only records the raw arguments (safe for any ctx, including the
    /// unmapped STDOUT address); `recording_engine_snapshot` additionally
    /// copies the first two words of the sink state while the call is
    /// live — the veneers build that state on THEIR stack frames, so
    /// reading it after return would be dangling (for the string sinks
    /// the words are {cursor} / {cursor, end}).
    static mut RECORDED: Option<(*const u8, usize, *mut c_void, VaList)> = None;
    static mut RECORDED_SINK_WORDS: Option<(usize, usize)> = None;

    unsafe extern "C" fn recording_engine(fmt: *const u8, putc: PutcFn, ctx: *mut c_void, ap: VaList) -> i32 {
        RECORDED = Some((fmt, putc as usize, ctx, ap));
        11
    }

    unsafe extern "C" fn recording_engine_snapshot(
        fmt: *const u8,
        putc: PutcFn,
        ctx: *mut c_void,
        ap: VaList,
    ) -> i32 {
        RECORDED = Some((fmt, putc as usize, ctx, ap));
        let w = ctx as *const usize;
        RECORDED_SINK_WORDS = Some((*w, *w.add(1)));
        11
    }

    unsafe fn with_engine(engine: PrintfEngineFn, body: impl FnOnce()) {
        PRINTF_ENGINE = engine;
        body();
        PRINTF_ENGINE = printf_engine_stub;
    }

    #[test]
    fn sprintf_writes_nul_terminated_string_and_returns_count() {
        let _guard = engine_lock();
        let mut buf = [0xAAu8; 16];
        unsafe {
            with_engine(echo_engine, || {
                let ret = sprintf(buf.as_mut_ptr(), b"hello\0".as_ptr(), core::ptr::null());
                assert_eq!(ret, 5);
                assert_eq!(&buf[..6], b"hello\0");
                // Byte past the terminator untouched.
                assert_eq!(buf[6], 0xAA);
            });
        }
    }

    #[test]
    fn vsprintf_matches_sprintf() {
        let _guard = engine_lock();
        let mut buf = [0u8; 16];
        let args: [u32; 1] = [0xdeadbeef];
        unsafe {
            with_engine(echo_engine, || {
                let ret = vsprintf(buf.as_mut_ptr(), b"abc\0".as_ptr(), args.as_ptr());
                assert_eq!(ret, 3);
                assert_eq!(&buf[..4], b"abc\0");
            });
        }
    }

    #[test]
    fn snprintf_truncates_with_nul_and_would_be_length() {
        let _guard = engine_lock();
        let mut buf = [0xAAu8; 8];
        unsafe {
            with_engine(echo_engine, || {
                // Room for 3 chars + NUL; engine emits 6.
                let ret = snprintf(buf.as_mut_ptr(), 4, b"abcdef\0".as_ptr(), core::ptr::null());
                assert_eq!(ret, 6, "return is the would-be length");
                assert_eq!(&buf[..4], b"abc\0");
                assert_eq!(buf[4], 0xAA, "nothing past size bytes");
            });
        }
    }

    #[test]
    fn snprintf_exact_fit_and_size_one() {
        let _guard = engine_lock();
        let mut buf = [0xAAu8; 8];
        unsafe {
            with_engine(echo_engine, || {
                // Exactly size-1 chars: no truncation.
                let ret = snprintf(buf.as_mut_ptr(), 4, b"abc\0".as_ptr(), core::ptr::null());
                assert_eq!(ret, 3);
                assert_eq!(&buf[..4], b"abc\0");

                // size 1: only the terminator fits.
                buf.iter_mut().for_each(|b| *b = 0xAA);
                let ret = snprintf(buf.as_mut_ptr(), 1, b"xyz\0".as_ptr(), core::ptr::null());
                assert_eq!(ret, 3);
                assert_eq!(buf[0], 0);
                assert_eq!(buf[1], 0xAA);
            });
        }
    }

    #[test]
    fn snprintf_size_zero_writes_nothing() {
        let _guard = engine_lock();
        let mut buf = [0xAAu8; 4];
        unsafe {
            with_engine(echo_engine, || {
                let ret = snprintf(buf.as_mut_ptr(), 0, b"abc\0".as_ptr(), core::ptr::null());
                assert_eq!(ret, 3, "would-be length still reported");
                assert_eq!(buf, [0xAA; 4], "no store, not even the NUL");
            });
        }
    }

    #[test]
    fn vsnprintf_truncates_like_snprintf() {
        let _guard = engine_lock();
        let mut buf = [0xAAu8; 8];
        let args: [u32; 1] = [7];
        unsafe {
            with_engine(echo_engine, || {
                let ret = vsnprintf(buf.as_mut_ptr(), 3, b"wxyz\0".as_ptr(), args.as_ptr());
                assert_eq!(ret, 4);
                assert_eq!(&buf[..3], b"wx\0");
            });
        }
    }

    #[test]
    fn sprintf_binds_mem_putc_and_cursor_state() {
        let _guard = engine_lock();
        let mut buf = [0u8; 8];
        let fmt = b"%d\0";
        let args: [u32; 2] = [42, 43];
        unsafe {
            with_engine(recording_engine_snapshot, || {
                let ret = sprintf(buf.as_mut_ptr(), fmt.as_ptr(), args.as_ptr());
                assert_eq!(ret, 11);
                let (r_fmt, r_putc, _, r_ap) = RECORDED.expect("engine invoked");
                assert_eq!(r_fmt, fmt.as_ptr());
                assert_eq!(r_putc, mem_sink() as usize, "mem sink bound");
                assert_eq!(r_ap, args.as_ptr(), "va_list passed through");
                // Sink state is the cursor word, initially `buf`.
                let (cursor, _) = RECORDED_SINK_WORDS.expect("sink snapshotted");
                assert_eq!(cursor, buf.as_mut_ptr() as usize);
            });
        }
    }

    #[test]
    fn snprintf_binds_bounded_putc_and_cursor_end_state() {
        let _guard = engine_lock();
        let mut buf = [0u8; 8];
        unsafe {
            with_engine(recording_engine_snapshot, || {
                snprintf(buf.as_mut_ptr(), 5, b"%s\0".as_ptr(), core::ptr::null());
                let (_, r_putc, _, _) = RECORDED.expect("engine invoked");
                assert_eq!(r_putc, bounded_sink() as usize, "bounded sink bound");
                let (cursor, end) = RECORDED_SINK_WORDS.expect("sink snapshotted");
                assert_eq!(cursor, buf.as_mut_ptr() as usize);
                assert_eq!(end, buf.as_mut_ptr().add(4) as usize, "bound = buf + size - 1");
            });
        }
    }

    #[test]
    fn snprintf_size_zero_binds_empty_range() {
        let _guard = engine_lock();
        let mut buf = [0u8; 4];
        unsafe {
            with_engine(recording_engine_snapshot, || {
                snprintf(buf.as_mut_ptr(), 0, b"x\0".as_ptr(), core::ptr::null());
                let (_, _, _, _) = RECORDED.expect("engine invoked");
                let (cursor, end) = RECORDED_SINK_WORDS.expect("sink snapshotted");
                assert_eq!(cursor, buf.as_mut_ptr() as usize);
                assert_eq!(end, buf.as_mut_ptr() as usize, "size 0: bound stays buf");
            });
        }
    }

    #[test]
    fn printf_binds_stdout_and_returns_count_after_stub_flush() {
        let _guard = engine_lock();
        let fmt = b"boot %d\0";
        let args: [u32; 1] = [3];
        unsafe {
            with_engine(recording_engine, || {
                let ret = printf(fmt.as_ptr(), args.as_ptr());
                assert_eq!(ret, 11, "stub flush reports success -> count returned");
                let (r_fmt, r_putc, r_ctx, r_ap) = RECORDED.expect("engine invoked");
                assert_eq!(r_fmt, fmt.as_ptr());
                assert_eq!(r_putc, file_putc as PutcFn as usize, "FILE-layer sink bound");
                assert_eq!(r_ctx, STDOUT as *mut c_void, "stdout FILE bound");
                assert_eq!(r_ap, args.as_ptr());
            });
        }
    }

    #[test]
    fn fprintf_binds_caller_file_and_returns_count() {
        let _guard = engine_lock();
        let mut fake_file = [0u8; 64];
        let file = fake_file.as_mut_ptr() as *mut File;
        unsafe {
            with_engine(recording_engine, || {
                let ret = fprintf(file, b"x\0".as_ptr(), core::ptr::null());
                assert_eq!(ret, 11);
                let (_, r_putc, r_ctx, _) = RECORDED.expect("engine invoked");
                assert_eq!(r_putc, file_putc as PutcFn as usize);
                assert_eq!(r_ctx, file as *mut c_void, "caller FILE passed through");
            });
        }
    }

    #[test]
    fn file_putc_stub_discards_and_flush_stub_reports_success() {
        unsafe {
            // The semihost-dead FILE layer: output goes nowhere, flush ok.
            file_putc(b'a', STDOUT as *mut c_void);
            assert_eq!(file_flush(STDOUT), 0);
        }
    }

    #[test]
    fn default_engine_stub_emits_nothing_but_veneers_terminate() {
        let _guard = engine_lock();
        let mut buf = [0xAAu8; 8];
        unsafe {
            assert_eq!(sprintf(buf.as_mut_ptr(), b"hi\0".as_ptr(), core::ptr::null()), 0);
            assert_eq!(buf[0], 0, "buffer still NUL-terminated");
            buf.iter_mut().for_each(|b| *b = 0xAA);
            assert_eq!(snprintf(buf.as_mut_ptr(), 8, b"hi\0".as_ptr(), core::ptr::null()), 0);
            assert_eq!(buf[0], 0);
            assert_eq!(printf(b"hi\0".as_ptr(), core::ptr::null()), 0);
        }
    }

    /// Guard against accidental regression of the sink bindings: the
    /// pointers the veneers pass must be the helpers' real sinks.
    #[test]
    fn sink_function_identities() {
        fn collect(v: &mut Vec<usize>, f: usize) {
            v.push(f);
        }
        let mut v = Vec::new();
        collect(&mut v, mem_sink() as usize);
        collect(&mut v, bounded_sink() as usize);
        collect(&mut v, file_putc as PutcFn as usize);
        assert_ne!(v[0], v[1]);
        assert_ne!(v[0], v[2]);
        assert_ne!(v[1], v[2]);
    }
}
