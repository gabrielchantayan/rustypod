//! `stream_write_cstr` — original: `FUN_082647c0` @ 0x082647c0.
//!
//! **48 bytes**, twelve instruction words, no literal pool. (An earlier
//! survey of this neighbourhood recorded it as 44 bytes; that is one word
//! short. Decoded from osos.dec the body runs 0x082647c0..0x082647ec
//! inclusive — `stmdb sp!,{r3,r4,r5,lr}` through `ldmia sp!,{r3,r4,r5,pc}`
//! — and the next function starts at 0x082647f0 with its own
//! `ldrb r1,[r0,#0x19]; strb r1,[r0,#0x18]; bx lr`.) The same survey's
//! other conclusions hold: it opens `push {r3,r4,r5,lr}`, calls
//! 0x08392478 then 0x0827899c with `sp` as an out-parameter, returns
//! `[sp]`, and has nothing to do with the big-endian pack/unpack family.
//!
//! 53 call sites, all unconditional `bl` (no predicated calls, no tail
//! `b`), binary-scanned by decoding every branch word in osos.dec. They
//! form five runs in 0x08265010..0x08266418 — the framework's debug/stats
//! dump methods, each shaped `Dump(this, stream)`:
//!
//! ```text
//! stmdb sp!,{r1,r2,r3,r4,r5,lr}
//! mov r4,r0                  ; this
//! add r0,sp,#0x4             ; a scratch StringObject
//! mov r5,r1                  ; the stream
//! bl 0x08277440              ; StringObject ctor
//! add r2,pc,#0x1b4           ; a literal such as "Max Events In Queue: %d"
//! mov r1,r5
//! mov r0,r4
//! bl 0x082647c0              ; <- this function
//! ```
//!
//! The original never reads r0. It is the `this` of those dump methods,
//! passed because the helper is one of their member functions, and it is
//! kept in the signature so call sites transcribe unchanged.
//!
//! Algorithm: measure the string with the unguarded retailOS `strlen`
//! @ 0x08392478 (ported, [`crate::libc::strlen::strlen`]), hand the
//! pointer/length pair to the stream writer @ 0x0827899c along with the
//! address of a stack word, and return that word.
//!
//! Ghidra renders the function with a phantom fourth parameter and
//! `local_10 = param_4`: that is only `push {r3,...}` spilling the
//! scratch register whose slot then serves as the out-parameter. The
//! spilled value is dead — 0x0827899c's callee @ 0x082789b8 stores 0
//! through the out-pointer (`mov r6,#0; str r6,[r5]`) before any branch,
//! so the slot is always written before it is read.

use crate::libc::strlen::strlen;

/// The one call [`stream_write_cstr`] makes that is not yet ported.
///
/// `write` is retailOS `FUN_0827899c` @ 0x0827899c (24 bytes, 21 `bl` +
/// 4 other call sites): a two-instruction preamble that zeroes a fifth,
/// stack-passed argument and tail-calls the buffered-stream write core
/// @ 0x082789b8. That core takes the lock guard at +0x00, stores 0
/// through `written`, and appends `length` bytes from `data` to the
/// stream, updating `written` and returning a status (0x15 when the
/// stream's error byte at +0x14 is already set).
#[derive(Clone, Copy)]
pub struct StreamWriteOps {
    pub write: unsafe extern "C" fn(
        stream: *mut u8,
        length: usize,
        data: *const u8,
        written: *mut u32,
    ) -> i32,
}

/// Consumes nothing and reports nothing written — the behavior of a
/// stream whose error byte is already set, which is the original's own
/// no-progress outcome.
unsafe extern "C" fn missing_stream_write(
    _stream: *mut u8,
    _length: usize,
    _data: *const u8,
    written: *mut u32,
) -> i32 {
    written.write(0);
    0x15
}

/// Unwired stream operations.
pub const DEFAULT_STREAM_WRITE_OPS: StreamWriteOps = StreamWriteOps {
    write: missing_stream_write,
};

/// Active stream operations. Target integration writes this once with the
/// retailOS bridge; host tests temporarily install recorders.
pub static mut STREAM_WRITE_OPS: StreamWriteOps = DEFAULT_STREAM_WRITE_OPS;

/// Volatile dispatch prevents target builds using the default from
/// folding away the integration boundary.
#[inline(always)]
fn stream_write_ops() -> StreamWriteOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STREAM_WRITE_OPS)) }
}

/// stream_write_cstr — original: `FUN_082647c0` @ 0x082647c0 (48 bytes,
/// 53 `bl` call sites).
///
/// Writes the NUL-terminated `text` to `stream` and returns the number of
/// bytes the stream accepted. The terminator is not written: the length
/// handed to the stream is `strlen(text)`.
///
/// `owner` is the `this` of the dump method that calls this helper. The
/// original overwrites r0 before its first use, so the parameter is
/// accepted and ignored.
///
/// # Deviations
///
/// The stream writer @ 0x0827899c is not ported; its contract is reached
/// through [`STREAM_WRITE_OPS`] rather than a guessed implementation. The
/// original leaves the out-parameter's stack word uninitialized (it holds
/// the spilled r3) because the callee always stores 0 into it first; the
/// port initializes it to 0 so an unwired or partially-writing hook can
/// never return a stale value.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_write_cstr(
    owner: *mut u8,
    stream: *mut u8,
    text: *const u8,
) -> u32 {
    let _ = owner;
    let mut written: u32 = 0;
    let length = strlen(text);
    (stream_write_ops().write)(stream, length, text, &mut written);
    written
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    #[derive(Default)]
    struct Recorder {
        calls: usize,
        stream: usize,
        length: usize,
        data: usize,
        first_byte: u8,
        report: u32,
        status: i32,
    }

    static LOCK: Mutex<()> = Mutex::new(());
    static RECORDER: Mutex<Recorder> = Mutex::new(Recorder {
        calls: 0,
        stream: 0,
        length: 0,
        data: 0,
        first_byte: 0,
        report: 0,
        status: 0,
    });

    unsafe extern "C" fn recording_write(
        stream: *mut u8,
        length: usize,
        data: *const u8,
        written: *mut u32,
    ) -> i32 {
        let mut recorder = RECORDER.lock().unwrap();
        recorder.calls += 1;
        recorder.stream = stream as usize;
        recorder.length = length;
        recorder.data = data as usize;
        recorder.first_byte = if length == 0 { 0 } else { data.read() };
        written.write(recorder.report);
        recorder.status
    }

    fn install(report: u32, status: i32) -> (MutexGuard<'static, ()>, StreamWriteOps) {
        let lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        *RECORDER.lock().unwrap() = Recorder {
            report,
            status,
            ..Recorder::default()
        };
        let previous = unsafe { STREAM_WRITE_OPS };
        unsafe {
            STREAM_WRITE_OPS = StreamWriteOps {
                write: recording_write,
            };
        }
        (lock, previous)
    }

    fn restore(previous: StreamWriteOps) {
        unsafe { STREAM_WRITE_OPS = previous };
    }

    #[test]
    fn measures_the_string_and_reports_what_the_stream_accepted() {
        const TEXT: &[u8] = b"Max Events In Queue: 12\0trailing garbage";
        let mut stream = [0u8; 4];
        let (_lock, previous) = install(23, 0);

        let written = unsafe {
            stream_write_cstr(
                0xdead_beefusize as *mut u8,
                stream.as_mut_ptr(),
                TEXT.as_ptr(),
            )
        };
        restore(previous);

        let recorder = RECORDER.lock().unwrap();
        assert_eq!(recorder.calls, 1);
        assert_eq!(recorder.stream, stream.as_ptr() as usize);
        assert_eq!(recorder.data, TEXT.as_ptr() as usize, "the string is not copied");
        assert_eq!(recorder.length, 23, "the NUL is measured but not written");
        assert_eq!(written, 23);
    }

    #[test]
    fn an_empty_string_still_reaches_the_stream_with_length_zero() {
        let (_lock, previous) = install(0, 0);

        let written = unsafe { stream_write_cstr(core::ptr::null_mut(), core::ptr::null_mut(), b"\0".as_ptr()) };
        restore(previous);

        let recorder = RECORDER.lock().unwrap();
        assert_eq!(recorder.calls, 1, "a zero-length write is still issued");
        assert_eq!(recorder.length, 0);
        assert_eq!(written, 0);
    }

    #[test]
    fn a_partial_write_returns_the_streams_count_not_the_length() {
        const TEXT: &[u8] = b"0123456789\0";
        let (_lock, previous) = install(4, 0x15);

        let written =
            unsafe { stream_write_cstr(core::ptr::null_mut(), core::ptr::null_mut(), TEXT.as_ptr()) };
        restore(previous);

        assert_eq!(RECORDER.lock().unwrap().length, 10);
        assert_eq!(written, 4, "the out-parameter wins over the requested length");
    }

    #[test]
    fn a_failing_status_is_swallowed_and_only_the_count_survives() {
        const TEXT: &[u8] = b"x\0";
        let (_lock, previous) = install(0, 0x15);

        let written =
            unsafe { stream_write_cstr(core::ptr::null_mut(), core::ptr::null_mut(), TEXT.as_ptr()) };
        restore(previous);

        assert_eq!(written, 0, "the original discards the writer's status");
    }

    #[test]
    fn the_unwired_default_reports_nothing_written() {
        let lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let previous = unsafe { STREAM_WRITE_OPS };
        unsafe { STREAM_WRITE_OPS = DEFAULT_STREAM_WRITE_OPS };

        let written =
            unsafe { stream_write_cstr(core::ptr::null_mut(), core::ptr::null_mut(), b"abc\0".as_ptr()) };
        unsafe { STREAM_WRITE_OPS = previous };
        drop(lock);

        assert_eq!(written, 0);
    }

    #[test]
    fn the_owner_argument_is_never_dereferenced() {
        let (_lock, previous) = install(1, 0);

        // A wild `this` pointer must not be touched: the original
        // overwrites r0 before its first use.
        let written = unsafe { stream_write_cstr(1usize as *mut u8, core::ptr::null_mut(), b"z\0".as_ptr()) };
        restore(previous);

        assert_eq!(written, 1);
        assert_eq!(RECORDER.lock().unwrap().first_byte, b'z');
    }
}
