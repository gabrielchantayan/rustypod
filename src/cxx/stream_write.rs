//! `stream_write` — original: `FUN_0827899c` @ 0x0827899c.
//!
//! **28 bytes**, seven instruction words, no literal pool. Decoded from
//! osos.dec the body runs 0x0827899c..0x082789b4 inclusive:
//!
//! ```text
//! mov  ip, r3
//! push {r3, lr}
//! mov  r3, #0
//! str  r3, [sp]
//! mov  r3, ip
//! bl   0x082789b8
//! pop  {ip, pc}
//! ```
//!
//! Ghidra's 28-byte extent is CORRECT here — the next word at
//! 0x082789b8 opens with a full `push {r4,r5,r6,r7,r8,r9,sl,fp,lr}` and
//! is a separately linked sibling, the shared buffered-stream write core,
//! not part of this function. The core has its own second caller: the
//! wrapper @ 0x08277ef4, byte-pattern-identical to this one except it
//! stores 6 into the stacked slot instead of 0.
//!
//! 25 branch sites, binary-scanned by decoding every B/BL word in
//! osos.dec: 21 unconditional `bl`, 2 predicated `bleq` (@ 0x0827f010,
//! @ 0x0827f068 — those callers gate the call on a zero test), and 2
//! tail `b` (@ 0x08161ab0, `bgt` @ 0x082c7274). The 23 `bl` call sites
//! attributed to this function count the two `bleq` forms.
//!
//! Algorithm: this is the mode-0 front end of the shared write core.
//! `push {r3, lr}` reserves the first stack-argument slot (the pushed r3
//! value is dead), 0 is stored into it — a FIFTH argument the core reads
//! back at `[sp, #64]` — r3 is restored through ip, and the core is
//! called with (stream, length, data, written, 0). The core's r0 status
//! (0 on success, 5 on short final flush, 0x15 when the stream's error
//! byte at +0x14 was already set) returns verbatim through `pop {ip, pc}`.
//!
//! The fifth word is forwarded by the core as the third stacked argument
//! of the facade vtable +0x20 write call. Its meaning is not established
//! — 0 here, 6 in the sibling wrapper — so it is named `mode` and left
//! undocumented beyond that.

/// The one call [`stream_write`] makes that is not yet ported.
///
/// `core` is retailOS `FUN_082789b8` @ 0x082789b8 (876 bytes, 2 `bl`
/// call sites — here and the mode-6 sibling wrapper @ 0x08277ef4): the
/// shared buffered-stream write core. It constructs the lock guard on the
/// stream's +0x00 word (0x0818a144, unported), stores 0 through
/// `written` before any branch, unwraps `[stream, #28]` when
/// `file_has_directory_entry` @ 0x082a548c (ported) reports no entry,
/// appends `length` bytes from `data` to the paged buffer (page acquire
/// 0x08277f10 / release 0x08277d1c, both unported) or through the facade
/// vtable slots +0x20/+0x34, advancing `written`, and releases the guard
/// with `mutex_unlock_counted` @ 0x0809449c (ported). Returns a status:
/// 0 success, 5 short final flush, 0x15 error byte already set.
#[derive(Clone, Copy)]
pub struct StreamWriteCoreOps {
    pub core: unsafe extern "C" fn(
        stream: *mut u8,
        length: u32,
        data: *const u8,
        written: *mut u32,
        mode: u32,
    ) -> u32,
}

/// Consumes nothing and reports nothing written — the behavior of a
/// stream whose error byte is already set, which is the original core's
/// own no-progress outcome: it stores 0 through `written` (`mov r6, #0;
/// str r6, [r5]`) before its first branch and returns 0x15.
unsafe extern "C" fn missing_stream_write_core(
    _stream: *mut u8,
    _length: u32,
    _data: *const u8,
    written: *mut u32,
    _mode: u32,
) -> u32 {
    written.write(0);
    0x15
}

/// Unwired stream-write-core operations.
pub const DEFAULT_STREAM_WRITE_CORE_OPS: StreamWriteCoreOps = StreamWriteCoreOps {
    core: missing_stream_write_core,
};

/// Active stream-write-core operations. Target integration writes this
/// once with the retailOS bridge; host tests temporarily install
/// recorders.
pub static mut STREAM_WRITE_CORE_OPS: StreamWriteCoreOps = DEFAULT_STREAM_WRITE_CORE_OPS;

/// Volatile dispatch prevents target builds using the default from
/// folding away the integration boundary.
#[inline(always)]
fn stream_write_core_ops() -> StreamWriteCoreOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STREAM_WRITE_CORE_OPS)) }
}

/// stream_write — original: `FUN_0827899c` @ 0x0827899c (28 bytes,
/// 21 `bl` + 2 `bleq` + 2 tail `b` call sites).
///
/// Writes `length` bytes from `data` to `stream`, reporting the accepted
/// count through `written` and returning the core's status. Identical to
/// calling the shared core @ 0x082789b8 with mode 0; this front end
/// exists to supply that zeroed fifth, stack-passed argument.
///
/// # Deviations
///
/// The shared core @ 0x082789b8 is not ported; its contract is reached
/// through [`STREAM_WRITE_CORE_OPS`] rather than a guessed
/// implementation. The original pushes the dead r3 value and overwrites
/// its slot with 0; the port passes the literal 0 — the pushed value is
/// never observable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_write(
    stream: *mut u8,
    length: u32,
    data: *const u8,
    written: *mut u32,
) -> u32 {
    (stream_write_core_ops().core)(stream, length, data, written, 0)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::{Mutex, MutexGuard};

    #[derive(Default)]
    struct Recorder {
        calls: usize,
        stream: usize,
        length: u32,
        data: usize,
        written: usize,
        mode: Option<u32>,
        status: u32,
    }

    static LOCK: Mutex<()> = Mutex::new(());
    static RECORDER: Mutex<Recorder> = Mutex::new(Recorder {
        calls: 0,
        stream: 0,
        length: 0,
        data: 0,
        written: 0,
        mode: None,
        status: 0,
    });

    unsafe extern "C" fn recording_core(
        stream: *mut u8,
        length: u32,
        data: *const u8,
        written: *mut u32,
        mode: u32,
    ) -> u32 {
        let mut recorder = RECORDER.lock();
        recorder.calls += 1;
        recorder.stream = stream as usize;
        recorder.length = length;
        recorder.data = data as usize;
        recorder.written = written as usize;
        recorder.mode = Some(mode);
        recorder.status
    }

    fn install(status: u32) -> (MutexGuard<'static, ()>, StreamWriteCoreOps) {
        let lock = LOCK.lock();
        *RECORDER.lock() = Recorder {
            status,
            ..Recorder::default()
        };
        let previous = unsafe { STREAM_WRITE_CORE_OPS };
        unsafe {
            STREAM_WRITE_CORE_OPS = StreamWriteCoreOps {
                core: recording_core,
            };
        }
        (lock, previous)
    }

    fn restore(previous: StreamWriteCoreOps) {
        unsafe { STREAM_WRITE_CORE_OPS = previous };
    }

    #[test]
    fn forwards_all_four_arguments_verbatim_and_zeroes_the_mode() {
        let mut stream = [0u8; 8];
        let data = [0xabu8, 0xcd, 0xef];
        let mut written = u32::MAX;
        let (_lock, previous) = install(0);

        let status = unsafe {
            stream_write(
                stream.as_mut_ptr(),
                3,
                data.as_ptr(),
                &mut written,
            )
        };
        restore(previous);

        let recorder = RECORDER.lock();
        assert_eq!(recorder.calls, 1);
        assert_eq!(recorder.stream, stream.as_ptr() as usize);
        assert_eq!(recorder.length, 3);
        assert_eq!(recorder.data, data.as_ptr() as usize);
        assert_eq!(recorder.written, &written as *const u32 as usize);
        assert_eq!(recorder.mode, Some(0), "the fifth argument is always zeroed");
        assert_eq!(status, 0);
    }

    #[test]
    fn returns_the_cores_status_verbatim() {
        for status in [0u32, 5, 0x15, 0xdead_beef] {
            let (_lock, previous) = install(status);
            let mut written = 0u32;

            let returned = unsafe {
                stream_write(
                    core::ptr::null_mut(),
                    0,
                    core::ptr::null(),
                    &mut written,
                )
            };
            restore(previous);

            assert_eq!(returned, status, "r0 passes through pop {{ip, pc}}");
        }
    }

    #[test]
    fn a_zero_length_write_still_reaches_the_core() {
        let (_lock, previous) = install(0);
        let mut written = 7u32;

        let status =
            unsafe { stream_write(core::ptr::null_mut(), 0, core::ptr::null(), &mut written) };
        restore(previous);

        let recorder = RECORDER.lock();
        assert_eq!(recorder.calls, 1, "no length guard exists in the wrapper");
        assert_eq!(recorder.length, 0);
        assert_eq!(status, 0);
    }

    #[test]
    fn the_unwired_default_reports_nothing_written_and_error_status() {
        let lock = LOCK.lock();
        let previous = unsafe { STREAM_WRITE_CORE_OPS };
        unsafe { STREAM_WRITE_CORE_OPS = DEFAULT_STREAM_WRITE_CORE_OPS };
        let mut written = 99u32;

        let status = unsafe {
            stream_write(
                core::ptr::null_mut(),
                4,
                b"data".as_ptr(),
                &mut written,
            )
        };
        unsafe { STREAM_WRITE_CORE_OPS = previous };
        drop(lock);

        assert_eq!(written, 0, "the core stores 0 through written first");
        assert_eq!(status, 0x15, "the error-byte-set no-progress status");
    }
}
