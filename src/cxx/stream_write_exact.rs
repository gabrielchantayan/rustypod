//! `stream_write_exact` — original: `FUN_081f53e0` @ 0x081f53e0.
//!
//! **76 bytes**, nineteen instruction words, no literal pool. Raw osos.dec
//! disassembly establishes the body as 0x081f53e0..0x081f5428 inclusive;
//! 0x081f542c begins the separately linked stream-writer constructor.
//!
//! Twelve callers reach this function, all unconditional `bl`: 0x081615b4,
//! 0x081615f4, 0x08161624, 0x08161650, 0x08161684, 0x081616c4,
//! 0x081616fc, 0x08161728, 0x08161760, 0x0816180c, 0x08161854, and
//! 0x081619b0. Decoding every ARM B/BL immediate in osos.dec found no
//! predicated or tail-branch caller.
//!
//! Algorithm: load the requested byte count from `length` and the contained
//! stream pointer at owner +8, call [`stream_write`], then replace `length`
//! with the completed count. It succeeds when all requested bytes completed,
//! regardless of the writer status; a short write maps status 0x11 to 1 and
//! every other status to 3.

use crate::cxx::stream_write::stream_write;

/// Owner layout observed by this wrapper. `stream` is at +8 on both the
/// 32-bit target and host because the preceding state is two 32-bit words.
#[repr(C)]
pub struct StreamWriteOwner {
    _state: [u32; 2],
    stream: *mut u8,
}

/// Write exactly the requested byte count, translating a short write into the
/// caller's three-result status convention.
///
/// Original: `FUN_081f53e0` @ 0x081f53e0 (76 bytes, 12 unconditional `bl`
/// call sites).
///
/// # Deviations
///
/// The ARM prologue saves its incoming, otherwise unused r3 in the stack word
/// subsequently supplied as `stream_write`'s out-parameter. The retailOS
/// shared write core always overwrites that word before returning. The port
/// initializes it to zero so a partially implemented replacement core cannot
/// expose an ABI-scratch register value; a compliant core's result is
/// identical.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_write_exact(
    owner: *mut StreamWriteOwner,
    data: *const u8,
    length: *mut u32,
) -> u32 {
    let requested = length.read();
    let stream = (*owner).stream;
    let mut completed = 0;
    let write_status = stream_write(stream, requested, data, &mut completed);

    let result = if length.read() == completed {
        0
    } else if write_status == 0x11 {
        1
    } else {
        3
    };
    length.write(completed);
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::stream_write::{StreamWriteCoreOps, STREAM_WRITE_CORE_OPS, STREAM_WRITE_TEST_LOCK};
    use parking_lot::Mutex;

    #[derive(Default)]
    struct Recorder {
        calls: usize,
        stream: usize,
        length: u32,
        data: usize,
        completed: u32,
        status: u32,
    }

    static RECORDER: Mutex<Recorder> = Mutex::new(Recorder {
        calls: 0,
        stream: 0,
        length: 0,
        data: 0,
        completed: 0,
        status: 0,
    });

    unsafe extern "C" fn recording_core(
        stream: *mut u8,
        length: u32,
        data: *const u8,
        completed: *mut u32,
        _mode: u32,
    ) -> u32 {
        let mut recorder = RECORDER.lock();
        recorder.calls += 1;
        recorder.stream = stream as usize;
        recorder.length = length;
        recorder.data = data as usize;
        completed.write(recorder.completed);
        recorder.status
    }

    fn install(completed: u32, status: u32) -> StreamWriteCoreOps {
        *RECORDER.lock() = Recorder {
            completed,
            status,
            ..Recorder::default()
        };
        let previous = unsafe { STREAM_WRITE_CORE_OPS };
        unsafe {
            STREAM_WRITE_CORE_OPS = StreamWriteCoreOps {
                core: recording_core,
            };
        }
        previous
    }

    fn restore(previous: StreamWriteCoreOps) {
        unsafe { STREAM_WRITE_CORE_OPS = previous };
    }

    #[test]
    fn forwards_owner_stream_and_replaces_length_after_a_full_write() {
        let _guard = STREAM_WRITE_TEST_LOCK.lock();
        let mut stream = [0u8; 8];
        let mut owner = StreamWriteOwner {
            _state: [0; 2],
            stream: stream.as_mut_ptr(),
        };
        let data = [0xa5u8; 7];
        let previous = install(7, 0x15);
        let mut length = 7;

        let status = unsafe { stream_write_exact(&mut owner, data.as_ptr(), &mut length) };
        restore(previous);

        let recorder = RECORDER.lock();
        assert_eq!(recorder.calls, 1);
        assert_eq!(recorder.stream, stream.as_ptr() as usize);
        assert_eq!(recorder.length, 7);
        assert_eq!(recorder.data, data.as_ptr() as usize);
        assert_eq!(length, 7);
        assert_eq!(status, 0, "a complete write ignores the core status");
    }

    #[test]
    fn short_write_maps_the_error_status_and_reports_completed_count() {
        let _guard = STREAM_WRITE_TEST_LOCK.lock();
        let mut stream = [0u8; 1];
        let mut owner = StreamWriteOwner {
            _state: [0; 2],
            stream: stream.as_mut_ptr(),
        };
        let data = [0u8; 4];

        for (core_status, expected) in [(0x11, 1), (5, 3)] {
            let previous = install(2, core_status);
            let mut length = 4;
            let status = unsafe { stream_write_exact(&mut owner, data.as_ptr(), &mut length) };
            restore(previous);

            assert_eq!(length, 2);
            assert_eq!(status, expected);
        }
    }

    #[test]
    fn zero_length_write_still_calls_the_stream_and_succeeds_when_complete() {
        let _guard = STREAM_WRITE_TEST_LOCK.lock();
        let mut owner = StreamWriteOwner {
            _state: [0; 2],
            stream: core::ptr::null_mut(),
        };
        let previous = install(0, 0xdead_beef);
        let mut length = 0;

        let status = unsafe { stream_write_exact(&mut owner, core::ptr::null(), &mut length) };
        restore(previous);

        assert_eq!(RECORDER.lock().calls, 1, "there is no zero-length guard");
        assert_eq!(length, 0);
        assert_eq!(status, 0, "a full write wins over an error status");
    }
}
