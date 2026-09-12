//! `stream_read` — original: `FUN_083d8134` @ 0x083d8134.
//!
//! **120 bytes**, from 0x083d8134 through 0x083d81a8. Raw `osos.dec`
//! disassembly places the separately linked next function, the readiness helper,
//! at 0x083d81ac. A complete aligned ARM B/BL-immediate scan finds seven
//! inbound calls, all unconditional `bl` (no predicated or tail-branch forms):
//! 0x080745d0, 0x080745e8, 0x082aae4c, 0x082aaec0, 0x082aaf28, 0x082aafe4,
//! and 0x082ab0cc.
//!
//! Algorithm: ask the owner readiness helper to begin a mode-0x10 operation.
//! When it permits the read, call the contained reader object's vtable slot
//! `+0x1c` with `(reader, buffer, requested)`. A nonnegative result replaces
//! the owner's completed-count word. Any result other than the requested raw
//! 32-bit count signals owner error 6. It always returns the original owner.
//!
//! Deliberate deviation: readiness (`FUN_083d81ac`) and error signalling
//! (`FUN_083e7898`) are not ported. The target default crosses those verified
//! retailOS entries, while host tests use one volatile operation seam; this also
//! models the target-width vtable function pointer without truncating a host
//! function address.

/// The first two target words of the stream-read owner.
///
/// `owner_descriptor` points to a descriptor whose word at `-0x0c` is the
/// signed byte displacement from this prefix to the complete owner state.
/// The field remains `u32` so its target offset stays four bytes on a 64-bit
/// test host.
#[repr(C)]
pub struct StreamReadOwner {
    owner_descriptor: u32,
    completed: i32,
}

/// The part of the dynamically located complete owner read by this wrapper.
#[repr(C)]
struct StreamReadOwnerState {
    _prefix: [u32; 13],
    reader: u32,
}

const _: [u8; 0x34] = [0; core::mem::offset_of!(StreamReadOwnerState, reader)];

/// Host/test bridge for the three unported call boundaries in [`stream_read`].
///
/// Target defaults call the verified retail addresses and the reader's vtable
/// slot +0x1c. Host tests replace these operations because the firmware stores
/// every pointer, including a function pointer, in one 32-bit word.
#[derive(Clone, Copy)]
pub struct StreamReadOps {
    pub prepare: unsafe extern "C" fn(*mut StreamReadOwner) -> bool,
    pub read: unsafe extern "C" fn(*mut u8, *mut u8, u32) -> i32,
    pub signal: unsafe extern "C" fn(*mut u8, u32) -> u32,
}

type PrepareRead = unsafe extern "C" fn(*mut u8, *mut StreamReadOwner, u32) -> *mut u8;
type ReaderRead = unsafe extern "C" fn(*mut u8, *mut u8, u32) -> i32;
type SignalReadError = unsafe extern "C" fn(*mut u8, u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_prepare(owner: *mut StreamReadOwner) -> bool {
    let prepare: PrepareRead = unsafe { core::mem::transmute(0x083d_81acusize) };
    let mut enabled = 0u8;
    unsafe { prepare(&mut enabled, owner, 1) };
    enabled != 0
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_read(reader: *mut u8, buffer: *mut u8, requested: u32) -> i32 {
    let vtable = unsafe { (reader.cast::<u32>()).read() as *const u32 };
    let read: ReaderRead = unsafe { core::mem::transmute(vtable.add(7).read() as usize) };
    unsafe { read(reader, buffer, requested) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_signal(state: *mut u8, error: u32) -> u32 {
    let signal: SignalReadError = unsafe { core::mem::transmute(0x083e_7898usize) };
    unsafe { signal(state, error) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_prepare(_owner: *mut StreamReadOwner) -> bool {
    panic!("stream_read requires FUN_083d81ac")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_read(_reader: *mut u8, _buffer: *mut u8, _requested: u32) -> i32 {
    panic!("stream_read requires its reader vtable slot +0x1c")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_signal(_state: *mut u8, _error: u32) -> u32 {
    panic!("stream_read requires FUN_083e7898")
}

#[cfg(target_os = "none")]
const DEFAULT_STREAM_READ_OPS: StreamReadOps = StreamReadOps {
    prepare: firmware_prepare,
    read: firmware_read,
    signal: firmware_signal,
};

#[cfg(not(target_os = "none"))]
const DEFAULT_STREAM_READ_OPS: StreamReadOps = StreamReadOps {
    prepare: missing_prepare,
    read: missing_read,
    signal: missing_signal,
};

/// Active stream-read operations. Target defaults preserve the raw helper and
/// vtable dispatches; tests temporarily install recorders.
pub static mut STREAM_READ_OPS: StreamReadOps = DEFAULT_STREAM_READ_OPS;

#[inline(always)]
fn stream_read_ops() -> StreamReadOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STREAM_READ_OPS)) }
}

#[inline(always)]
unsafe fn owner_state(owner: *mut StreamReadOwner) -> *mut StreamReadOwnerState {
    let descriptor = unsafe { (*owner).owner_descriptor as *const i32 };
    let state_offset = unsafe { descriptor.offset(-3).read() };
    unsafe { (owner.cast::<u8>()).offset(state_offset as isize).cast() }
}

/// Reads `requested` bytes through the complete owner's reader object.
///
/// Original: `FUN_083d8134` @ 0x083d8134 (120 bytes, 7 unconditional `bl`
/// call sites verified by decoding every aligned ARM B/BL immediate in
/// `osos.dec`). The raw body has no NULL, alignment, bounds, or short-read
/// guard; its only control gate is the result written by `FUN_083d81ac`.
///
/// # Safety
///
/// `owner` must be a readable/writable owner prefix whose descriptor and
/// displaced complete state are readable; its reader and vtable must satisfy
/// the slot +0x1c ABI. `buffer` must be accepted for `requested` bytes by that
/// vtable method. The original provides none of these checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_read")]
#[inline(never)]
pub unsafe extern "C" fn stream_read(
    owner: *mut StreamReadOwner,
    buffer: *mut u8,
    requested: u32,
) -> *mut StreamReadOwner {
    let ops = stream_read_ops();
    if unsafe { (ops.prepare)(owner) } {
        let state = unsafe { owner_state(owner) };
        let reader = unsafe { (*state).reader as usize as *mut u8 };
        let completed = unsafe { (ops.read)(reader, buffer, requested) };
        if completed >= 0 {
            unsafe { (*owner).completed = completed };
        }
        if requested != completed as u32 {
            unsafe { (ops.signal)(state.cast(), 6) };
        }
    }
    owner
}

#[cfg(test)]
pub(crate) static STREAM_READ_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    const OWNER_AT: usize = 0x100;
    const DESCRIPTOR_AT: usize = 0x300;
    const STATE_AT: usize = 0x400;
    const READER_AT: usize = 0x800;
    static SLAB: LazyLock<Option<usize>> =
        LazyLock::new(|| try_map_u32_slab(hints::CXX_STREAM_READ, SLAB_LEN).map(|p| p as usize));

    #[derive(Default)]
    struct Recorder {
        enabled: bool,
        prepare_calls: u32,
        read_calls: u32,
        reader: usize,
        buffer: usize,
        requested: u32,
        completed: i32,
        signal_calls: u32,
        state: usize,
        error: u32,
    }

    static RECORDER: parking_lot::Mutex<Recorder> = parking_lot::Mutex::new(Recorder {
        enabled: false,
        prepare_calls: 0,
        read_calls: 0,
        reader: 0,
        buffer: 0,
        requested: 0,
        completed: 0,
        signal_calls: 0,
        state: 0,
        error: 0,
    });

    unsafe extern "C" fn recording_prepare(_owner: *mut StreamReadOwner) -> bool {
        let mut recorder = RECORDER.lock();
        recorder.prepare_calls += 1;
        recorder.enabled
    }

    unsafe extern "C" fn recording_read(reader: *mut u8, buffer: *mut u8, requested: u32) -> i32 {
        let mut recorder = RECORDER.lock();
        recorder.read_calls += 1;
        recorder.reader = reader as usize;
        recorder.buffer = buffer as usize;
        recorder.requested = requested;
        recorder.completed
    }

    unsafe extern "C" fn recording_signal(state: *mut u8, error: u32) -> u32 {
        let mut recorder = RECORDER.lock();
        recorder.signal_calls += 1;
        recorder.state = state as usize;
        recorder.error = error;
        0
    }

    fn install(enabled: bool, completed: i32) -> StreamReadOps {
        *RECORDER.lock() = Recorder { enabled, completed, ..Recorder::default() };
        let previous = unsafe { STREAM_READ_OPS };
        unsafe {
            STREAM_READ_OPS = StreamReadOps {
                prepare: recording_prepare,
                read: recording_read,
                signal: recording_signal,
            };
        }
        previous
    }

    fn restore(previous: StreamReadOps) {
        unsafe { STREAM_READ_OPS = previous };
    }

    fn fixture() -> Option<(*mut StreamReadOwner, *mut u8, *mut u8)> {
        let base = (*SLAB)? as *mut u8;
        unsafe { ptr::write_bytes(base, 0, SLAB_LEN) };
        let owner = unsafe { base.add(OWNER_AT).cast::<StreamReadOwner>() };
        let descriptor = unsafe { base.add(DESCRIPTOR_AT) };
        let state = unsafe { base.add(STATE_AT).cast::<StreamReadOwnerState>() };
        let reader = unsafe { base.add(READER_AT) };
        unsafe {
            owner.write(StreamReadOwner {
                owner_descriptor: descriptor as usize as u32,
                completed: -77,
            });
            descriptor.sub(12).cast::<i32>().write(STATE_AT as i32 - OWNER_AT as i32);
            (*state).reader = reader as usize as u32;
        }
        Some((owner, state.cast(), reader))
    }

    #[test]
    fn complete_read_forwards_the_contained_reader_and_updates_completed() {
        let _guard = STREAM_READ_TEST_LOCK.lock();
        let Some((owner, _state, reader)) = fixture() else {
            assert!(note_missing_u32_fixture("cxx/stream_read"));
            return;
        };
        let previous = install(true, 5);
        let mut buffer = [0u8; 5];

        let returned = unsafe { stream_read(owner, buffer.as_mut_ptr(), 5) };
        restore(previous);

        let recorder = RECORDER.lock();
        assert_eq!(returned, owner);
        assert_eq!(recorder.prepare_calls, 1);
        assert_eq!(recorder.read_calls, 1);
        assert_eq!(recorder.reader, reader as usize);
        assert_eq!(recorder.buffer, buffer.as_ptr() as usize);
        assert_eq!(recorder.requested, 5);
        assert_eq!(unsafe { (*owner).completed }, 5);
        assert_eq!(recorder.signal_calls, 0);
    }

    #[test]
    fn short_read_updates_completed_and_signals_error_six() {
        let _guard = STREAM_READ_TEST_LOCK.lock();
        let Some((owner, state, _reader)) = fixture() else {
            assert!(note_missing_u32_fixture("cxx/stream_read"));
            return;
        };
        let previous = install(true, 2);

        let returned = unsafe { stream_read(owner, ptr::null_mut(), 4) };
        restore(previous);

        let recorder = RECORDER.lock();
        assert_eq!(returned, owner);
        assert_eq!(unsafe { (*owner).completed }, 2);
        assert_eq!(recorder.signal_calls, 1);
        assert_eq!(recorder.state, state as usize);
        assert_eq!(recorder.error, 6);
    }

    #[test]
    fn negative_read_keeps_completed_but_still_signals_a_raw_count_mismatch() {
        let _guard = STREAM_READ_TEST_LOCK.lock();
        let Some((owner, _state, _reader)) = fixture() else {
            assert!(note_missing_u32_fixture("cxx/stream_read"));
            return;
        };
        let previous = install(true, -1);

        unsafe { stream_read(owner, ptr::null_mut(), 0) };
        restore(previous);

        let recorder = RECORDER.lock();
        assert_eq!(unsafe { (*owner).completed }, -77);
        assert_eq!(recorder.signal_calls, 1);
        assert_eq!(recorder.error, 6);
    }

    #[test]
    fn denied_preparation_skips_the_reader_and_preserves_completed() {
        let _guard = STREAM_READ_TEST_LOCK.lock();
        let Some((owner, _state, _reader)) = fixture() else {
            assert!(note_missing_u32_fixture("cxx/stream_read"));
            return;
        };
        let previous = install(false, 4);

        unsafe { stream_read(owner, ptr::null_mut(), 4) };
        restore(previous);

        let recorder = RECORDER.lock();
        assert_eq!(recorder.prepare_calls, 1);
        assert_eq!(recorder.read_calls, 0);
        assert_eq!(recorder.signal_calls, 0);
        assert_eq!(unsafe { (*owner).completed }, -77);
    }
}
