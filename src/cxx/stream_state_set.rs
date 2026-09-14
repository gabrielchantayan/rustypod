//! `stream_state_set` — original: `FUN_083e7898` @ **0x083e7898** (28 bytes).
//!
//! Raw ARM is seven instructions from 0x083e7898 through 0x083e78b0; the
//! following `ldr r1,[pc,#52]` at 0x083e78b4 starts a separately linked
//! constructor. Decoding every aligned ARM `B`/`BL` immediate in `osos.dec`
//! finds five direct inbound calls: `blne` at 0x083b5420, 0x083b54e0, and
//! 0x083d81a0; plain `bl` at 0x083d8334; and `bleq` at 0x083d8384. There are
//! no inbound tail branches.
//!
//! Algorithm: OR `requested_state` into the stream state at +0x10. If word
//! +0x34 is zero, also set state bit 0. Tail-dispatch to 0x082a8db8 with the
//! stream, accumulated state, and an all-ones mask; its return value becomes
//! this function's return value.
//!
//! Deliberate deviation: 0x082a8db8 is unported. Target builds branch to that
//! retailOS helper; host builds use a volatile callback seam to prove the
//! exact arguments and forwarded result.

#[cfg(not(target_os = "none"))]
use core::ptr;

const RETAIL_STREAM_STATE_CLEAR: usize = 0x082a_8db8;
const BAD_STATE_BIT: u32 = 1;
const ALL_STATE_BITS: u32 = u32::MAX;

#[repr(C)]
struct StreamStateFields {
    _before_state: [u32; 4],
    state: u32,
    _between_state_and_sentry: [u32; 8],
    sentry: u32,
}

/// Host boundary for the unported state-clear helper at 0x082a8db8.
#[cfg(not(target_os = "none"))]
pub struct StreamStateSetOps {
    pub clear: unsafe extern "C" fn(*mut u8, u32, u32) -> u32,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_stream_state_clear(_stream: *mut u8, _state: u32, _mask: u32) -> u32 {
    0
}

/// Host callback seam for the unported state-clear helper. Target builds call
/// 0x082a8db8 directly.
#[cfg(not(target_os = "none"))]
pub static mut STREAM_STATE_SET_OPS: StreamStateSetOps = StreamStateSetOps {
    clear: missing_stream_state_clear,
};

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn stream_state_clear(stream: *mut u8, state: u32) -> u32 {
    let clear: unsafe extern "C" fn(*mut u8, u32, u32) -> u32 =
        core::mem::transmute(RETAIL_STREAM_STATE_CLEAR);
    clear(stream, state, ALL_STATE_BITS)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn stream_state_clear(stream: *mut u8, state: u32) -> u32 {
    let clear = ptr::read_volatile(ptr::addr_of!(STREAM_STATE_SET_OPS.clear));
    clear(stream, state, ALL_STATE_BITS)
}

/// Accumulates `requested_state` into a stream's state and invokes its state
/// clear helper with all state bits enabled.
///
/// # Safety
/// `stream` must point to writable, word-aligned storage with u32 fields at
/// +0x10 and +0x34. The original has no NULL or bounds guard. The installed
/// host callback must accept the same stream pointer.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_state_set")]
#[inline(never)]
pub unsafe extern "C" fn stream_state_set(stream: *mut u8, requested_state: u32) -> u32 {
    let fields = stream.cast::<StreamStateFields>();
    let mut state = core::ptr::addr_of!((*fields).state).read_volatile() | requested_state;
    if core::ptr::addr_of!((*fields).sentry).read_volatile() == 0 {
        state |= BAD_STATE_BIT;
    }
    stream_state_clear(stream, state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static CLEAR_CALLS: AtomicU32 = AtomicU32::new(0);
    static SEEN_STREAM: AtomicUsize = AtomicUsize::new(0);
    static SEEN_STATE: AtomicU32 = AtomicU32::new(0);
    static SEEN_MASK: AtomicU32 = AtomicU32::new(0);
    const CLEAR_RESULT: u32 = 0xc1ea_0001;

    unsafe extern "C" fn record_clear(stream: *mut u8, state: u32, mask: u32) -> u32 {
        SEEN_STREAM.store(stream as usize, Ordering::SeqCst);
        SEEN_STATE.store(state, Ordering::SeqCst);
        SEEN_MASK.store(mask, Ordering::SeqCst);
        CLEAR_CALLS.fetch_add(1, Ordering::SeqCst);
        CLEAR_RESULT
    }

    fn install_recording_clear() {
        unsafe {
            STREAM_STATE_SET_OPS = StreamStateSetOps { clear: record_clear };
        }
        CLEAR_CALLS.store(0, Ordering::SeqCst);
        SEEN_STREAM.store(0, Ordering::SeqCst);
        SEEN_STATE.store(0, Ordering::SeqCst);
        SEEN_MASK.store(0, Ordering::SeqCst);
    }

    fn fixture(state: u32, sentry: u32) -> StreamStateFields {
        StreamStateFields {
            _before_state: [0xa5a5_a5a5; 4],
            state,
            _between_state_and_sentry: [0xa5a5_a5a5; 8],
            sentry,
        }
    }

    #[test]
    fn accumulates_state_without_bad_bit_when_sentry_is_set() {
        let _lock = TEST_LOCK.lock();
        install_recording_clear();
        let mut stream = fixture(0x10, 1);
        let stream_ptr = (&mut stream as *mut StreamStateFields).cast::<u8>();

        assert_eq!(unsafe { stream_state_set(stream_ptr, 0x24) }, CLEAR_RESULT);
        assert_eq!(CLEAR_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(SEEN_STREAM.load(Ordering::SeqCst), stream_ptr as usize);
        assert_eq!(SEEN_STATE.load(Ordering::SeqCst), 0x34);
        assert_eq!(SEEN_MASK.load(Ordering::SeqCst), u32::MAX);
        assert_eq!(stream.state, 0x10);
    }

    #[test]
    fn adds_bad_bit_when_sentry_is_clear() {
        let _lock = TEST_LOCK.lock();
        install_recording_clear();
        let mut stream = fixture(0x8, 0);
        let stream_ptr = (&mut stream as *mut StreamStateFields).cast::<u8>();

        assert_eq!(unsafe { stream_state_set(stream_ptr, 0) }, CLEAR_RESULT);
        assert_eq!(CLEAR_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(SEEN_STATE.load(Ordering::SeqCst), 0x9);
        assert_eq!(SEEN_MASK.load(Ordering::SeqCst), u32::MAX);
        assert_eq!(stream.state, 0x8);
    }
}
