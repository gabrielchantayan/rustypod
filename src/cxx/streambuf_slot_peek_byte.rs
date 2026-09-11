//! `streambuf_slot_peek_byte` — original: `FUN_083d7158` @ load address
//! **0x083d7158**.
//!
//! Raw ARM disassembly fixes the extent at exactly 32 bytes,
//! 0x083d7158..0x083d7174: the following separately linked routine begins at
//! 0x083d7178. Decoding every ARM B/BL-immediate word in `osos.dec` finds
//! eight incoming calls, all unconditional plain `bl` (zero predicated):
//! 0x083b646c, 0x083b64b4, 0x083b6528, 0x083b6570, 0x083b66d0, 0x083b6760,
//! 0x083b680c, and 0x083b685c.
//!
//! The routine dereferences its target-width `Streambuf *` slot. A NULL slot
//! produces signed EOF (`-1`); otherwise it calls the raw stream-buffer peek
//! helper at 0x083da5a8. It returns the low byte of either result, so EOF is
//! observable as `0xff`.
//!
//! # Deliberate deviations
//!
//! None on ARM. The shared bridge to 0x083da5a8 preserves the direct call;
//! host tests replace that unavailable target helper with a recorder.

use super::streambuf_slot_peek_equal::streambuf_sgetc;

/// streambuf_slot_peek_byte — original: `FUN_083d7158` @ 0x083d7158
/// (32 bytes; 8 unconditional plain `bl` call sites, zero predicated).
///
/// Dereferences `streambuf_slot`, peeks a non-NULL stream buffer through the
/// retailOS helper at 0x083da5a8, and returns only that helper's low byte. A
/// NULL slot therefore returns the byte form of EOF, `0xff`.
///
/// # Safety
///
/// `streambuf_slot` must point to one aligned, readable target-width
/// `Streambuf *` word. A non-NULL word must name a stream buffer accepted by
/// retailOS helper 0x083da5a8.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn streambuf_slot_peek_byte(streambuf_slot: *const u32) -> u8 {
    let streambuf = streambuf_slot.read() as *mut u8;
    let character = if streambuf.is_null() {
        -1
    } else {
        streambuf_sgetc(streambuf)
    };

    character as u8
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::streambuf_slot_peek_equal::{StreambufSgetc, STREAMBUF_SGETC, STREAMBUF_SGETC_TEST_LOCK};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    const SLOT_OFFSET: usize = 0x100;
    const STREAMBUF_OFFSET: usize = 0x200;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::STREAMBUF_SLOT_PEEK_BYTE, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static RECORDER: Mutex<Recorder> = Mutex::new(Recorder::new());

    struct Recorder {
        call_count: usize,
        streambuf: usize,
        result: i32,
    }

    impl Recorder {
        const fn new() -> Self {
            Self {
                call_count: 0,
                streambuf: 0,
                result: -1,
            }
        }
    }

    unsafe extern "C" fn record_sgetc(streambuf: *mut u8) -> i32 {
        let mut recorder = RECORDER.lock().unwrap_or_else(|poison| poison.into_inner());
        recorder.call_count += 1;
        recorder.streambuf = streambuf as usize;
        recorder.result
    }

    struct SgetcReset(StreambufSgetc);

    impl Drop for SgetcReset {
        fn drop(&mut self) {
            unsafe { STREAMBUF_SGETC = self.0 };
        }
    }

    fn install_sgetc(result: i32) -> SgetcReset {
        *RECORDER.lock().unwrap_or_else(|poison| poison.into_inner()) = Recorder {
            result,
            ..Recorder::new()
        };
        let previous = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STREAMBUF_SGETC)) };
        unsafe { STREAMBUF_SGETC = record_sgetc };
        SgetcReset(previous)
    }

    unsafe fn fixture() -> Option<(*mut u32, *mut u8)> {
        let Some(base) = *FIXTURE else {
            return None;
        };
        let base = base as *mut u8;
        ptr::write_bytes(base, 0, FIXTURE_LEN);
        let slot = base.add(SLOT_OFFSET).cast::<u32>();
        let streambuf = base.add(STREAMBUF_OFFSET);
        slot.write(streambuf as usize as u32);
        Some((slot, streambuf))
    }

    #[test]
    fn null_slot_maps_eof_to_a_byte_without_peeking() {
        let _guard = STREAMBUF_SGETC_TEST_LOCK.lock();
        let _reset = install_sgetc(0x42);
        let Some((slot, _)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("cxx/streambuf_slot_peek_byte"));
            return;
        };
        unsafe { slot.write(0) };

        assert_eq!(unsafe { streambuf_slot_peek_byte(slot) }, 0xff);
        assert_eq!(RECORDER.lock().unwrap_or_else(|poison| poison.into_inner()).call_count, 0);
    }

    #[test]
    fn helper_result_is_truncated_and_receives_slot_value() {
        let _guard = STREAMBUF_SGETC_TEST_LOCK.lock();
        let _reset = install_sgetc(0x1234_56a5);
        let Some((slot, streambuf)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("cxx/streambuf_slot_peek_byte"));
            return;
        };

        assert_eq!(unsafe { streambuf_slot_peek_byte(slot) }, 0xa5);
        let recorder = RECORDER.lock().unwrap_or_else(|poison| poison.into_inner());
        assert_eq!(recorder.call_count, 1);
        assert_eq!(recorder.streambuf, streambuf as usize);
    }

    #[test]
    fn helper_eof_maps_to_ff() {
        let _guard = STREAMBUF_SGETC_TEST_LOCK.lock();
        let _reset = install_sgetc(-1);
        let Some((slot, _)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("cxx/streambuf_slot_peek_byte"));
            return;
        };

        assert_eq!(unsafe { streambuf_slot_peek_byte(slot) }, 0xff);
        assert_eq!(RECORDER.lock().unwrap_or_else(|poison| poison.into_inner()).call_count, 1);
    }
}
