//! `streambuf_slot_consume` — original: `FUN_083daf50` @ load address
//! **0x083daf50**.
//!
//! Raw ARM disassembly fixes the extent at exactly 28 bytes,
//! 0x083daf50..0x083daf68: `pop {r4,pc}` at 0x083daf68 is followed by the
//! separately linked slot-lookup routine at 0x083daf6c. Decoding every ARM
//! B/BL-immediate word in `osos.dec` finds seven inbound calls, all
//! unconditional plain `bl` (zero predicated): 0x083b649c, 0x083b6544,
//! 0x083b6594, 0x083b6728, 0x083b677c, 0x083b6820, and 0x083b6944.
//!
//! The body loads the target-width `Streambuf *` from its slot, skips NULL,
//! otherwise calls 0x083da654 with that buffer, and returns the original slot.
//! Raw 0x083da654 confirms that it consumes the buffered byte when one is
//! available and otherwise dispatches a stream-buffer virtual method; this
//! port intentionally names only its established consumption behavior rather
//! than assigning an unverified C++ callee identity.
//!
//! # Deliberate deviations
//!
//! None on ARM. The bridge tail-branches directly to the still-unported
//! 0x083da654 helper. Host tests replace only that unavailable target helper
//! with a recorder; no target-width callback is fabricated.

#[cfg(target_arch = "arm")]
extern "C" {
    fn streambuf_consume_raw(streambuf: *mut u8);
}

// Direct bridge to the raw stream-buffer consumption helper at 0x083da654.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .section .text.streambuf_consume_raw, "ax", %progbits
    .p2align 2
    .globl streambuf_consume_raw
    .type streambuf_consume_raw, %function
streambuf_consume_raw:
    b       0x083da654
    .size streambuf_consume_raw, . - streambuf_consume_raw
"#
);

#[cfg(not(target_arch = "arm"))]
pub(crate) type StreambufConsume = unsafe extern "C" fn(*mut u8);

/// Host-only stand-in for the unavailable direct helper.
///
/// It is test infrastructure only: ARM always tail-branches to 0x083da654.
#[cfg(not(target_arch = "arm"))]
pub(crate) unsafe extern "C" fn unavailable_streambuf_consume(_streambuf: *mut u8) {}

#[cfg(not(target_arch = "arm"))]
pub(crate) static mut STREAMBUF_CONSUME: StreambufConsume = unavailable_streambuf_consume;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn streambuf_consume_raw(streambuf: *mut u8) {
    core::ptr::read_volatile(core::ptr::addr_of!(STREAMBUF_CONSUME))(streambuf)
}

/// streambuf_slot_consume — original: `FUN_083daf50` @ 0x083daf50
/// (28 bytes; 7 unconditional plain `bl` call sites, zero predicated).
///
/// Dereferences `streambuf_slot`; a zero target-width stream-buffer word is
/// left alone, while a nonzero word is passed once to retailOS helper
/// 0x083da654. The slot is not overwritten and is returned even after the
/// helper runs.
///
/// # Safety
///
/// `streambuf_slot` must point to one aligned, readable target-width
/// `Streambuf *` word. A nonzero word must name a buffer accepted by retailOS
/// helper 0x083da654.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn streambuf_slot_consume(streambuf_slot: *mut u32) -> *mut u32 {
    let streambuf = streambuf_slot.read() as *mut u8;
    if !streambuf.is_null() {
        streambuf_consume_raw(streambuf);
    }
    streambuf_slot
}

#[cfg(test)]
pub(crate) static STREAMBUF_CONSUME_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    const SLOT_OFFSET: usize = 0x100;
    const STREAMBUF_OFFSET: usize = 0x200;

    static RECORDER: Mutex<Recorder> = Mutex::new(Recorder::new());
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::STREAMBUF_SLOT_CONSUME, FIXTURE_LEN).map(|pointer| pointer as usize)
    });


    struct Recorder {
        call_count: usize,
        streambuf: usize,
    }

    impl Recorder {
        const fn new() -> Self {
            Self {
                call_count: 0,
                streambuf: 0,
            }
        }
    }

    unsafe extern "C" fn record_consume(streambuf: *mut u8) {
        let mut recorder = RECORDER.lock().unwrap_or_else(|poison| poison.into_inner());
        recorder.call_count += 1;
        recorder.streambuf = streambuf as usize;
    }

    struct ConsumeReset(StreambufConsume);

    impl Drop for ConsumeReset {
        fn drop(&mut self) {
            unsafe { STREAMBUF_CONSUME = self.0 };
        }
    }

    fn install_consume() -> ConsumeReset {
        *RECORDER.lock().unwrap_or_else(|poison| poison.into_inner()) = Recorder::new();
        let previous = unsafe { ptr::read_volatile(ptr::addr_of!(STREAMBUF_CONSUME)) };
        unsafe { STREAMBUF_CONSUME = record_consume };
        ConsumeReset(previous)
    }

    unsafe fn fixture() -> Option<(*mut u32, *mut u8)> {
        let base = (*FIXTURE)? as *mut u8;
        ptr::write_bytes(base, 0, FIXTURE_LEN);
        let slot = base.add(SLOT_OFFSET).cast::<u32>();
        let streambuf = base.add(STREAMBUF_OFFSET);
        slot.write(streambuf as usize as u32);
        Some((slot, streambuf))
    }

    #[test]
    fn null_slot_skips_consume_and_returns_the_original_slot() {
        let _guard = STREAMBUF_CONSUME_TEST_LOCK.lock();
        let _reset = install_consume();
        let Some((slot, _)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("cxx/streambuf_slot_consume"));
            return;
        };
        unsafe { slot.write(0) };

        assert_eq!(unsafe { streambuf_slot_consume(slot) }, slot);
        let recorder = RECORDER.lock().unwrap_or_else(|poison| poison.into_inner());
        assert_eq!(recorder.call_count, 0);
        assert_eq!(unsafe { slot.read() }, 0);
    }

    #[test]
    fn nonnull_slot_forwards_once_and_keeps_the_slot_value() {
        let _guard = STREAMBUF_CONSUME_TEST_LOCK.lock();
        let _reset = install_consume();
        let Some((slot, streambuf)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("cxx/streambuf_slot_consume"));
            return;
        };

        assert_eq!(unsafe { streambuf_slot_consume(slot) }, slot);
        let recorder = RECORDER.lock().unwrap_or_else(|poison| poison.into_inner());
        assert_eq!(recorder.call_count, 1);
        assert_eq!(recorder.streambuf, streambuf as usize);
        assert_eq!(unsafe { slot.read() }, streambuf as usize as u32);
    }
}
