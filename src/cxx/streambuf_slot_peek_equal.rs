//! `streambuf_slot_peek_equal` — original: `FUN_083d6504` @ load address
//! **0x083d6504**.
//!
//! Raw ARM confirms the exact 76-byte extent, 0x083d6504..0x083d654c:
//! the `pop {r4,r5,r6,pc}` at 0x083d654c is followed by the independently
//! linked sibling at 0x083d6550. Decoding every ARM B/BL word in `osos.dec`
//! finds exactly nine incoming calls, all unconditional plain `bl` (no
//! predicated forms): 0x083b6450, 0x083b64a4, 0x083b6518, 0x083b6560,
//! 0x083b6690, 0x083b6750, 0x083b67fc, 0x083b694c, and 0x083d7b5c.
//!
//! The routine loads two `Streambuf *` slots from context +0x6c and +0x70.
//! A NULL stream buffer is represented as EOF (`-1`); a non-NULL buffer is
//! passed to retailOS's direct `sgetc`-shaped helper at 0x083da5a8, which
//! returns its next byte or reaches its virtual fallback. The two resulting
//! `i32` character values are compared and normalized to a C++ bool. The
//! slots themselves are deliberately not NULL-guarded, exactly as the raw
//! `ldr r0,[r1]` / `ldr r0,[r5]` sequence requires.
//!
//! # Deliberate deviations
//!
//! None on ARM: the shared bridge tail-branches directly to the unported
//! helper at 0x083da5a8. Host tests replace that helper through a test-only
//! recorder because a target-width vtable callback word cannot name a native
//! x86-64 callback.

/// Context fields consumed by [`streambuf_slot_peek_equal`].
///
/// All pointer-bearing fields remain target-width words: a Rust host pointer
/// would make +0x6c/+0x70 overlap or move. The preceding fields are not read
/// by this routine.
#[repr(C)]
pub struct StreambufSlotPairContext {
    unused: [u32; 27],
    left_slot: u32,
    right_slot: u32,
}

const _: [u8; 0x6c] = [0; core::mem::offset_of!(StreambufSlotPairContext, left_slot)];
const _: [u8; 0x70] = [0; core::mem::offset_of!(StreambufSlotPairContext, right_slot)];

#[cfg(target_arch = "arm")]
extern "C" {
    pub(crate) fn streambuf_sgetc(streambuf: *mut u8) -> i32;
}

// Reaches the exact unported direct callee while retaining the caller's LR.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .section .text.streambuf_sgetc, "ax", %progbits
    .p2align 2
    .globl streambuf_sgetc
    .type streambuf_sgetc, %function
streambuf_sgetc:
    b       0x083da5a8
    .size streambuf_sgetc, . - streambuf_sgetc
"#
);

#[cfg(not(target_arch = "arm"))]
pub(crate) type StreambufSgetc = unsafe extern "C" fn(*mut u8) -> i32;

/// Host-only stand-in for the unported virtual stream-buffer helper.
///
/// It is test-only infrastructure, not a target integration seam: ARM always
/// tail-branches to 0x083da5a8 above. EOF is the helper's observable result
/// for an exhausted stream buffer when no recorder is installed.
#[cfg(not(target_arch = "arm"))]
pub(crate) unsafe extern "C" fn unavailable_streambuf_sgetc(_streambuf: *mut u8) -> i32 {
    -1
}

#[cfg(not(target_arch = "arm"))]
pub(crate) static mut STREAMBUF_SGETC: StreambufSgetc = unavailable_streambuf_sgetc;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
pub(crate) unsafe fn streambuf_sgetc(streambuf: *mut u8) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(STREAMBUF_SGETC))(streambuf)
}

/// streambuf_slot_peek_equal — original: `FUN_083d6504` @ 0x083d6504
/// (76 bytes; 9 unconditional plain `bl` call sites, zero predicated).
///
/// Returns true when the next character reported by the two stream buffers
/// selected through `context`'s +0x6c/+0x70 slots is equal. A NULL buffer in
/// either slot contributes EOF (`-1`) without calling 0x083da5a8. The left
/// buffer is sampled before the right one, matching the two ordered `bl`
/// instructions in the raw body.
///
/// # Safety
///
/// `context` must point to a live [`StreambufSlotPairContext`]. Its two slot
/// words must be readable `Streambuf *` words; every non-NULL buffer must
/// satisfy retailOS helper 0x083da5a8's stream-buffer contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn streambuf_slot_peek_equal(context: *const StreambufSlotPairContext) -> bool {
    let left_slot = (*context).left_slot as *const u32;
    let right_slot = (*context).right_slot as *const u32;

    let left_streambuf = left_slot.read() as *mut u8;
    let left_character = if left_streambuf.is_null() {
        -1
    } else {
        streambuf_sgetc(left_streambuf)
    };

    let right_streambuf = right_slot.read() as *mut u8;
    let right_character = if right_streambuf.is_null() {
        -1
    } else {
        streambuf_sgetc(right_streambuf)
    };

    left_character == right_character
}

#[cfg(test)]
pub(crate) static STREAMBUF_SGETC_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    const LEFT_SLOT_OFFSET: usize = 0x100;
    const RIGHT_SLOT_OFFSET: usize = 0x104;
    const LEFT_STREAMBUF_OFFSET: usize = 0x200;
    const RIGHT_STREAMBUF_OFFSET: usize = 0x300;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::STREAMBUF_SLOT_PEEK_EQUAL, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static RECORDER: Mutex<Recorder> = Mutex::new(Recorder::new());

    struct Recorder {
        calls: [usize; 2],
        call_count: usize,
        results: [i32; 2],
    }

    impl Recorder {
        const fn new() -> Self {
            Self {
                calls: [0; 2],
                call_count: 0,
                results: [0; 2],
            }
        }
    }

    unsafe extern "C" fn record_sgetc(streambuf: *mut u8) -> i32 {
        let mut recorder = RECORDER.lock().unwrap_or_else(|poison| poison.into_inner());
        let index = recorder.call_count;
        recorder.calls[index] = streambuf as usize;
        recorder.call_count += 1;
        recorder.results[index]
    }

    struct SgetcReset(StreambufSgetc);

    impl Drop for SgetcReset {
        fn drop(&mut self) {
            unsafe { STREAMBUF_SGETC = self.0 };
        }
    }

    fn install_sgetc(results: [i32; 2]) -> SgetcReset {
        *RECORDER.lock().unwrap_or_else(|poison| poison.into_inner()) = Recorder {
            results,
            ..Recorder::new()
        };
        let previous = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STREAMBUF_SGETC)) };
        unsafe { STREAMBUF_SGETC = record_sgetc };
        SgetcReset(previous)
    }

    unsafe fn fixture() -> Option<(*mut StreambufSlotPairContext, *mut u8, *mut u8)> {
        let Some(base) = *FIXTURE else {
            return None;
        };
        let base = base as *mut u8;
        ptr::write_bytes(base, 0, FIXTURE_LEN);
        let context = base.cast::<StreambufSlotPairContext>();
        let left_slot = base.add(LEFT_SLOT_OFFSET).cast::<u32>();
        let right_slot = base.add(RIGHT_SLOT_OFFSET).cast::<u32>();
        let left_streambuf = base.add(LEFT_STREAMBUF_OFFSET);
        let right_streambuf = base.add(RIGHT_STREAMBUF_OFFSET);
        (*context).left_slot = left_slot as usize as u32;
        (*context).right_slot = right_slot as usize as u32;
        (left_slot).write(left_streambuf as usize as u32);
        (right_slot).write(right_streambuf as usize as u32);
        Some((context, left_streambuf, right_streambuf))
    }

    #[test]
    fn null_streambufs_compare_as_eof_without_peeking() {
        let _guard = STREAMBUF_SGETC_TEST_LOCK.lock();
        let _reset = install_sgetc([17, 23]);
        let Some((context, _, _)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("cxx/streambuf_slot_peek_equal"));
            return;
        };
        unsafe {
            let base = context.cast::<u8>();
            (base.add(LEFT_SLOT_OFFSET).cast::<u32>()).write(0);
            (base.add(RIGHT_SLOT_OFFSET).cast::<u32>()).write(0);
            assert!(streambuf_slot_peek_equal(context));
        }
        assert_eq!(RECORDER.lock().unwrap_or_else(|poison| poison.into_inner()).call_count, 0);
    }

    #[test]
    fn equal_peeks_sample_left_then_right() {
        let _guard = STREAMBUF_SGETC_TEST_LOCK.lock();
        let _reset = install_sgetc([0xff, 0xff]);
        let Some((context, left, right)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("cxx/streambuf_slot_peek_equal"));
            return;
        };
        assert!(unsafe { streambuf_slot_peek_equal(context) });
        let recorder = RECORDER.lock().unwrap_or_else(|poison| poison.into_inner());
        assert_eq!(recorder.call_count, 2);
        assert_eq!(recorder.calls, [left as usize, right as usize]);
    }

    #[test]
    fn null_buffer_is_eof_and_different_peeks_do_not_compare_equal() {
        let _guard = STREAMBUF_SGETC_TEST_LOCK.lock();
        let _reset = install_sgetc([0, -1]);
        let Some((context, _, right)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("cxx/streambuf_slot_peek_equal"));
            return;
        };
        unsafe {
            let base = context.cast::<u8>();
            (base.add(LEFT_SLOT_OFFSET).cast::<u32>()).write(0);
            assert!(!streambuf_slot_peek_equal(context));
        }
        let recorder = RECORDER.lock().unwrap_or_else(|poison| poison.into_inner());
        assert_eq!(recorder.call_count, 1);
        assert_eq!(recorder.calls[0], right as usize);
    }
}
