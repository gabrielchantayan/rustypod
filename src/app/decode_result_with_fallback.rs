//! Handles a decoded result and retries through its fallback payload —
//! `FUN_0805bf20` @ 0x0805bf20.
//!
//! Raw `osos.dec` establishes the exact 176-byte body
//! 0x0805bf20..0x0805bfcc: `pop {r4-r8,pc}` ends it, and 0x0805bfd0 begins
//! the next sibling function. The body has three plain `bl` calls
//! (0x08065dfc, 0x08031140, and 0x0805c0c8) and no predicated calls.
//!
//! Algorithm: invoke the primary decoder using the owner's +0x158 context.
//! Normalize status 0x20 to 0x30. On success, inspect the decoded result's
//! tag: tags 3/4 carry a word at +4 and payload at +8; tags 0x300/0x400 carry
//! a word at +10 and payload at +14. A nonzero carried word is submitted to
//! the fallback decoder; unknown tags and zero words leave the primary status.
//! Deliberate deviation: the three unresolved retail callees retain verified
//! address seams on target and replaceable host seams; their stronger semantic
//! identity is not yet recovered.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_PRIMARY_DECODE: usize = 0x0806_5dfc;
const RETAIL_READ_WORD: usize = 0x0803_1140;
const RETAIL_FALLBACK_DECODE: usize = 0x0805_c0c8;

pub type PrimaryDecode = unsafe extern "C" fn(*mut u32, u32, u32, u32, *mut u8, *mut *mut u8, u32) -> u32;
pub type ReadWord = unsafe extern "C" fn(*const u32) -> u32;
pub type FallbackDecode = unsafe extern "C" fn(*const u32, u32, *mut u8, u32, u32, *mut u8, u32) -> u32;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct DecodeResultOps {
    pub primary_decode: PrimaryDecode,
    pub read_word: ReadWord,
    pub fallback_decode: FallbackDecode,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_primary_decode(_: *mut u32, _: u32, _: u32, _: u32, _: *mut u8, _: *mut *mut u8, _: u32) -> u32 {
    panic!("install decode-result host operations before calling this wrapper")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_read_word(_: *const u32) -> u32 {
    panic!("install decode-result host operations before calling this wrapper")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_fallback_decode(_: *const u32, _: u32, _: *mut u8, _: u32, _: u32, _: *mut u8, _: u32) -> u32 {
    panic!("install decode-result host operations before calling this wrapper")
}

#[cfg(not(target_os = "none"))]
pub static mut DECODE_RESULT_OPS: DecodeResultOps = DecodeResultOps {
    primary_decode: missing_primary_decode,
    read_word: missing_read_word,
    fallback_decode: missing_fallback_decode,
};

#[inline(always)]
unsafe fn primary_decode(context: *mut u32, input: u32, fallback_data: u32, result: *mut u8, result_out: *mut *mut u8, caller_context: u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let target: PrimaryDecode = unsafe { core::mem::transmute(RETAIL_PRIMARY_DECODE) };
        unsafe { target(context, input, fallback_data, input, result, result_out, caller_context) }
    }
    #[cfg(not(target_os = "none"))]
    {
        let target = unsafe { core::ptr::read_volatile(addr_of!(DECODE_RESULT_OPS.primary_decode)) };
        unsafe { target(context, input, fallback_data, input, result, result_out, caller_context) }
    }
}

#[inline(always)]
unsafe fn read_word(word: *const u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let target: ReadWord = unsafe { core::mem::transmute(RETAIL_READ_WORD) };
        unsafe { target(word) }
    }
    #[cfg(not(target_os = "none"))]
    {
        let target = unsafe { core::ptr::read_volatile(addr_of!(DECODE_RESULT_OPS.read_word)) };
        unsafe { target(word) }
    }
}

#[inline(always)]
unsafe fn fallback_decode(owner: *const u32, decoded_word: u32, payload: *mut u8, input: u32, _fallback_data: u32, result: *mut u8, caller_context: u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let target: FallbackDecode = unsafe { core::mem::transmute(RETAIL_FALLBACK_DECODE) };
        unsafe { target(owner, decoded_word, payload, 0, input, result, caller_context) }
    }
    #[cfg(not(target_os = "none"))]
    {
        let target = unsafe { core::ptr::read_volatile(addr_of!(DECODE_RESULT_OPS.fallback_decode)) };
        unsafe { target(owner, decoded_word, payload, 0, input, result, caller_context) }
    }
}

/// Decodes `input`, then processes a nonempty fallback payload from its result.
///
/// # Safety
/// `owner` must point to at least 0x15c readable bytes and its +0x158 word
/// must be accepted by the primary decoder. `result` must be aligned and large
/// enough for the tagged result record selected by that decoder.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn decode_result_with_fallback(owner: *const u32, fallback_data: u32, input: u32, result: *mut u8, caller_context: u32) -> u32 {
    let context = unsafe { *owner.add(0x158 / 4) } as usize as *mut u32;
    let mut result_out = result;
    let mut status = unsafe { primary_decode(context, input, fallback_data, result, &mut result_out, caller_context) };
    if status == 0x20 {
        return 0x30;
    }
    if status != 0 {
        return status;
    }

    let tag = unsafe { core::ptr::read(result.cast::<u16>()) };
    let (decoded_word, payload) = match tag {
        3 | 4 => (unsafe { core::ptr::read(result.add(4).cast::<u32>()) }, unsafe { result.add(8) }),
        0x300 | 0x400 => (unsafe { read_word(result.add(10).cast::<u32>()) }, unsafe { result.add(14) }),
        _ => return 0,
    };
    if decoded_word != 0 {
        status = unsafe { fallback_decode(owner, decoded_word, payload, input, fallback_data, result, caller_context) };
    }
    status
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr::addr_of_mut;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static LOCK: Mutex<()> = Mutex::new(());
    static PRIMARY_STATUS: Mutex<u32> = Mutex::new(0);
    static FALLBACK_CALL: LazyLock<Mutex<Option<(u32, usize, u32, usize, u32)>>> = LazyLock::new(|| Mutex::new(None));

    unsafe extern "C" fn primary(_: *mut u32, _: u32, _: u32, _: u32, _: *mut u8, _: *mut *mut u8, _: u32) -> u32 {
        *PRIMARY_STATUS.lock()
    }
    unsafe extern "C" fn word_at(pointer: *const u32) -> u32 { unsafe { pointer.read_unaligned() } }
    unsafe extern "C" fn fallback(_: *const u32, word: u32, payload: *mut u8, _: u32, input: u32, result: *mut u8, caller_context: u32) -> u32 {
        *FALLBACK_CALL.lock() = Some((word, payload as usize, input, result as usize, caller_context));
        0x47
    }

    fn install(status: u32) {
        *PRIMARY_STATUS.lock() = status;
        *FALLBACK_CALL.lock() = None;
        unsafe { DECODE_RESULT_OPS = DecodeResultOps { primary_decode: primary, read_word: word_at, fallback_decode: fallback } };
    }

    #[test]
    fn normalizes_primary_capacity_status_without_inspecting_result() {
        let _guard = LOCK.lock();
        install(0x20);
        let owner = [0u32; 0x159 / 4 + 1];
        let mut result = [0u32; 5];
        assert_eq!(unsafe { decode_result_with_fallback(owner.as_ptr(), 0x11, 0x22, result.as_mut_ptr().cast(), 0x33) }, 0x30);
        assert_eq!(*FALLBACK_CALL.lock(), None);
    }

    #[test]
    fn dispatches_nonempty_compact_and_wide_results() {
        let _guard = LOCK.lock();
        let owner = [0u32; 0x159 / 4 + 1];
        let mut compact = [0u32; 5];
        install(0);
        unsafe { compact.as_mut_ptr().cast::<u16>().write(4); compact.as_mut_ptr().add(1).write(0x1234) };
        assert_eq!(unsafe { decode_result_with_fallback(owner.as_ptr(), 0x11, 0x22, compact.as_mut_ptr().cast(), 0x33) }, 0x47);
        assert_eq!(*FALLBACK_CALL.lock(), Some((0x1234, compact.as_mut_ptr() as usize + 8, 0x22, compact.as_mut_ptr() as usize, 0x33)));

        let mut wide = [0u32; 6];
        install(0);
        unsafe { wide.as_mut_ptr().cast::<u16>().write(0x300); wide.as_mut_ptr().cast::<u8>().add(10).cast::<u32>().write_unaligned(0x5678) };
        assert_eq!(unsafe { decode_result_with_fallback(owner.as_ptr(), 0x11, 0x22, wide.as_mut_ptr().cast(), 0x33) }, 0x47);
        assert_eq!(*FALLBACK_CALL.lock(), Some((0x5678, wide.as_mut_ptr() as usize + 14, 0x22, wide.as_mut_ptr() as usize, 0x33)));
    }

    #[test]
    fn leaves_zero_and_unknown_results_successful() {
        let _guard = LOCK.lock();
        let owner = [0u32; 0x159 / 4 + 1];
        let mut result = [0u32; 5];
        install(0);
        unsafe { result.as_mut_ptr().cast::<u16>().write(3) };
        assert_eq!(unsafe { decode_result_with_fallback(owner.as_ptr(), 0, 0, addr_of_mut!(result).cast(), 0) }, 0);
        unsafe { result.as_mut_ptr().cast::<u16>().write(5); result.as_mut_ptr().add(1).write(1) };
        assert_eq!(unsafe { decode_result_with_fallback(owner.as_ptr(), 0, 0, result.as_mut_ptr().cast(), 0) }, 0);
        assert_eq!(*FALLBACK_CALL.lock(), None);
    }
}
