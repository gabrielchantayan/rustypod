//! `callback_table_random_seed` — `FUN_08062154` @ **0x08062154**.
//!
//! True instruction size: 88 bytes, ending at 0x080621ac; the two literal
//! words occupy 0x080621ac..0x080621b4, where the next real function begins.
//! Verified outgoing calls: two plain BL and one BLEQ (three total).
//! Generate eight entropy words, pack their bytes little-endian into a
//! 32-byte stack buffer, dispatch slot +0x0c with length 32 and double 32.0,
//! then poison the buffer and return 1, even when the slot is absent.
//!
//! Deliberate deviation: call the existing random-service Rust implementation
//! with explicit inherited r4 = byte index (0, 4, ..., 28), rather than rely
//! on LLVM register allocation across the stock veneer. Its r0-r3 arguments
//! are unused. Reuse the existing callback and heap-poison state models.

use crate::app::callback_table_double_to_i32_dispatch::callback_table_double_to_i32_dispatch;
use crate::heap::heap_poison::heap_poison;
use crate::runtime::rtc_seeded_random_service::rtc_seeded_random_service_inner;

/// The entropy service, callback table, and heap-poison state must be valid.
/// The callback may use the buffer synchronously, but must not retain it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn callback_table_random_seed() -> u32 {
    let mut bytes = [0u8; 32];
    for offset in (0..32).step_by(4) {
        let word = rtc_seeded_random_service_inner(0, 0, 0, 0, offset as u32);
        bytes[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
    }
    callback_table_double_to_i32_dispatch(bytes.as_mut_ptr(), 32, 0x4040_0000_0000_0000);
    heap_poison(bytes.as_mut_ptr(), 32);
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::callback_table::tests::{reset_callback_table_for_test, CALLBACK_TABLE_TEST_LOCK};
    use crate::app::callback_table_double_to_i32_dispatch::HostCallbackTable;
    use crate::drivers::ata_cmd::LARGE_ALLOC_TAG;
    use crate::runtime::rtc_seeded_random_service::*;
    use crate::testing::{RTC_SEEDED_RANDOM_SERVICE_TEST_LOCK, TRACED_ALLOC_TEST_LOCK};

    static mut READS: u32 = 0;
    static mut CAPTURED: [u8; 32] = [0; 32];
    static mut DISPATCHED: bool = false;
    static mut POISON_START: usize = 0;

    unsafe extern "C" fn acquire() -> u32 { 7 }
    unsafe extern "C" fn release(token: u32) { assert_eq!(token, 7); }
    unsafe extern "C" fn timer() -> u32 { 3 }
    unsafe extern "C" fn rtc(_: u32, out: *mut u8) -> i32 {
        for i in 0..7 { out.add(i).write(i as u8); }
        0
    }
    unsafe extern "C" fn read() -> u32 {
        let n = READS;
        READS += 1;
        match n % 4 { 0 => 0, 1 => u32::MAX, 2 => 0x8001_7ffe, _ => 0x0123_4567 }
    }
    unsafe extern "C" fn capture(bytes: *mut u8, len: u32, entropy: i32) {
        assert_eq!((len, entropy), (32, 32));
        core::ptr::copy_nonoverlapping(bytes, core::ptr::addr_of_mut!(CAPTURED).cast(), 32);
        DISPATCHED = true;
        POISON_START = bytes as usize;
        // A callback may change the shared tag before the subsequent poison.
        LARGE_ALLOC_TAG = 0xf0;
    }

    #[test]
    fn packs_full_words_seeds_once_and_poisons_after_optional_dispatch() {
        let _entropy = RTC_SEEDED_RANDOM_SERVICE_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _tag = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _table = CALLBACK_TABLE_TEST_LOCK.lock();
        unsafe {
            let saved = (ENTROPY_SESSION_ACQUIRE, ENTROPY_WORD_READ, ENTROPY_SESSION_RELEASE,
                RTC_READ, TIMER_READ, INITIALIZED, ENTROPY_WORD, ENTROPY_SEED, LARGE_ALLOC_TAG);
            let (mut initialized, mut input, mut seed) = (0u32, 5u32, 0u32);
            (ENTROPY_SESSION_ACQUIRE, ENTROPY_WORD_READ, ENTROPY_SESSION_RELEASE,
                RTC_READ, TIMER_READ, INITIALIZED, ENTROPY_WORD, ENTROPY_SEED) =
                (acquire, read, release, rtc, timer, &mut initialized, &mut input, &mut seed);
            READS = 0;
            for present in [true, false] {
                let table = HostCallbackTable { unresolved_00_to_08: [0; 3],
                    dispatch_double_as_i32: if present { Some(capture) } else { None } };
                reset_callback_table_for_test((&table as *const HostCallbackTable).cast_mut().cast());
                DISPATCHED = false;
                assert_eq!(callback_table_random_seed(), 1);
                assert_eq!(DISPATCHED, present);
                assert_eq!(seed, 29); // RTC sum 21 + timer 3 + input 5 + first r4 0.
                assert_eq!(initialized, 1);
                if present {
                    assert_eq!(READS, 27); // Nineteen warm-up reads, then eight words.
                    let words = [0x0123_4567u32, 0, u32::MAX, 0x8001_7ffe,
                        0x0123_4567, 0, u32::MAX, 0x8001_7ffe];
                    let expected: [u8; 32] = core::array::from_fn(|i| (words[i / 4] >> (8 * (i % 4))) as u8);
                    assert_eq!(core::ptr::addr_of!(CAPTURED).read(), expected);
                    let mut tag = 0xf0u8;
                    let mut fills = [0u8; 32];
                    for i in 0..32 {
                        fills[i] = tag;
                        tag = tag.wrapping_add(((POISON_START + i + 1) & 15) as u8).wrapping_add(17);
                    }
                    if fills.contains(&tag) { tag = tag.wrapping_add(63); }
                    assert_eq!(LARGE_ALLOC_TAG, tag);
                } else { assert_eq!(READS, 35); }
            }
            reset_callback_table_for_test(core::ptr::null_mut());
            (ENTROPY_SESSION_ACQUIRE, ENTROPY_WORD_READ, ENTROPY_SESSION_RELEASE,
                RTC_READ, TIMER_READ, INITIALIZED, ENTROPY_WORD, ENTROPY_SEED, LARGE_ALLOC_TAG) = saved;
        }
    }
}
