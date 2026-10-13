//! Selects the key representation before STANDARD cipher schedule expansion.
//!
//! `standard_cipher_expand_key` — original `FUN_0802ad38` at `0x0802ad38`:
//! 108 bytes, [0x0802ad38, 0x0802ada4), ending in POP before the next PUSH.
//! Raw A32 decoding verifies two outgoing plain BLs (serializer at 0x0802ad84,
//! expansion at 0x0802ad98) and two incoming plain BLs (0x0802af5c,
//! 0x082ea1d0); no predicated BLs in either direction.
//!
//! Mode 2 serializes four scalar words most-significant byte first into a
//! sixteen-byte stack key. Every other mode uses the supplied byte pointer.
//! Expands that key through the existing retail helper at 0x0802dec0 using
//! the unchanged mode, signed round-count bits, and destination.
//!
//! Deliberate deviations: reuse the Rust serializer and the existing retail
//! expansion veneer. Pointer-typed seams preserve native host addresses and
//! the four-word ARM ABI. No mode validation or key-pointer NULL guard added.

use super::standard_cipher_configure::retail_standard_cipher_expand_key;
use crate::util::store_four_u32_be::store_four_u32_be;

/// # Safety
/// Except in mode 2, `key` must satisfy the retail expansion helper's read
/// contract. `schedule` must hold its output. Mode 2 never dereferences `key`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn standard_cipher_expand_key(
    key_mode: u32, first: u32, second: u32, third: u32, fourth: u32,
    key: *const u8, round_count: u32, schedule: *mut u8,
) {
    let mut serialized = core::mem::MaybeUninit::<[u8; 16]>::uninit();
    let selected = if key_mode == 2 {
        let destination = serialized.as_mut_ptr().cast::<u8>();
        unsafe { store_four_u32_be(first, second, third, fourth, destination); }
        destination as *const u8
    } else {
        key
    };
    unsafe { retail_standard_cipher_expand_key(selected, key_mode, round_count, schedule); }
}

#[cfg(test)]
mod tests {
    use super::standard_cipher_expand_key;
    use super::super::standard_cipher_configure::{EXPANSION_TEST_LOCK,
        RETAIL_STANDARD_CIPHER_EXPAND_KEY, RetailStandardCipherExpandKey};

    // Reference for the first 128-bit expansion round in 0x0802dec0.
    // These four substitution bytes are from the raw table at 0x0891ee4c;
    // the fixture deliberately restricts the final key word to indices 0..3.
    unsafe extern "C" fn reference_first_round(
        key: *const u8, mode: u32, rounds: u32, schedule: *mut u8,
    ) {
        assert!(mode == 0 || mode == 2);
        assert_eq!(rounds, 1);
        let substitution = [0x27u8, 0x53, 0x82, 0x61];
        for i in 0..16 { *schedule.add(i) = *key.add(i); }
        for i in 0..4 {
            *schedule.add(16 + i) = *key.add(i)
                ^ substitution[*key.add(12 + (i + 1) % 4) as usize]
                ^ if i == 0 { 1 } else { 0 };
        }
        for i in 4..16 {
            *schedule.add(16 + i) = *schedule.add(12 + i) ^ *key.add(i);
        }
    }

    struct Restore(RetailStandardCipherExpandKey);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { RETAIL_STANDARD_CIPHER_EXPAND_KEY = self.0; } }
    }

    #[test]
    fn word_key_and_unaligned_byte_key_produce_verified_first_round() {
        let _lock = EXPANSION_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _restore = unsafe {
            let restore = Restore(RETAIL_STANDARD_CIPHER_EXPAND_KEY);
            RETAIL_STANDARD_CIPHER_EXPAND_KEY = reference_first_round;
            restore
        };
        let key = [0, 1, 2, 3, 3, 2, 1, 0, 1, 0, 3, 2, 2, 3, 0, 1];
        let expected_round = [0x60, 0x26, 0x51, 0x81, 0x63, 0x24, 0x50, 0x81,
            0x62, 0x24, 0x53, 0x83, 0x60, 0x27, 0x53, 0x82];
        let mut source = [0xa5u8; 18];
        source[1..17].copy_from_slice(&key);
        for mode in [0, 2] {
            let mut output = [0xa5u8; 34];
            unsafe {
                standard_cipher_expand_key(mode,
                    if mode == 2 { 0x00010203 } else { u32::MAX },
                    if mode == 2 { 0x03020100 } else { u32::MAX },
                    if mode == 2 { 0x01000302 } else { u32::MAX },
                    if mode == 2 { 0x02030001 } else { u32::MAX },
                    if mode == 2 { core::ptr::null() } else { source.as_ptr().add(1) },
                    1, output.as_mut_ptr().add(1));
            }
            assert_eq!(&output[1..17], &key);
            assert_eq!(&output[17..33], &expected_round);
            assert_eq!((output[0], output[33]), (0xa5, 0xa5));
            assert_eq!(&source[1..17], &key);
        }
    }
}
