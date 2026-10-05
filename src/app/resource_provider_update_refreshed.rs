//! Resource-provider refreshed-state update.
//!
//! Original: `FUN_081b6f94` @ `0x081b6f94`, 32 bytes, ending with `bx lr`
//! at `0x081b6fb0`; the next function's push is at `0x081b6fb4`.
//! Full-image aligned A32 decoding verifies two plain inbound BLs at
//! `0x0822e058` and `0x0822e080`, zero predicated inbound BLs, and zero
//! outbound calls. Read byte +0xe8; only if nonzero, read byte +0xe9.
//! Store their normalized conjunction at +0xeb, preserving all other bytes.
//! No deliberate behavioral deviations. Volatile byte accesses preserve the
//! firmware's conditional read and single-byte write; the unused incoming r0
//! value is preserved by the original but is not a caller-consumed result.

/// Updates the resource provider's normalized refreshed-state byte.
///
/// # Safety
/// `provider` must permit a read at +0xe8 and a write at +0xeb, and a read
/// at +0xe9 when +0xe8 is nonzero. No alignment or NULL guard is imposed.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_provider_update_refreshed(provider: *mut u8) {
    let refreshed = unsafe { provider.add(0xe8).read_volatile() != 0 }
        && unsafe { provider.add(0xe9).read_volatile() != 0 };
    unsafe { provider.add(0xeb).write_volatile(refreshed as u8) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_byte_pairs_normalize_and_preserve_other_fields() {
        let mut provider = [0xa5u8; 0xed];
        for first in 0..=255u8 {
            for second in 0..=255u8 {
                provider[0xe8] = first;
                provider[0xe9] = second;
                provider[0xeb] = 0xff;
                let mut expected = provider;
                expected[0xeb] = if first == 0 { 0 } else if second == 0 { 0 } else { 1 };
                unsafe { resource_provider_update_refreshed(provider.as_mut_ptr()) };
                assert_eq!(provider, expected);
                // Reusing an object must clear stale true state as inputs change.
                provider[0xe8] = 0;
                expected[0xe8] = 0;
                expected[0xeb] = 0;
                unsafe { resource_provider_update_refreshed(provider.as_mut_ptr()) };
                assert_eq!(provider, expected);
            }
        }
    }
}
