//! Query the shared iAP session's advertised sample-rate capabilities.

use core::ptr::read_volatile;

/// Original `FUN_081f20f0` at 0x081f20f0: 176 bytes through 0x081f21a0
/// (168 code bytes and literals at 0x081f2198/9c).
/// Verified inbound calls: two plain BLs at 0x081f20ac and 0x081f2270,
/// zero predicated BLs. Body: zero plain or predicated BLs.
/// Read the capability mask at shared session 0x089cca2c + 0x10, then
/// test bits 0..8 for 8000, 11025, 12000, 16000, 22050, 24000, 32000,
/// 44100 and 48000 Hz respectively. All other signed rates return zero.
/// Deviations: use the existing host-rebindable session state and a volatile
/// aligned word read; express the original comparison tree as a Rust match.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iap_sample_rate_supported(rate_hz: i32) -> u32 {
    #[cfg(target_os = "none")]
    let state = 0x089cca2c as *const u32;
    #[cfg(not(target_os = "none"))]
    let state = read_volatile(core::ptr::addr_of!(super::iap_session_state_reset::IAP_SESSION_STATE));
    supports_rate(read_volatile(state.add(4)), rate_hz)
}

#[inline(always)]
fn supports_rate(capabilities: u32, rate_hz: i32) -> u32 {
    let bit = match rate_hz {
        8000 => 1,
        11025 => 2,
        12000 => 4,
        16000 => 8,
        22050 => 16,
        24000 => 32,
        32000 => 64,
        44100 => 128,
        48000 => 256,
        _ => return 0,
    };
    (capabilities & bit != 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    const RATES: [i32; 9] = [8000, 11025, 12000, 16000, 22050, 24000, 32000, 44100, 48000];

    #[test]
    fn every_capability_combination_matches_rate_membership() {
        for mask in 0..512u32 {
            for (index, rate) in RATES.into_iter().enumerate() {
                let expected = (mask >> index) & 1;
                assert_eq!(supports_rate(mask, rate), expected);
                assert_eq!(supports_rate(mask | 0xfffffe00, rate), expected);
            }
        }
    }

    #[test]
    fn rejects_signed_extremes_and_neighbors_even_with_all_bits_set() {
        for rate in [i32::MIN, -48000, -1, 0, 1, i32::MAX] {
            assert_eq!(supports_rate(u32::MAX, rate), 0);
        }
        for rate in RATES {
            assert_eq!(supports_rate(u32::MAX, rate - 1), 0);
            assert_eq!(supports_rate(u32::MAX, rate + 1), 0);
        }
    }
}
