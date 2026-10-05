//! Configure audio-resampler rates — retailOS `FUN_081e7148` @ `0x081e7148`.
//!
//! True extent: 84 bytes [0x081e7148, 0x081e719c). Raw A32 has six
//! outbound plain BLs, zero predicated BLs; two inbound plain BLs at
//! 0x081970f4 and 0x08197498, zero predicated inbound BLs. The next function
//! independently copies interleaved halfword samples. Store source and
//! destination rates at +12/+16, clear phase at +36, then compute the
//! unsigned Q16.16 step as truncate(scale(source/destination, 16) + 0.5),
//! converting each unsigned rate to binary32 before division.
//!
//! Deliberate deviations: reuse the existing ADS floating-point ports rather
//! than native arithmetic (notably __fadd's tie-away behavior). The repr(C)
//! format prefix widens its vtable pointer on hosts; field order, not native
//! byte offsets, preserves the target layout. No new retail-call seams.

use super::audio_format_notify_mismatch::AudioFormatComparison;
use crate::fp::fp_fadd::__fadd;
use crate::fp::fp_fconv::{__f2u, __u2f};
use crate::fp::fp_fmuldiv::__fdiv;
use crate::fp::fp_scalb::__fscalb;

#[repr(C)]
pub struct AudioResampler {
    pub format: AudioFormatComparison,
    pub phase: u32,
    pub step: u32,
}

/// # Safety
/// `resampler` must reference a valid, writable AudioResampler.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn audio_resampler_set_rates(
    resampler: *mut AudioResampler, source_rate: u32, destination_rate: u32,
) {
    (*resampler).format.source_rate = source_rate;
    (*resampler).format.destination_rate = destination_rate;
    (*resampler).phase = 0;
    let destination = __u2f(destination_rate);
    let source = __u2f(source_rate);
    let ratio = __fdiv(source, destination);
    let scaled = __fscalb(ratio, 16);
    (*resampler).step = __f2u(__fadd(scaled, 0x3f00_0000));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_reset_phase_and_round_step_without_changing_format_metadata() {
        // Independent expected values include ordinary audio rates, half-unit
        // rounding, integer->binary32 precision loss, and conversion saturation.
        for (source, destination, step) in [
            (44100, 48000, 60211), (48000, 44100, 71332),
            (8000, 48000, 10923), (48000, 8000, 393216),
            (1, 131072, 1), (1, 262144, 0),
            (0, 48000, 0), (0, 0, 0), (1, 0, u32::MAX),
            (u32::MAX, 1, u32::MAX), (u32::MAX, u32::MAX, 65536),
            (16777217, 16777216, 65536),
        ] {
            let mut state = AudioResampler {
                format: AudioFormatComparison {
                    vtable: core::ptr::null(), reserved: [0x12345678, 0x87654321],
                    source_rate: 99, destination_rate: 100,
                    source_bits: 16, destination_bits: 8,
                    source_channels: 2, destination_channels: 1,
                },
                phase: u32::MAX, step: 0xdeadbeef,
            };
            unsafe { audio_resampler_set_rates(&mut state, source, destination); }
            assert_eq!((state.format.source_rate, state.format.destination_rate),
                (source, destination));
            assert_eq!((state.phase, state.step), (0, step), "{source}/{destination}");
            assert!(state.format.vtable.is_null());
            assert_eq!(state.format.reserved, [0x12345678, 0x87654321]);
            assert_eq!((state.format.source_bits, state.format.destination_bits,
                state.format.source_channels, state.format.destination_channels), (16, 8, 2, 1));
        }
    }
}
