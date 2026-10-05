//! Notify an audio-format interface whether its paired formats differ.
//!
//! retailOS `0x081e71cc`, true extent 56 bytes [0x081e71cc,0x081e7204).
//! Raw A32 verifies two inbound plain BLs (0x0819711c, 0x081974c4), no
//! predicated inbound BLs, and no outbound plain or predicated BLs. The final
//! `bx r2` tail-dispatches virtual slot +8. The next function starts with
//! `push {r4-r11,lr}`. Compare sample rates, then bit depths, then channel
//! counts, stopping at the first unequal pair. Always dispatch with exactly
//! zero for identical formats or one for differing formats. Callers establish
//! the field roles by accepting sample rates, bit depths 8/16 and channels 1/2.
//!
//! Deliberate deviations: host repr(C) pointers widen, preserving field and
//! vtable word indices rather than host byte offsets. The virtual method has
//! no verified concrete identity; retain dynamic dispatch, not a retail seam.

#[repr(C)]
pub struct AudioFormatVtable {
    pub reserved: [usize; 2],
    pub notify_mismatch: unsafe extern "C" fn(*mut AudioFormatComparison, u32),
}

#[repr(C)]
pub struct AudioFormatComparison {
    pub vtable: *const AudioFormatVtable,
    pub reserved: [u32; 2],
    pub source_rate: u32,
    pub destination_rate: u32,
    pub source_bits: u32,
    pub destination_bits: u32,
    pub source_channels: u32,
    pub destination_channels: u32,
}

/// The receiver and its vtable must be valid, with a callable slot +8.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn audio_format_notify_mismatch(receiver: *mut AudioFormatComparison) {
    let mismatch = (*receiver).source_rate != (*receiver).destination_rate
        || (*receiver).source_bits != (*receiver).destination_bits
        || (*receiver).source_channels != (*receiver).destination_channels;
    ((*(*receiver).vtable).notify_mismatch)(receiver, mismatch as u32);
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn record(receiver: *mut AudioFormatComparison, mismatch: u32) {
        // The real method may mutate its receiver. Capture both call count and
        // argument in fields the comparison itself must leave untouched.
        (*receiver).reserved[0] += 1;
        (*receiver).reserved[1] = mismatch;
    }

    #[test]
    fn each_format_pair_controls_notification_without_changing_formats() {
        let vtable = AudioFormatVtable { reserved: [0; 2], notify_mismatch: record };
        for base in [[44100, 16, 2], [0, 0, 0], [u32::MAX, 0x80000000, u32::MAX]] {
            for mask in 0..8 {
                let destination = [base[0] ^ (mask & 1),
                    base[1] ^ ((mask >> 1) & 1), base[2] ^ ((mask >> 2) & 1)];
                let mut receiver = AudioFormatComparison {
                    vtable: &vtable, reserved: [0, 99],
                    source_rate: base[0], destination_rate: destination[0],
                    source_bits: base[1], destination_bits: destination[1],
                    source_channels: base[2], destination_channels: destination[2],
                };
                unsafe { audio_format_notify_mismatch(&mut receiver); }
                assert_eq!(receiver.reserved, [1, (base != destination) as u32]);
                assert_eq!(receiver.vtable, &vtable as *const _);
                assert_eq!([receiver.source_rate, receiver.source_bits, receiver.source_channels], base);
                assert_eq!([receiver.destination_rate, receiver.destination_bits,
                    receiver.destination_channels], destination);
                // Even a repeated equal-state notification must dispatch again.
                unsafe { audio_format_notify_mismatch(&mut receiver); }
                assert_eq!(receiver.reserved, [2, (base != destination) as u32]);
            }
        }
    }
}
