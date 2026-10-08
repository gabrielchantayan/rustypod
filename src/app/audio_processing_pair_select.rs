//! Select audio processing words — retailOS `FUN_0812252c` @ `0x0812252c`.
//!
//! True extent: 152 bytes [0x0812252c, 0x081225c4), including the literal
//! at +148; next function starts with LDRH at 0x081225c4. Raw A32 verifies
//! zero outbound plain/predicated BLs and two inbound plain BLs at
//! 0x081224ac/0x08123498 (zero predicated). Select a two-word table entry
//! using input sample bits (+4), channels (+8), and Q16 rate ratio (+0x48).
//! Copy it to +0x9c/+0xa0 and set the changed byte at +0x18 to one.
//!
//! Deliberate deviations: target table reads remain volatile at 0x083e25fc;
//! host builds use its verified raw-image words. These words resemble A32
//! instructions, not established callee identities: retain them verbatim,
//! without creating call seams or assuming that the table is immutable.

#[cfg(not(target_os = "none"))]
const HOST_PROCESSING_WORDS: [u32; 16] = [
    0xe58d0000, 0xe59d1000, 0xe59d0004, 0xe1500001,
    0x228d0004, 0x31a0000d, 0xe5906000, 0xe3a01000,
    0xe1a00206, 0xebfa1192, 0xe1a08000, 0xe8950003,
    0xe1a02008, 0xe1a03004, 0xeb00199d, 0xe8940006,
];

/// # Safety
/// `state` must point to at least 41 aligned, readable/writable u32 words.
/// On the device, the firmware processing table must be readable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn audio_processing_pair_select(state: *mut u32) {
    let bits = state.add(1).read();
    let stereo = state.add(2).read() == 2;
    let unity_rate = state.add(18).read() == 0x10000;
    let entry = if unity_rate {
        if bits == 16 { if stereo { 1 } else { 0 } }
        else { if stereo { 2 } else { 3 } }
    } else {
        if bits == 16 { if stereo { 4 } else { 5 } }
        else { if stereo { 6 } else { 7 } }
    };
    #[cfg(target_os = "none")]
    let table = 0x083e25fc as *const u32;
    #[cfg(not(target_os = "none"))]
    let table = HOST_PROCESSING_WORDS.as_ptr();
    let first = table.add(entry * 2).read_volatile();
    let second = table.add(entry * 2 + 1).read_volatile();
    state.add(39).write(first);
    state.add(40).write(second);
    state.cast::<u8>().add(0x18).write(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_every_pair_and_preserves_neighbors_for_noncanonical_inputs() {
        for ratio in [0, 0xffff, 0x10000, 0x10001, u32::MAX] {
            for bits in [0, 8, 16, 17, u32::MAX] {
                for channels in [0, 1, 2, 3, u32::MAX] {
                    let expected = match (ratio == 0x10000, bits == 16, channels == 2) {
                        (true, true, false) => (0xe58d0000, 0xe59d1000),
                        (true, true, true) => (0xe59d0004, 0xe1500001),
                        (true, false, true) => (0x228d0004, 0x31a0000d),
                        (true, false, false) => (0xe5906000, 0xe3a01000),
                        (false, true, true) => (0xe1a00206, 0xebfa1192),
                        (false, true, false) => (0xe1a08000, 0xe8950003),
                        (false, false, true) => (0xe1a02008, 0xe1a03004),
                        (false, false, false) => (0xeb00199d, 0xe8940006),
                    };
                    let mut state = [0xa5b6c7d8; 43];
                    state[1] = bits;
                    state[2] = channels;
                    state[18] = ratio;
                    let mut reference = state;
                    reference[39] = expected.0;
                    reference[40] = expected.1;
                    reference[6] = (reference[6] & 0xffffff00) | 1;
                    unsafe { audio_processing_pair_select(state.as_mut_ptr()); }
                    assert_eq!(state, reference, "ratio={ratio:#x}, bits={bits}, channels={channels}");
                }
            }
        }
    }
}
