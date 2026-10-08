//! Set the audio output channel control flag in both controller banks.
//!
//! Original: `FUN_081079c8` @ `0x081079c8`, true size 56 bytes:
//! 52 instruction bytes and the 0x38400b00 literal at 0x081079fc.
//! The next function starts with PUSH at 0x08107a00. Full-image aligned
//! A32 decoding verifies two plain inbound BLs (0x08293aec, 0x08293b28),
//! zero predicated inbound BLs, and zero outgoing BLs of either kind.
//!
//! For channels 1 through 6, read/OR/write bit 28 first at
//! 0x38400900 + channel*0x20, then at 0x38400b00 + channel*0x20.
//! Preserve every other bit and leave channel zero and other words alone.
//! The caller supplies an output object, but r0 is overwritten without use.
//! The hardware meaning of bit 28 remains unidentified.
//!
//! Deliberate deviations: volatile word accesses model MMIO; host builds
//! substitute an isolated register array. No callee seams or added guards.

use core::ptr;

#[cfg(not(target_os = "none"))]
static mut HOST_REGISTERS: [u32; 0xc00 / 4] = [0; 0xc00 / 4];

#[inline(always)]
fn registers() -> *mut u32 {
    #[cfg(target_os = "none")]
    { 0x3840_0000 as *mut u32 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(HOST_REGISTERS).cast::<u32>() }
}

/// Sets bit 28 in the six channel words of each audio output bank.
///
/// # Safety
/// The peripheral must be accessible and callers must serialize register
/// updates. `output` is ignored and need not point to a valid object.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn audio_output_channel_flags_set(_output: *mut u8) {
    let base = registers();
    for channel in 1..7 {
        let first = base.add((0x900 + channel * 0x20) / 4);
        ptr::write_volatile(first, ptr::read_volatile(first) | 0x1000_0000);
        let second = base.add((0xb00 + channel * 0x20) / 4);
        ptr::write_volatile(second, ptr::read_volatile(second) | 0x1000_0000);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_other_bits_and_words_and_is_idempotent() {
        unsafe {
            for seed in [0, u32::MAX, 0xefff_ffff, 0xa55a_1234] {
                let mut expected = [0u32; 0xc00 / 4];
                for word in 0..expected.len() {
                    let value = seed ^ (word as u32).wrapping_mul(0x0101_0101);
                    ptr::write(registers().add(word), value);
                    let offset = word * 4;
                    let selected = [0x920, 0x940, 0x960, 0x980, 0x9a0, 0x9c0,
                                    0xb20, 0xb40, 0xb60, 0xb80, 0xba0, 0xbc0]
                        .contains(&offset);
                    expected[word] = if selected { value | 0x1000_0000 } else { value };
                }
                for output in [ptr::null_mut(), usize::MAX as *mut u8] {
                    audio_output_channel_flags_set(output);
                    for word in 0..expected.len() {
                        assert_eq!(ptr::read_volatile(registers().add(word)), expected[word],
                                   "register offset {:#x}", word * 4);
                    }
                }
            }
        }
    }
}
