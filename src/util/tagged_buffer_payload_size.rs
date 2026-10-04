//! Tagged-buffer payload size — `FUN_082142a8` @ 0x082142a8.
//! True extent: 48 bytes, 0x082142a8..0x082142d8, ending in `pop {pc}`;
//! the next function is the five-word alignment-padding leaf.
//! Two incoming plain BLs (0x081a89f0, 0x081a8a04), zero predicated BLs.
//! One outgoing plain BL to alignment_padding @ 0x082142d8, zero predicated
//! BLs: `bls` @ 0x082142c0 branches to the return epilogue.
//!
//! Extract the low 24-bit length. Alignment bits 0x70000000 shifted right
//! by 26 yield classes 0, 4, 8, 12, 16, 20, 24, 28. For classes above four,
//! subtract padding for the target address descriptor+12, wrapping modulo
//! 2^32. Other flags do not select a different algorithm. Reuses the canonical
//! alignment_padding port, including its non-power-of-two mask arithmetic.
//! Deliberate deviations: LLVM register allocation and frame layout only.

use crate::util::alignment_padding::alignment_padding;

/// Return the tagged buffer's payload length after alignment padding.
///
/// # Safety
/// `descriptor` must point to one readable, four-byte-aligned word. The
/// payload address is calculated in target-width arithmetic, not dereferenced.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tagged_buffer_payload_size(descriptor: *const u32) -> u32 {
    let flags = unsafe { descriptor.read() };
    let length = flags & 0x00ff_ffff;
    let alignment = (flags & 0x7000_0000) >> 26;
    if alignment <= 4 {
        length
    } else {
        let payload = (descriptor as usize as u32).wrapping_add(12);
        length.wrapping_sub(alignment_padding(payload, alignment))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn covers_alignment_classes_flags_residues_and_length_underflow() {
        let Some(slab) = try_map_u32_slab(hints::TAGGED_BUFFER_PAYLOAD_SIZE, 0x1000) else {
            note_missing_u32_fixture(module_path!());
            return;
        };
        for offset in (0..128).step_by(4) {
            let descriptor = unsafe { slab.add(offset).cast::<u32>() };
            let payload = (descriptor as usize as u32).wrapping_add(12);
            for class in 0..8u32 {
                let alignment = class * 4;
                // Wider arithmetic models ARM's subtraction and final mask;
                // non-power-of-two classes must not use round-up division.
                let padding = if class <= 1 { 0 } else {
                    let mask = u64::from(alignment - 1);
                    ((0x1_0000_0000u64 + u64::from(alignment)
                        - (u64::from(payload) & mask)) & mask) as u32
                };
                for length in [0, 1, padding, padding.saturating_sub(1), 31, 0x00ff_ffff] {
                    for extra_flags in [0, 0x0800_0000, 0x8700_0000] {
                        let flags = (class << 28) | extra_flags | length;
                        unsafe { descriptor.write(flags) };
                        assert_eq!(unsafe { tagged_buffer_payload_size(descriptor) },
                            length.wrapping_sub(padding),
                            "offset={offset}, flags={flags:#x}, padding={padding}");
                        assert_eq!(unsafe { descriptor.read() }, flags);
                    }
                }
            }
        }
    }
}
