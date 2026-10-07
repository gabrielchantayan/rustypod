//! RIFF/WAVE chunk lookup used by the retailOS WAVE loader.

use crate::util::be_read::read_u32_be;
use crate::util::le_read::read_u32_le;

/// `wave_find_chunk` — `FUN_08137034` @ 0x08137034.
/// True extent [0x08137034, 0x08137094): 96 bytes; next function starts
/// at 0x08137094. Whole-image ARM-word decoding verifies two plain BL
/// callers (0x081371e0, 0x081371f8), zero predicated BL callers, and two
/// outgoing plain BLs: read_u32_le @ 0x080ed748 and read_u32_be @ 0x080743b8.
///
/// Read the buffer descriptor from owner word one, form its wrapping u32
/// end address, and unconditionally probe the chunk at RIFF base + 12.
/// Compare the big-endian FourCC after reading the little-endian length.
/// On mismatch advance by length + 8, then stop if the advanced address
/// PLUS the same length + 8 is unsigned >= end. This unusual double-stride
/// bound and absence of RIFF odd-length padding are intentional firmware
/// behavior, not corrected here. Return the matching header address or zero.
/// Caller 0x08137148 validates RIFF/WAVE and searches for `fmt ` and `data`.
/// No deliberate behavioral deviations; target addresses stay u32 on hosts.
///
/// # Safety
/// `owner` must expose two aligned u32 words. Its second word points to an
/// aligned descriptor containing buffer address and byte length. Every chunk
/// actually probed must expose eight readable bytes, even if outside the
/// descriptor's declared extent. All traversed addresses must be valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn wave_find_chunk(owner: *const u32, riff_base: u32, fourcc: u32) -> u32 {
    let descriptor = *owner.add(1) as usize as *const u32;
    let end = (*descriptor).wrapping_add(*descriptor.add(1));
    let mut chunk = riff_base.wrapping_add(12);
    loop {
        let length = read_u32_le(chunk.wrapping_add(4) as usize as *const u8);
        if read_u32_be(chunk as usize as *const u8) == fourcc {
            return chunk;
        }
        chunk = chunk.wrapping_add(length).wrapping_add(8);
        if chunk.wrapping_add(length).wrapping_add(8) >= end {
            return 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::wave_find_chunk;

    #[test]
    fn packed_headers_double_stride_bound_and_wrapping_end() {
        unsafe {
            let Some(slab) = crate::testing::try_map_u32_slab(
                crate::testing::hints::WAVE_FIND_CHUNK, 4096,
            ) else {
                crate::testing::note_missing_u32_fixture("util/wave_find_chunk");
                return;
            };
            let owner = slab as *mut u32;
            let descriptor = slab.add(16) as *mut u32;
            let base = slab.add(64) as usize as u32;
            *owner = 0xdead_beef;
            *owner.add(1) = descriptor as usize as u32;
            *descriptor = base;
            // Odd length: second header is deliberately unaligned, no pad.
            let first = base + 12;
            let second = first + 11;
            let third = second + 8;
            for (address, tag, length) in [
                (first, *b"JUNK", 3u32),
                (second, *b"fmt ", 0u32),
                (third, *b"data", 1u32),
            ] {
                let p = address as usize as *mut u8;
                core::ptr::copy_nonoverlapping(tag.as_ptr(), p, 4);
                core::ptr::copy_nonoverlapping(length.to_le_bytes().as_ptr(), p.add(4), 4);
            }
            let fmt = u32::from_be_bytes(*b"fmt ");
            let data = u32::from_be_bytes(*b"data");
            // First probe is unconditional, even for zero declared length.
            *descriptor.add(1) = 0;
            assert_eq!(wave_find_chunk(owner, base, u32::from_be_bytes(*b"JUNK")), first);
            assert_eq!(wave_find_chunk(owner, base, fmt), 0);
            // The second header fits, but equality at the double-stride
            // boundary rejects it; one extra byte permits the probe.
            *descriptor.add(1) = second + 11 - base;
            assert_eq!(wave_find_chunk(owner, base, fmt), 0);
            *descriptor.add(1) += 1;
            assert_eq!(wave_find_chunk(owner, base, fmt), second);
            *descriptor.add(1) = 128;
            assert_eq!(wave_find_chunk(owner, base, data), third);
            assert_eq!(wave_find_chunk(owner, base, fmt.swap_bytes()), 0);
            // Buffer-end addition is 32-bit wrapping, not host usize math.
            *descriptor = u32::MAX - 15;
            *descriptor.add(1) = 32;
            assert_eq!(wave_find_chunk(owner, base, data), 0);
            assert_eq!(*owner, 0xdead_beef);
        }
    }
}
