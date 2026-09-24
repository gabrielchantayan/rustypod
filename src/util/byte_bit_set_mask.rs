//! Big-endian byte bit-set mask lookup.
//!
//! `byte_bit_set_mask` — original: `FUN_0809c340` at load address
//! **0x0809c340** (**36 bytes**, 0x0809c340..0x0809c364; the next distinct
//! function begins `push {r4, lr}` at 0x0809c364). Raw `osos.dec` words are
//! `e5902000 e1520001 85900008 83a02080 87d001c1 82011007 80000132 93a00000
//! e12fff1e`. A full direct-call scan finds three unconditional `bl` callers
//! (0x0809c1cc, 0x0809c1e0, and 0x0809c1f4) and no predicated `bl` callers.
//!
//! The target record has an unsigned bit count at +0x00 and a target-width
//! byte-bitmap pointer at +0x08. In-range indices select bytes in ascending
//! order and bits most-significant first, returning the original bit mask
//! (`0x80` through `1`), not a normalized boolean. Deliberate deviations:
//! none.

/// Target layout consumed by [`byte_bit_set_mask`].
#[repr(C)]
pub struct ByteBitSet {
    /// +0x00: number of valid bits, compared unsigned.
    pub bit_count: u32,
    /// +0x04: uninspected by this routine.
    pub reserved: u32,
    /// +0x08: target-width address of the byte bitmap.
    pub bytes: u32,
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(ByteBitSet, bit_count)];
const _: [u8; 0x04] = [0; core::mem::offset_of!(ByteBitSet, reserved)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(ByteBitSet, bytes)];
const _: [u8; 0x0c] = [0; core::mem::size_of::<ByteBitSet>()];

/// Returns the big-endian bit mask for `bit_index`, or zero when it is outside
/// `set`'s unsigned bit count.
///
/// # Safety
///
/// `set` must be readable. When `bit_index < (*set).bit_count`, `bytes` must
/// be a valid target-width pointer to the byte selected by the original ARM
/// arithmetic; the retail routine performs neither NULL nor bounds checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn byte_bit_set_mask(set: *const ByteBitSet, bit_index: u32) -> u32 {
    if (*set).bit_count > bit_index {
        let byte_offset = (bit_index as i32 >> 3) as isize;
        let byte = ((*set).bytes as usize as *const u8).offset(byte_offset).read();
        u32::from(byte) & (0x80 >> (bit_index & 7))
    } else {
        0
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn returns_most_significant_first_masks_and_honors_bit_count() {
        let Some(slab) = try_map_u32_slab(hints::BYTE_BIT_SET_MASK, 0x1000) else {
            return;
        };
        let set = slab.cast::<ByteBitSet>();
        let bitmap = unsafe { slab.add(0x100).cast::<u8>() };

        unsafe {
            bitmap.write(0b1000_0001);
            bitmap.add(1).write(0b0100_0000);
            set.write(ByteBitSet {
                bit_count: 10,
                reserved: 0,
                bytes: bitmap as usize as u32,
            });

            assert_eq!(byte_bit_set_mask(set, 0), 0x80);
            assert_eq!(byte_bit_set_mask(set, 1), 0);
            assert_eq!(byte_bit_set_mask(set, 7), 1);
            assert_eq!(byte_bit_set_mask(set, 8), 0);
            assert_eq!(byte_bit_set_mask(set, 9), 0x40);
            assert_eq!(byte_bit_set_mask(set, 10), 0);
            assert_eq!(byte_bit_set_mask(set, u32::MAX), 0);
        }
    }
}
