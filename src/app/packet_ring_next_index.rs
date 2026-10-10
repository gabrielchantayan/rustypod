//! Advance the four-slot packet ring's producer or consumer index.
//!
//! FUN_0807f310 @ 0x0807f310: true extent [0x0807f310,0x0807f320),
//! 16 bytes; the next function starts with PUSH. Raw A32 verifies two
//! incoming plain BLs at 0x080cb7f0 and 0x080cc4c4, zero predicated
//! incoming BLs, and zero outgoing plain or predicated BLs.
//!
//! ADD r0,r0,#1; CMP r0,#4; MOVEQ r0,#0; BX lr. Increment modulo
//! 2^32 and reset only the result four to zero. Callers advance the
//! consumer word at owner+0x840 and producer word at owner+0x844 for
//! packet records of stride 0x206. Deliberate deviations: none; u32
//! preserves all register bit patterns, including out-of-range inputs.

/// Advance an index without normalizing values outside the four-slot ring.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn packet_ring_next_index(index: u32) -> u32 {
    let next = index.wrapping_add(1);
    if next == 4 { 0 } else { next }
}

#[cfg(test)]
mod tests {
    use super::packet_ring_next_index;

    #[test]
    fn ring_cycle() {
        let mut index = 0;
        for expected in [1, 2, 3, 0, 1] {
            index = packet_ring_next_index(index);
            assert_eq!(index, expected);
        }
    }

    #[test]
    fn out_of_range_values_are_not_masked_or_clamped() {
        for (input, expected) in [
            (4, 5), (7, 8), (0x7fff_ffff, 0x8000_0000),
            (0xffff_fffe, 0xffff_ffff), (0xffff_ffff, 0),
        ] {
            assert_eq!(packet_ring_next_index(input), expected);
        }
    }
}
