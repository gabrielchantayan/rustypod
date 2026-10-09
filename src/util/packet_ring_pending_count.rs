//! Pending packet count in a four-slot ring — retailOS `FUN_080f1554`.
//!
//! Load address: `0x080f1554`; true size: 36 bytes, ending at `0x080f1578`,
//! where the next function starts with `mov r1,r0,lsl #8`. Raw A32 decoding
//! verifies two inbound plain BLs (0x080cb7fc, 0x080cc37c), zero predicated
//! BLs, and no outbound calls. Loads write/read indices at +0x844/+0x840,
//! wraps `write - read + 4` to 32 bits, then returns its signed remainder
//! modulo four. The consumer drains until zero; the producer treats three
//! as full. No deliberate behavioral deviations or new callee seams.

/// # Safety
/// `ring` must point to an aligned record readable through word 0x211.
/// Fields remain four-byte words on hosts as well as the target.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn packet_ring_pending_count(ring: *const u32) -> i32 {
    let write_index = ring.add(0x211).read_volatile();
    let read_index = ring.add(0x210).read_volatile();
    (write_index.wrapping_sub(read_index).wrapping_add(4) as i32) % 4
}

#[cfg(test)]
mod tests {
    use super::packet_ring_pending_count;

    fn count(read: u32, write: u32) -> i32 {
        let mut ring = [0xa5a5_a5a5u32; 0x213];
        ring[0x210] = read;
        ring[0x211] = write;
        let before = ring;
        let result = unsafe { packet_ring_pending_count(ring.as_ptr()) };
        assert_eq!(ring, before);
        result
    }

    #[test]
    fn all_valid_ring_positions_include_empty_full_and_wrap() {
        for read in 0..4 {
            for write in 0..4 {
                assert_eq!(count(read, write), ((write + 4 - read) % 4) as i32);
            }
        }
    }

    #[test]
    fn negative_intermediate_uses_signed_remainder_not_mask() {
        assert_eq!(count(5, 0), -1);
        assert_eq!(count(6, 0), -2);
        assert_eq!(count(7, 0), -3);
        assert_eq!(count(8, 0), 0);
    }

    #[test]
    fn wraps_arithmetic_before_signed_remainder() {
        let values = [0, 1, 3, 4, 7, 0x7fff_fffc, 0x7fff_ffff,
                      0x8000_0000, 0x8000_0003, 0xffff_fffc, u32::MAX];
        for read in values {
            for write in values {
                let bits = (write as i64 - read as i64 + 4).rem_euclid(1i64 << 32);
                let signed = if bits >= 1i64 << 31 { bits - (1i64 << 32) } else { bits };
                assert_eq!(count(read, write), (signed % 4) as i32);
            }
        }
    }
}
