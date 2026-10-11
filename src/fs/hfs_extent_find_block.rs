//! HFS extent-record logical-block lookup.
//!
//! Original: `FUN_080660b8` at `0x080660b8`, 168 bytes, true extent
//! [0x080660b8, 0x08066160); the next independent function starts with PUSH.
//! Whole-image raw A32 decoding finds two incoming plain BLs at 0x08065ffc
//! and 0x080660b0, no predicated incoming BLs, and no outgoing BLs.
//!
//! Volume signature +2 equal to 0x482b selects eight descriptors, otherwise
//! three. Each descriptor is two native-endian u32 words: start block and
//! block count. Accumulate nonzero counts from the supplied starting logical
//! block until the wrapping exclusive end exceeds the requested block. Return
//! zero with the containing descriptor index and exclusive end, or 0x10 with
//! the last nonempty index (zero for empty records). A zero count sets the
//! exhausted flag; filling every descriptor leaves it clear for overflow lookup.
//!
//! Deliberate deviations: omit the dead comparison of the always-zero r3.
//! Volatile aligned accesses preserve stock output initialization and aliasing
//! order; descriptor word indices remain four bytes apart on host and target.

/// Searches an HFS/HFS+ extent record for a logical allocation block.
///
/// # Safety
/// `volume` must permit an aligned halfword read at +2. `extents` must permit
/// aligned word reads for three or eight descriptor pairs according to that
/// signature (only visited counts are read). Output pointers must be writable
/// and aligned for their types. Aliases must satisfy all those access bounds.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.hfs_extent_find_block")]
#[inline(never)]
pub unsafe extern "C" fn hfs_extent_find_block(
    volume: *const u16, logical_block: u32, extents: *const u32,
    first_logical_block: u32, out_index: *mut u32, out_end: *mut u32,
    out_exhausted: *mut u8,
) -> u32 {
    out_end.write_volatile(first_logical_block);
    out_exhausted.write_volatile(0);
    let limit = if volume.add(1).read_volatile() == 0x482b { 8 } else { 3 };
    let mut index = 0;
    while index < limit {
        let count = extents.add(index * 2 + 1).read_volatile();
        if count == 0 { break; }
        let end = out_end.read_volatile().wrapping_add(count);
        out_end.write_volatile(end);
        if end > logical_block {
            out_index.write_volatile(index as u32);
            return 0;
        }
        index += 1;
    }
    out_index.write_volatile(if index == 0 { 0 } else { index as u32 - 1 });
    if index < limit { out_exhausted.write_volatile(1); }
    0x10
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(signature: u16, counts: &[u32], block: u32, first: u32) -> (u32, u32, u32, u8) {
        let volume = [0, signature];
        let mut record = [0xdead_beef; 16];
        for (i, count) in counts.iter().enumerate() { record[i * 2 + 1] = *count; }
        let (mut index, mut end, mut exhausted) = (99, 99, 99);
        let status = unsafe {
            hfs_extent_find_block(volume.as_ptr(), block, record.as_ptr(), first,
                &mut index, &mut end, &mut exhausted)
        };
        (status, index, end, exhausted)
    }

    #[test]
    fn boundaries_empty_termination_and_full_records() {
        assert_eq!(run(0x482b, &[0], 0, 7), (0x10, 0, 7, 1));
        assert_eq!(run(0x4244, &[2, 3, 4], 1, 0), (0, 0, 2, 0));
        assert_eq!(run(0x4244, &[2, 3, 4], 2, 0), (0, 1, 5, 0));
        assert_eq!(run(0x4244, &[2, 3, 4], 9, 0), (0x10, 2, 9, 0));
        assert_eq!(run(0x482b, &[2, 0, 100], 2, 0), (0x10, 0, 2, 1));
        assert_eq!(run(0x482b, &[1; 8], 7, 0), (0, 7, 8, 0));
        assert_eq!(run(0x482b, &[1; 8], 8, 0), (0x10, 7, 8, 0));
        assert_eq!(run(0x482b, &[2, 3, 0], 0, u32::MAX - 1), (0, 1, 3, 0));
        assert_eq!(run(0x482b, &[2, 3, 0], u32::MAX, u32::MAX - 1), (0x10, 1, 3, 1));
    }

    #[test]
    fn all_small_record_shapes_match_reference() {
        for signature in [0x482b, 0x4244, 0, 0x4858] {
            let limit = if signature == 0x482b { 8 } else { 3 };
            for zero_at in 0..=limit {
                let mut counts = [2u32; 8];
                if zero_at < limit { counts[zero_at] = 0; }
                for first in [0u32, 5, u32::MAX - 3] {
                    for block in (0..22).chain([u32::MAX]) {
                        let mut end = first;
                        let mut expected = (0x10, zero_at.saturating_sub(1) as u32,
                            first.wrapping_add(2 * zero_at as u32), (zero_at < limit) as u8);
                        for i in 0..zero_at {
                            end = ((end as u64 + 2) & 0xffff_ffff) as u32;
                            if block < end {
                                expected = (0, i as u32, end, 0);
                                break;
                            }
                        }
                        assert_eq!(run(signature, &counts, block, first), expected,
                            "signature {signature:x}, zero {zero_at}, first {first}, block {block}");
                    }
                }
            }
        }
    }
}
