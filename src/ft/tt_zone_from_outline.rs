//! TrueType execution-zone setup from a glyph-load outline.

/// Original `FUN_08093234` at load address `0x08093234`, 76 bytes
/// (`0x08093234..0x08093280`, next entry starts with a register push).
/// Raw ARM verifies zero outgoing plain/predicated BLs and two incoming
/// plain BLs (0x080cc218, 0x080d8f3c), no incoming predicated BLs.
/// Set zone point/contour counts to outline counts minus their respective
/// offsets. Set original/current point cursors from glyph-load extra_points
/// and outline.points, tags from outline.tags, and contour endpoints from
/// outline.contours, advancing by 8/8/1/2 bytes per item respectively.
/// Preserve zone words +0/+4 and all other fields. Counts and addresses wrap.
/// Deliberate deviations: none; target addresses remain u32 even on hosts,
/// and raw-pointer accesses retain the firmware's order, including overlap.
///
/// # Safety
/// `zone` must provide 28 writable bytes and `glyph_load` 24 readable bytes,
/// both word-aligned. Overlap is allowed; stored addresses are not dereferenced.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tt_zone_from_outline(
    zone: *mut u8, glyph_load: *const u8, point_offset: u32, contour_offset: u32,
) {
    let points = glyph_load.add(2).cast::<u16>().read();
    zone.add(8).cast::<u16>().write(points.wrapping_sub(point_offset as u16));
    let contours = glyph_load.cast::<u16>().read();
    zone.add(10).cast::<u16>().write(contours.wrapping_sub(contour_offset as u16));
    let original = glyph_load.add(20).cast::<u32>().read();
    zone.add(12).cast::<u32>().write(original.wrapping_add(point_offset.wrapping_mul(8)));
    let current = glyph_load.add(4).cast::<u32>().read();
    zone.add(16).cast::<u32>().write(current.wrapping_add(point_offset.wrapping_mul(8)));
    let tags = glyph_load.add(8).cast::<u32>().read();
    zone.add(20).cast::<u32>().write(tags.wrapping_add(point_offset));
    let endpoints = glyph_load.add(12).cast::<u32>().read();
    zone.add(24).cast::<u32>().write(endpoints.wrapping_add(contour_offset.wrapping_mul(2)));
}

#[cfg(test)]
mod tests {
    use super::tt_zone_from_outline;

    // Byte-level ARM reference, intentionally reading after each preceding store.
    fn reference(bytes: &mut [u8], dst: usize, src: usize, points: u32, contours: u32) {
        for (source, destination, width, offset, scale, subtract) in [
            (2, 8, 2, points, 1, true), (0, 10, 2, contours, 1, true),
            (20, 12, 4, points, 8, false), (4, 16, 4, points, 8, false),
            (8, 20, 4, points, 1, false), (12, 24, 4, contours, 2, false),
        ] {
            let mut value = 0u64;
            for i in 0..width { value |= (bytes[src + source + i] as u64) << (i * 8); }
            let delta = (offset as u64) * scale;
            value = if subtract { value.wrapping_sub(delta) } else { value.wrapping_add(delta) };
            for i in 0..width { bytes[dst + destination + i] = (value >> (i * 8)) as u8; }
        }
    }

    #[test]
    fn counts_addresses_wrap_and_untouched_fields_survive() {
        for (points, contours) in [(0, 0), (3, 2), (0xffff, 0x10000),
                                  (0x20000001, 0x80000001), (u32::MAX, u32::MAX)] {
            let mut words = [0xa5a5a5a5u32; 20];
            words[0] = 0x00020001; // two points, one contour
            words[1] = 0xfffffff8;
            words[2] = 0xffffffff;
            words[3] = 0xfffffffe;
            words[5] = 0xfffffff0;
            let bytes = unsafe { core::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), 80) };
            let mut expected = bytes.to_vec();
            reference(&mut expected, 32, 0, points, contours);
            unsafe { tt_zone_from_outline(bytes.as_mut_ptr().add(32), bytes.as_ptr(), points, contours); }
            assert_eq!(bytes, expected);
        }
    }

    #[test]
    fn overlapping_records_observe_prior_stores() {
        for (dst, src) in [(0, 0), (0, 4), (4, 0), (0, 12), (12, 0)] {
            let mut words = core::array::from_fn::<_, 20, _>(|i| 0x10203040u32 + i as u32);
            let bytes = unsafe { core::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), 80) };
            let mut expected = bytes.to_vec();
            reference(&mut expected, dst, src, 0xfffffffd, 0x80000002);
            unsafe { tt_zone_from_outline(bytes.as_mut_ptr().add(dst), bytes.as_ptr().add(src),
                                         0xfffffffd, 0x80000002); }
            assert_eq!(bytes, expected);
        }
    }
}
