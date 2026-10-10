//! Export fitted auto-hinter points to a FreeType outline.

use super::types::{FtOutline, FtVector};

/// Accessed auto-hinter point layout; 40 bytes on both ARM and hosts.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AfFittedPoint {
    pub flags: u16,
    pub before_position: [u8; 14],
    pub position: FtVector,
    pub trailing: [u32; 4],
}

/// Accessed hints prefix: point count at +28, point pointer at +32 on ARM.
#[repr(C)]
pub struct AfGlyphHintsPrefix {
    pub preceding: [u32; 7],
    pub point_count: u32,
    pub points: *const AfFittedPoint,
}

/// Original `FUN_080ad5c8`, load address 0x080ad5c8, true size 112 bytes
/// ([0x080ad5c8, 0x080ad638), followed by a fresh push prologue).
/// Raw aligned A32 decoding verifies zero outgoing plain/predicated BLs,
/// and two incoming plain BLs at 0x080a7eb4 and 0x080b5cfc, no predicated BLs.
/// Copy each 40-byte point's fitted x/y at +16/+20 to outline vectors.
/// Convert flags to tags: bit 0 => conic (0), otherwise bit 1 => cubic (2),
/// otherwise on-curve (1). Preserve outline metadata and source points.
/// The endpoint uses wrapping 32-bit count * 40 and an unsigned address
/// comparison, as in the firmware. Deliberate representation deviation:
/// repr(C) pointer fields widen on hosts; no algorithmic deviation or seams.
///
/// # Safety
/// Both prefixes must be readable. When the unsigned source address is below
/// the computed endpoint, the traversed points and matching destination vector
/// and tag ranges must be valid and aligned. No references are formed; accesses
/// retain firmware order, including when source and destination overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn af_glyph_hints_save(
    hints: *const AfGlyphHintsPrefix,
    outline: *mut FtOutline,
) {
    use core::ptr::{read_volatile, write_volatile};
    let mut point = read_volatile(core::ptr::addr_of!((*hints).points));
    let count = read_volatile(core::ptr::addr_of!((*hints).point_count));
    let mut vector = read_volatile(core::ptr::addr_of!((*outline).points));
    let end = (point as usize).wrapping_add(count.wrapping_mul(40) as usize);
    let mut tag = read_volatile(core::ptr::addr_of!((*outline).tags));
    while (point as usize) < end {
        let x = read_volatile(core::ptr::addr_of!((*point).position.x));
        write_volatile(core::ptr::addr_of_mut!((*vector).x), x);
        let y = read_volatile(core::ptr::addr_of!((*point).position.y));
        write_volatile(core::ptr::addr_of_mut!((*vector).y), y);
        let flags = read_volatile(core::ptr::addr_of!((*point).flags));
        write_volatile(tag, if flags & 1 != 0 { 0 } else if flags & 2 != 0 { 2 } else { 1 });
        point = point.wrapping_add(1);
        vector = vector.wrapping_add(1);
        tag = tag.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn all_flag_bits_coordinates_and_untouched_metadata() {
        let points: std::vec::Vec<_> = (0..=u16::MAX).map(|flags| AfFittedPoint {
            flags, before_position: [0xa5; 14],
            position: FtVector { x: i32::MIN.wrapping_add(flags as i32), y: i32::MAX.wrapping_sub(flags as i32) },
            trailing: [0xdeadbeef; 4],
        }).collect();
        let sentinel = FtVector { x: 17, y: -31 };
        let mut vectors = std::vec![sentinel; points.len() + 1];
        let mut tags = std::vec![0xa5; points.len() + 1];
        let mut contour = 23i16;
        let mut outline = FtOutline { n_contours: 7, n_points: -1,
            points: vectors.as_mut_ptr(), tags: tags.as_mut_ptr(),
            contours: &mut contour, flags: 0x12345678 };
        let hints = AfGlyphHintsPrefix { preceding: [0x76543210; 7],
            point_count: points.len() as u32, points: points.as_ptr() };
        unsafe { af_glyph_hints_save(&hints, &mut outline); }
        for (index, point) in points.iter().enumerate() {
            assert_eq!(vectors[index], point.position);
            assert_eq!(tags[index], [1, 0, 2, 0][index % 4]);
            assert_eq!(point.flags, index as u16);
            assert_eq!(point.before_position, [0xa5; 14]);
            assert_eq!(point.trailing, [0xdeadbeef; 4]);
        }
        assert_eq!(vectors[points.len()], sentinel);
        assert_eq!(tags[points.len()], 0xa5);
        assert_eq!((outline.n_contours, outline.n_points, outline.flags, contour), (7, -1, 0x12345678, 23));
        assert_eq!(outline.points, vectors.as_mut_ptr());
        assert_eq!(outline.tags, tags.as_mut_ptr());
        assert_eq!(outline.contours, &mut contour as *mut i16);
        assert_eq!(hints.preceding, [0x76543210; 7]);
    }

    #[test]
    fn zero_and_wrapped_zero_extent_do_not_access_buffers() {
        for count in [0, 0x20000000, 0x40000000, 0x80000000] {
            let hints = AfGlyphHintsPrefix { preceding: [0; 7], point_count: count,
                points: core::ptr::null() };
            let mut outline = FtOutline { n_contours: 0, n_points: 0,
                points: core::ptr::null_mut(), tags: core::ptr::null_mut(),
                contours: core::ptr::null_mut(), flags: 0 };
            unsafe { af_glyph_hints_save(&hints, &mut outline); }
        }
    }
}
