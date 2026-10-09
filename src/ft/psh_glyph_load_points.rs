//! PostScript hinter per-dimension point initialization.

use crate::ft::types::FtOutline;

/// Prefix of the hinter glyph workspace, through the source outline.
/// Pointer fields widen on hosts; target offsets are 0, 4, 8, 12, 16, 20.
#[repr(C)]
pub struct PshGlyphPointSource {
    pub point_count: u32,
    pub contour_count: u32,
    pub points: *mut [u32; 12],
    pub contours: *mut u8,
    pub memory: *mut crate::ft::memory::FtMemory,
    pub outline: *const FtOutline,
}

/// Loads hinter point coordinates — `FUN_080c14c4` @ 0x080c14c4.
/// True extent: [0x080c14c4, 0x080c151c), 88 bytes; 0 plain and
/// 0 predicated outbound BLs, 2 plain and 0 predicated inbound BLs.
/// Clears each 48-byte point's flags at +0x10 and hint state at +0x20,
/// then stores the outline's x/y at +0x24/+0x28 for dimension zero,
/// or y/x for every nonzero dimension. Other point words are untouched.
/// Deliberate deviation: typed workspace/outline pointers widen on hosts;
/// the ARM layout and behavior are unchanged. No callee seams are needed.
///
/// # Safety
/// `glyph` and its outline must be readable even for zero points. For a
/// nonzero count, points must contain that many writable 12-word records
/// and outline points must contain that many readable vectors, without
/// overlap with the destination records or workspace.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn psh_glyph_load_points(glyph: *const PshGlyphPointSource, dimension: u32) {
    let mut source = (*(*glyph).outline).points;
    let mut destination = (*glyph).points;
    let mut remaining = (*glyph).point_count;
    while remaining != 0 {
        (*destination)[4] = 0;
        (*destination)[8] = 0;
        if dimension == 0 {
            (*destination)[9] = (*source).x as u32;
            (*destination)[10] = (*source).y as u32;
        } else {
            (*destination)[9] = (*source).y as u32;
            (*destination)[10] = (*source).x as u32;
        }
        source = source.add(1);
        destination = destination.add(1);
        remaining -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ft::types::FtVector;
    use core::ptr::null_mut;

    #[test]
    fn dimensions_reload_coordinates_and_preserve_unrelated_words() {
        let mut vectors = [
            FtVector { x: i32::MIN, y: i32::MAX },
            FtVector { x: -37, y: 0 },
            FtVector { x: 0x12345678, y: -91 },
        ];
        let outline = FtOutline {
            n_contours: 0, n_points: 0, points: vectors.as_mut_ptr(),
            tags: null_mut(), contours: null_mut(), flags: 0,
        };
        let mut records = [[0u32; 12]; 4];
        let glyph = PshGlyphPointSource {
            point_count: 3, contour_count: 0, points: records.as_mut_ptr(),
            contours: null_mut(), memory: null_mut(), outline: &outline,
        };
        for dimension in [0, 1, 2, u32::MAX, 0] {
            for (i, record) in records.iter_mut().enumerate() {
                for (j, word) in record.iter_mut().enumerate() {
                    *word = 0xa5000000 | ((i as u32) << 8) | j as u32;
                }
            }
            let mut expected = records;
            for (record, vector) in expected.iter_mut().zip(vectors.iter()) {
                record[4] = 0;
                record[8] = 0;
                let coordinates = if dimension == 0 { [vector.x, vector.y] } else { [vector.y, vector.x] };
                record[9] = coordinates[0] as u32;
                record[10] = coordinates[1] as u32;
            }
            unsafe { psh_glyph_load_points(&glyph, dimension); }
            assert_eq!(records, expected);
        }
    }

    #[test]
    fn zero_count_does_not_access_point_buffers() {
        let outline = FtOutline {
            n_contours: 0, n_points: 19, points: null_mut(),
            tags: null_mut(), contours: null_mut(), flags: 0,
        };
        let glyph = PshGlyphPointSource {
            point_count: 0, contour_count: 0, points: null_mut(),
            contours: null_mut(), memory: null_mut(), outline: &outline,
        };
        unsafe { psh_glyph_load_points(&glyph, 0); psh_glyph_load_points(&glyph, 9); }
        assert_eq!(glyph.point_count, 0);
        assert_eq!(outline.n_points, 19);
        assert_eq!(glyph.outline, &outline as *const _);
        assert_eq!(glyph.contours, null_mut());
    }
}
