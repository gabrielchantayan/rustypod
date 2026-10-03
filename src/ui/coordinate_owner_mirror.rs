//! Coordinate-owner bitmap mirror — `FUN_0826435c` at `0x0826435c`.
//! True extent: 88 bytes, ending at the distinct entry `0x082643b4`.
//! Raw A32: one outbound plain BL to `0x080f2b4c`, no predicated BLs;
//! two inbound plain BLs at `0x08198df8` and `0x08198e14`, no predicated BLs.
//! Adds owner row/column offsets to all rectangle endpoints with wrapping
//! arithmetic, mirrors the embedded bitmap descriptor at backing + 4 with
//! the unchanged axis selector, and returns the first two translated words.
//! Deliberate deviations: C-layout pointer fields expand on hosts; target
//! offsets remain +0x1c (backing), +0x2c (column), +0x30 (row). The unported
//! bitmap mirror remains a verified-address call; hosts must install a seam.

#[repr(C)]
pub struct CoordinateMirrorOwner {
    pub prefix: [u32; 7],
    pub backing: *mut u32,
    pub reserved: [u32; 3],
    pub column_offset: i32,
    pub row_offset: i32,
}

pub type BitmapMirror = unsafe extern "C" fn(*mut u32, *const i32, u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bitmap_mirror(_: *mut u32, _: *const i32, _: u32) {
    panic!("install COORDINATE_BITMAP_MIRROR before calling the host port");
}

#[cfg(not(target_os = "none"))]
pub static mut COORDINATE_BITMAP_MIRROR: BitmapMirror = missing_bitmap_mirror;

fn translate(rectangle: [i32; 4], row: i32, column: i32) -> [i32; 4] {
    [rectangle[0].wrapping_add(row), rectangle[1].wrapping_add(column),
     rectangle[2].wrapping_add(row), rectangle[3].wrapping_add(column)]
}

/// The owner, its backing bitmap, and four aligned rectangle words must be
/// valid for the retail mirror's accesses. Rectangle coordinates are half-open.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn coordinate_owner_mirror(
    owner: *const CoordinateMirrorOwner, rectangle: *const i32, axis: u32,
) -> u64 {
    let translated = translate(
        [rectangle.read(), rectangle.add(1).read(), rectangle.add(2).read(), rectangle.add(3).read()],
        (*owner).row_offset, (*owner).column_offset,
    );
    let bitmap = (*owner).backing.add(1);
    #[cfg(target_os = "none")]
    let mirror: BitmapMirror = core::mem::transmute(0x080f_2b4cusize);
    #[cfg(not(target_os = "none"))]
    let mirror = COORDINATE_BITMAP_MIRROR;
    mirror(bitmap, translated.as_ptr(), axis);
    (translated[0] as u32 as u64) | ((translated[1] as u32 as u64) << 32)
}

#[cfg(test)]
mod tests {
    use super::translate;

    #[test]
    fn translation_preserves_empty_and_reversed_rectangles() {
        assert_eq!(translate([7, -4, 7, -4], -10, 6), [-3, 2, -3, 2]);
        assert_eq!(translate([8, 9, -2, -3], 4, -5), [12, 4, 2, -8]);
    }

    #[test]
    fn translation_wraps_each_endpoint_independently() {
        assert_eq!(translate([i32::MAX, i32::MIN, -1, 0], 1, -1),
                   [i32::MIN, i32::MAX, 0, -1]);
        assert_eq!(translate([0, 0, i32::MIN, i32::MAX], i32::MIN, i32::MAX),
                   [i32::MIN, i32::MAX, 0, -2]);
    }
}
