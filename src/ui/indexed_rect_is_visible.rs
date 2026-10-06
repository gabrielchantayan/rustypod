//! Visible indexed rectangle predicate — FUN_0816b1dc @ 0x0816b1dc.
//!
//! True extent: 44 bytes [0x0816b1dc, 0x0816b208), ending in BX LR
//! before the next independently entered wrapper. Whole-image A32 decoding
//! verifies two incoming plain BLs (0x0816b10c, 0x0816b2dc), zero predicated
//! incoming BLs, and zero outgoing plain or predicated BLs.
//! Reject indices below the signed first-visible index at +0xe8. Otherwise
//! compute first + dimensions(+0xb8, +0xbc) with wrapping 32-bit MLA and
//! accept only indices strictly below that signed exclusive upper bound.
//! Deliberate deviations: none; opaque fields remain target-width words on hosts.

/// # Safety
/// `element` must be aligned and readable through the word at +0xe8.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_rect_is_visible(element: *const u32, index: i32) -> u32 {
    let first = element.add(0xe8 / 4).read() as i32;
    if first > index {
        return 0;
    }
    let span = (element.add(0xb8 / 4).read() as i32)
        .wrapping_mul(element.add(0xbc / 4).read() as i32);
    u32::from(first.wrapping_add(span) > index)
}

#[cfg(test)]
mod tests {
    use super::indexed_rect_is_visible;

    #[test]
    fn signed_boundaries_and_wrapping_mla() {
        let cases = [
            (-3i32, 2i32, 3i32), (7, 0, 8), (7, 8, 0),
            (-8, -2, 3), (-8, -2, -3),
            (i32::MAX - 1, 1, 3), (i32::MIN, 1, i32::MAX),
            (-2, i32::MAX, 2), (-2, i32::MIN, -1),
            (-10, 0x4000_0001, 4), (i32::MIN, i32::MIN, 2),
        ];
        let mut element = [0u32; 0xec / 4];
        for (first, dimension_a, dimension_b) in cases {
            element[0xe8 / 4] = first as u32;
            element[0xb8 / 4] = dimension_a as u32;
            element[0xbc / 4] = dimension_b as u32;
            // Wide arithmetic independently models the low word of ARM MLA.
            let upper = (i64::from(first) + i64::from(dimension_a)
                * i64::from(dimension_b)) as u32 as i32;
            for index in [i32::MIN, i32::MAX, -9, -3, -2, -1, 0, 7, 8,
                first.wrapping_sub(1), first, first.wrapping_add(1),
                upper.wrapping_sub(1), upper, upper.wrapping_add(1)] {
                let expected = u32::from(index >= first && index < upper);
                assert_eq!(unsafe { indexed_rect_is_visible(element.as_ptr(), index) },
                    expected, "first={first}, dimensions={dimension_a},{dimension_b}, index={index}");
            }
        }
    }
}
