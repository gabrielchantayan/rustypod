//! PFR glyph contour finalization.

/// FreeType `pfr_glyph_close_contour` — `FUN_080cd1b0` @ 0x080cd1b0.
/// True extent [0x080cd1b0, 0x080cd244): 148 bytes. Raw ARM decoding
/// verifies two plain incoming BLs (0x080c0f0c, 0x080c0f34), zero
/// predicated incoming BLs, and zero outgoing BLs of either kind.
///
/// If a contour is open, compare its starting point (the preceding contour's
/// endpoint, or zero) with its last point. Remove an identical closing point
/// only when there are at least two points. Append the remaining endpoint if
/// the contour is nonempty, then clear the open flag. Signed halfword counts
/// and endpoint indices match stock, including truncating count increments.
/// No behavioral deviations; target-width pointer words preserve the retail
/// layout on hosts rather than widening embedded pointers.
///
/// # Safety
/// `glyph` must be a writable retail-layout PFR glyph record (at least 41
/// bytes). Its +0x24 word points to a glyph loader with current outline at
/// +0x34. An open contour requires valid aligned point and endpoint arrays,
/// valid signed counts/indices, and capacity for one additional endpoint.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pfr_glyph_close_contour(glyph: *mut u8) {
    let loader = *glyph.add(0x24).cast::<u32>() as usize as *mut u8;
    if *glyph.add(0x28) == 0 {
        return;
    }
    let outline = loader.add(0x34);
    let contour_count = *outline.cast::<i16>() as i32;
    let point_count = *outline.add(2).cast::<i16>() as i32;
    let endpoints = *outline.add(12).cast::<u32>() as usize as *mut i16;
    let first = if contour_count > 0 {
        *endpoints.offset((contour_count - 1) as isize) as i32
    } else {
        0
    };
    let mut last = point_count - 1;
    if last > first {
        let points = *outline.add(4).cast::<u32>() as usize as *const i32;
        let start = points.offset(first as isize * 2);
        let end = points.offset(last as isize * 2);
        if *start == *end && *start.add(1) == *end.add(1) {
            *outline.add(2).cast::<i16>() = last as i16;
            last -= 1;
        }
    }
    if last >= first {
        *outline.cast::<i16>() = (contour_count + 1) as i16;
        *endpoints.offset(contour_count as isize) = last as i16;
    }
    *glyph.add(0x28) = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closes_empty_singleton_distinct_and_duplicate_contours() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::PFR_GLYPH_CLOSE_CONTOUR, 4096,
        ) else {
            crate::testing::note_missing_u32_fixture("pfr_glyph_close_contour");
            return;
        };
        unsafe {
            let glyph = slab;
            let loader = slab.add(64);
            let outline = loader.add(0x34);
            let points = slab.add(256).cast::<i32>();
            let endpoints = slab.add(512).cast::<i16>();
            *glyph.add(0x24).cast::<u32>() = loader as usize as u32;
            *outline.add(4).cast::<u32>() = points as usize as u32;
            *outline.add(12).cast::<u32>() = endpoints as usize as u32;
            // Previous endpoint is deliberately reused as the start: not +1.
            for (count, previous, input, expected) in [
                (0i16, 0i16, &[][..], &[][..]),
                (0, 0, &[[7, -9]][..], &[[7, -9]][..]),
                (0, 0, &[[7, -9], [7, 10]][..], &[[7, -9], [7, 10]][..]),
                (0, 0, &[[7, -9], [8, -9]][..], &[[7, -9], [8, -9]][..]),
                (0, 0, &[[7, -9], [7, -9]][..], &[[7, -9]][..]),
                (1, 1, &[[0, 0], [7, -9], [4, 5], [7, -9]][..],
                    &[[0, 0], [7, -9], [4, 5]][..]),
                (1, 2, &[[0, 0], [1, 1]][..], &[[0, 0], [1, 1]][..]),
                (0, 0, &[[i32::MIN, i32::MAX], [i32::MIN, i32::MAX]][..],
                    &[[i32::MIN, i32::MAX]][..]),
            ] {
                *outline.cast::<i16>() = count;
                *outline.add(2).cast::<i16>() = input.len() as i16;
                *endpoints = previous;
                *endpoints.add(count as usize) = -123;
                for (i, point) in input.iter().enumerate() {
                    *points.add(i * 2) = point[0];
                    *points.add(i * 2 + 1) = point[1];
                }
                *glyph.add(0x28) = 3;
                pfr_glyph_close_contour(glyph);
                let start = if count > 0 { previous as usize } else { 0 };
                let appended = expected.len() > start;
                assert_eq!(*outline.cast::<i16>(), count + appended as i16);
                assert_eq!(*outline.add(2).cast::<i16>(), expected.len() as i16);
                assert_eq!(*endpoints.add(count as usize),
                    if appended { expected.len() as i16 - 1 } else { -123 });
                assert_eq!(*glyph.add(0x28), 0);
                for (i, point) in input.iter().enumerate() {
                    assert_eq!([*points.add(i * 2), *points.add(i * 2 + 1)], *point);
                }
                // Closing twice must not append a second endpoint.
                pfr_glyph_close_contour(glyph);
                assert_eq!(*outline.cast::<i16>(), count + appended as i16);
            }
            // A closed contour must not dereference its loader.
            *glyph.add(0x24).cast::<u32>() = 0;
            pfr_glyph_close_contour(glyph);
        }
    }
}
