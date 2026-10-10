//! Packed-surface bounds clipping — FUN_08075e90 @ 0x08075e90.
//! True extent: 220 bytes, [0x08075e90, 0x08075f6c), next function's push.
//! Verified BL counts: two incoming plain (0x080748f0, 0x080f2df0), zero
//! incoming predicated, zero outgoing plain or predicated. Intersect the
//! state's QuickDraw bounds with an optional local clip, translate by the
//! surface's top/left using wrapping additions, then clamp to surface bounds.
//! Return 1 only when both signed spans are positive; do not clear empty bounds.
//! Deviations: none in algorithm or ABI. Pointer fields remain 32-bit on hosts.

/// # Safety
/// `state` is writable for eight aligned words; word 7 points to nine readable
/// aligned surface words. Non-null `clip` addresses four signed words in
/// top/left/bottom/right order. Overlapping clip/state storage is supported.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn packed_surface_bounds_clip(state: *mut u32, clip: *const i32) -> u32 {
    let surface = state.add(7).read() as usize as *const i32;
    let top = surface.add(5).read();
    let left = surface.add(6).read();
    let bottom = surface.add(7).read();
    let right = surface.add(8).read();
    let bounds = state.add(3).cast::<i32>();
    if !clip.is_null() {
        // Preserve the original horizontal-first access order for aliases.
        if bounds.add(1).read() < clip.add(1).read() {
            bounds.add(1).write(clip.add(1).read());
        }
        if bounds.add(3).read() > clip.add(3).read() {
            bounds.add(3).write(clip.add(3).read());
        }
        if bounds.read() < clip.read() {
            bounds.write(clip.read());
        }
        if bounds.add(2).read() > clip.add(2).read() {
            bounds.add(2).write(clip.add(2).read());
        }
    }
    let translated_left = bounds.add(1).read().wrapping_add(left);
    bounds.add(1).write(translated_left);
    let translated_right = bounds.add(3).read().wrapping_add(left);
    bounds.add(3).write(translated_right);
    let translated_top = bounds.read().wrapping_add(top);
    bounds.write(translated_top);
    let translated_bottom = bounds.add(2).read().wrapping_add(top);
    bounds.add(2).write(translated_bottom);
    if translated_left < left { bounds.add(1).write(left); }
    if translated_right > right { bounds.add(3).write(right); }
    if translated_top < top { bounds.write(top); }
    if translated_bottom > bottom { bounds.add(2).write(bottom); }
    (bounds.add(3).read() > bounds.add(1).read()
        && bounds.add(2).read() > bounds.read()) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_edges_wrapping_empty_and_optional_clip() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::PACKED_SURFACE_BOUNDS_CLIP, 4096) else { return; };
        let surface = slab.cast::<i32>();
        let origins = [[10, 20, 40, 60], [-20, -10, 30, 40],
            [i32::MAX - 2, i32::MIN + 2, i32::MAX, i32::MIN + 12]];
        let edges = [i32::MIN, -31, -1, 0, 1, 15, 50, i32::MAX];
        let clips = [None, Some([-5, 2, 20, 30]), Some([5, 8, 5, 8]),
            Some([30, 40, -20, -10])];
        unsafe {
            for origin in origins {
                for i in 0..4 { surface.add(5 + i).write(origin[i]); }
                for top in edges { for left in edges { for bottom in edges { for right in edges {
                    for clip in clips {
                        let input = [top, left, bottom, right];
                        let mut expected = input;
                        if let Some(c) = clip {
                            for i in 0..4 {
                                expected[i] = if i < 2 { expected[i].max(c[i]) }
                                    else { expected[i].min(c[i]) };
                            }
                        }
                        for i in 0..4 { expected[i] = expected[i].wrapping_add(origin[i % 2]); }
                        for i in 0..4 {
                            expected[i] = if i < 2 { expected[i].max(origin[i]) }
                                else { expected[i].min(origin[i]) };
                        }
                        let mut state = [0xabcddcba; 8];
                        for i in 0..4 { state[3 + i] = input[i] as u32; }
                        state[7] = surface as usize as u32;
                        let result = packed_surface_bounds_clip(state.as_mut_ptr(),
                            clip.as_ref().map_or(core::ptr::null(), |c| c.as_ptr()));
                        assert_eq!(result, (expected[3] > expected[1] && expected[2] > expected[0]) as u32);
                        assert_eq!(&state[3..7], &expected.map(|v| v as u32));
                        assert_eq!(&state[..3], &[0xabcddcba; 3]);
                        assert_eq!(state[7], surface as usize as u32);
                    }
                } } } }
            }
            // Shifted overlap: the left store changes the later bottom clip.
            for i in 0..4 { surface.add(5 + i).write([0, 0, 100, 100][i]); }
            let mut state = [0, 0, 10, 0, 5, 20, 30, surface as usize as u32];
            assert_eq!(packed_surface_bounds_clip(state.as_mut_ptr(), state.as_ptr().add(2).cast()), 0);
            assert_eq!(&state[3..7], &[10, 5, 5, 20]);
            extern "C" { fn munmap(addr: *mut u8, len: usize) -> i32; }
            assert_eq!(munmap(slab, 4096), 0);
        }
    }
}
