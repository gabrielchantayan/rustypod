//! Packed-surface span preparation: `FUN_080f05e0` at **0x080f05e0**.
//! True extent: 156 bytes, ending at the next push at 0x080f067c.
//! Raw ARM scan: two incoming plain BL sites (0x08074904, 0x080f2df8),
//! no predicated BL sites; one outgoing plain BL to 0x08079fc8.
//!
//! Transform the drawing word via the existing selector dispatcher, then
//! scale the horizontal bounds to bits. Compute the first framebuffer word,
//! row stride, inclusive word-distance, and MSB-first start/end masks. An
//! aligned exclusive end decrements the distance and uses an all-ones mask.
//!
//! Deliberate deviations: retain the identified selector dispatcher in retailOS
//! rather than port its unresolved tail transfers. Host callers must provide
//! that dependency via the internal test seam. All object fields remain u32
//! words on hosts, and register shifts use ARM's low-byte/zero-for-32 semantics.

type SelectorDispatch = unsafe extern "C" fn(u32, *mut u32, *const u8, u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn selector_dispatch(count: u32, word: *mut u32, selector: *const u8, swap: u32) {
    core::mem::transmute::<usize, SelectorDispatch>(0x0807_9fc8)(count, word, selector, swap);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn selector_dispatch(_: u32, _: *mut u32, _: *const u8, _: u32) {
    panic!("packed surface span preparation requires retailOS selector dispatcher 0x08079fc8")
}

#[inline]
fn arm_lsl(value: u32, shift: u32) -> u32 {
    value.checked_shl(shift & 0xff).unwrap_or(0)
}

/// # Safety
/// `state` must be aligned and writable for 15 words; word 7 must point to
/// four readable surface words. Its word/selector must be valid for retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn packed_surface_span_prepare(state: *mut u32) {
    prepare_with(state, selector_dispatch);
}

#[inline]
pub(super) unsafe fn prepare_with(state: *mut u32, dispatch: SelectorDispatch) {
    let surface = state.add(7).read() as usize as *const u32;
    dispatch(surface.add(2).read(), state.add(1), state.add(2).cast(), 1);
    // Reload after dispatch, just as the firmware does.
    let surface = state.add(7).read() as usize as *const u32;
    let shift = surface.add(3).read();
    let start = arm_lsl(state.add(4).read(), shift);
    let end = arm_lsl(state.add(6).read(), shift);
    state.add(11).write(start);
    state.add(12).write(end);
    let stride = surface.add(1).read();
    state.add(9).write(stride);
    let address = state.add(3).read().wrapping_mul(stride)
        .wrapping_add(surface.read()).wrapping_add((start >> 5) << 2);
    state.add(8).write(address);
    let mut distance = (end >> 5).wrapping_sub(start >> 5);
    let end_bits = end & 31;
    let end_mask = if end_bits == 0 {
        distance = distance.wrapping_sub(1);
        u32::MAX
    } else {
        u32::MAX << (32 - end_bits)
    };
    state.add(10).write(distance);
    state.add(13).write(u32::MAX >> (start & 31));
    state.add(14).write(end_mask);
}

#[cfg(test)]
mod tests {
    use super::*;

    // A supplied dependency changes bounds and the surface link, exercising
    // the firmware's required post-dispatch reload without modeling dispatch.
    unsafe extern "C" fn replace_surface(_: u32, word: *mut u32, _: *const u8, _: u32) {
        let state = word.sub(1);
        state.add(7).write(state.read());
        state.add(4).write(3);
        state.add(6).write(17);
    }
    unsafe extern "C" fn preserve(_: u32, _: *mut u32, _: *const u8, _: u32) {}

    #[test]
    fn masks_addresses_wrapping_and_register_shifts() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::PACKED_SURFACE_SPAN_PREPARE, 4096) else { return; };
        let surface = slab.cast::<u32>();
        unsafe {
            surface.write(0xffff_fffc);
            surface.add(1).write(0xffff_fff0);
            surface.add(2).write(16);
            for shift in [0, 1, 4, 5, 31, 32, 255, 256, 257] {
                surface.add(3).write(shift);
                for (left, right) in [(0, 0), (0, 32), (1, 31), (3, 17), (31, 33),
                    (32, 64), (33, 32), (u32::MAX, 1)] {
                    let mut state = [0xa5a5_a5a5; 15];
                    state[3] = u32::MAX;
                    state[4] = left;
                    state[6] = right;
                    state[7] = surface as usize as u32;
                    let before = state;
                    prepare_with(state.as_mut_ptr(), preserve);
                    // Independent wider-integer reference for ARM LSL.
                    let scale = |x: u32| -> u32 {
                        let n = shift & 255;
                        if n >= 32 { 0 } else { ((x as u64) << n) as u32 }
                    };
                    let start = scale(left);
                    let end = scale(right);
                    let last_word = end.wrapping_sub(1) >> 5;
                    // At end=0, subtraction is in word-distance space, not bits.
                    let distance = if end == 0 {
                        0u32.wrapping_sub(start >> 5).wrapping_sub(1)
                    } else { last_word.wrapping_sub(start >> 5) };
                    let mut first_mask = 0;
                    let mut last_mask = 0;
                    for bit in 0..32 {
                        if bit >= (start & 31) { first_mask |= 1 << (31 - bit); }
                        if end & 31 == 0 || bit < (end & 31) { last_mask |= 1 << (31 - bit); }
                    }
                    assert_eq!(&state[..8], &before[..8]);
                    assert_eq!(&state[8..], &[
                        0xffff_fffc_u32.wrapping_add(16).wrapping_add((start >> 5) * 4),
                        0xffff_fff0, distance, start, end, first_mask, last_mask]);
                }
            }
            surface.add(3).write(1);
            let mut state = [0; 15];
            state[0] = surface as usize as u32;
            state[7] = surface.add(8) as usize as u32;
            surface.add(10).write(8);
            prepare_with(state.as_mut_ptr(), replace_surface);
            assert_eq!(&state[10..], &[1, 6, 34, 0x03ff_ffff, 0xc000_0000]);
        }
    }
}
