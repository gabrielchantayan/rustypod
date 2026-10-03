//! Video-engine scissor rectangle setter — `FUN_08254798` @ 0x08254798.
//! True size: 64 bytes, 0x08254798..0x082547d8: 60 instruction bytes and
//! the 0x501 literal at 0x082547d4, followed by the next function's push.
//! Whole-image aligned A32 scan: one plain inbound BL at 0x08251e64 and
//! one BLNE at 0x082d20d8. Body: two plain BLs, zero predicated BLs.
//!
//! Reject negative width or height by latching error 0x501 without changing
//! geometry. Otherwise write x/y/width/height at +0x118..+0x124 and refresh
//! the frame rectangle through the resident helper at 0x08252e24. Origins
//! may be negative; zero dimensions are accepted. The enable byte at +0x130
//! is not changed (the refresh helper uses it to decide whether to clip).
//!
//! Deliberate deviations: remove stack rectangle staging and incidental
//! restoration of argument registers; the ABI returns void, as both callers
//! ignore the restored registers. Reuse the Rust error latch. Frame refresh
//! remains a firmware call, not another port; the public valid host path
//! panics, while tests inject the refresh as in video_engine_output_rect.

use crate::util::error_latch::latch_first_error;

/// # Safety
/// `engine` must be an aligned, live firmware video engine, including all
/// objects needed by frame refresh at 0x08252e24. With negative dimensions,
/// only its first writable error word is required.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn video_engine_set_scissor_rect(
    engine: *mut u32, x: i32, y: i32, width: i32, height: i32,
) {
    set_scissor_rect_with_refresh(engine, x, y, width, height, |engine| {
        #[cfg(target_os = "none")]
        {
            let refresh: unsafe extern "C" fn(*mut u32) =
                core::mem::transmute(0x0825_2e24usize);
            refresh(engine);
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = engine;
            panic!("video_engine_set_scissor_rect requires firmware frame refresh 0x08252e24");
        }
    });
}

#[inline]
unsafe fn set_scissor_rect_with_refresh(
    engine: *mut u32, x: i32, y: i32, width: i32, height: i32,
    refresh: impl FnOnce(*mut u32),
) {
    if width < 0 || height < 0 {
        latch_first_error(engine, 0x501);
        return;
    }
    let words = engine.cast::<i32>();
    for (index, value) in [x, y, width, height].iter().enumerate() {
        words.add(0x118 / 4 + index).write_volatile(*value);
    }
    refresh(engine);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_dimensions_preserve_geometry_and_first_error() {
        for (width, height) in [(-1, 0), (0, -1), (i32::MIN, i32::MAX),
                                (i32::MAX, i32::MIN), (-1, -1)] {
            for error in [0, 0x500, u32::MAX] {
                let mut engine = [0xdead_beefu32; 0x150 / 4];
                engine[0] = error;
                let mut expected = engine;
                expected[0] = if error == 0 { 0x501 } else { error };
                unsafe {
                    set_scissor_rect_with_refresh(engine.as_mut_ptr(), 17, -23, width, height,
                        |_| panic!("invalid dimensions must not refresh"));
                }
                assert_eq!(engine, expected);
            }
        }
    }

    #[test]
    fn accepted_boundaries_store_before_refresh_and_preserve_other_fields() {
        for (x, y, width, height) in [
            (0, 0, 0, 0), (-7, -11, 1, 3), (13, -19, 320, 241),
            (i32::MIN, i32::MAX, i32::MAX, i32::MAX),
            (i32::MAX, i32::MIN, 0, 1),
        ] {
            let mut engine = [0x1234_abcdu32; 0x150 / 4];
            let mut expected = engine;
            expected[0x118 / 4..0x128 / 4].copy_from_slice(
                &[x as u32, y as u32, width as u32, height as u32]);
            unsafe {
                set_scissor_rect_with_refresh(engine.as_mut_ptr(), x, y, width, height, |live| {
                    assert_eq!(core::slice::from_raw_parts(live, expected.len()), &expected);
                    // A refresh-side effect must survive the setter's return.
                    live.add(0x9c / 4).write(0x7654_3210);
                });
            }
            expected[0x9c / 4] = 0x7654_3210;
            assert_eq!(engine, expected);
        }
    }
}
