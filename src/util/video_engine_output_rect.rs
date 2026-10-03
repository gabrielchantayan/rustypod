//! Video-engine output rectangle setter — `FUN_082551b4` @ 0x082551b4.
//! True extent: 188 bytes, 0x082551b4..0x08255270 (184 instruction bytes
//! plus the 0x501 literal; next function starts with push at 0x08255270).
//! Raw aligned A32 decoding verifies two inbound BLs: plain BL at 0x08251e4c
//! and BLNE at 0x082d249c. Body: four plain BLs, zero predicated BLs.
//!
//! Reject negative dimensions by latching error 0x501. Otherwise store the
//! integer output rectangle at +0x108, update the Q16.16 center at +0x134
//! and half-size at +0x140 while preserving both third components, then
//! refresh the frame rectangle through the stock helper at 0x08252e24.
//! Half dimensions truncate before conversion, including odd dimensions;
//! center addition and fixed-point shifts wrap like A32 arithmetic.
//!
//! Deliberate deviations: stack rectangle staging is eliminated. The two
//! vector copies and error latch reuse their existing Rust ports. The frame
//! refresh remains a firmware call, not a second port; host callers need the
//! private injected refresh used by tests (the public host path panics).

use crate::fp::fixed16_vec3::copy_fixed16_vec3;
use crate::util::error_latch::latch_first_error;

/// # Safety
/// `engine` must be an aligned, live firmware video engine, including all
/// fields and objects required by frame refresh at 0x08252e24. Negative
/// dimensions require only a writable error word at the start of `engine`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn video_engine_set_output_rect(
    engine: *mut u32, x: i32, y: i32, width: i32, height: i32,
) {
    set_output_rect_with_refresh(engine, x, y, width, height, |engine| {
        #[cfg(target_os = "none")]
        {
            let refresh: unsafe extern "C" fn(*mut u32) =
                core::mem::transmute(0x0825_2e24usize);
            refresh(engine);
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = engine;
            panic!("video_engine_set_output_rect requires firmware frame refresh 0x08252e24");
        }
    });
}

#[inline]
unsafe fn set_output_rect_with_refresh(
    engine: *mut u32, x: i32, y: i32, width: i32, height: i32,
    refresh: impl FnOnce(*mut u32),
) {
    if width < 0 || height < 0 {
        latch_first_error(engine, 0x501);
        return;
    }
    let words = engine.cast::<i32>();
    for (index, value) in [x, y, width, height].iter().enumerate() {
        words.add(0x108 / 4 + index).write_volatile(*value);
    }
    let half_width = width / 2;
    let half_height = height / 2;
    let mut vector = [
        x.wrapping_add(half_width).wrapping_shl(16),
        y.wrapping_add(half_height).wrapping_shl(16),
        words.add(0x13c / 4).read_volatile(),
    ];
    copy_fixed16_vec3(words.add(0x134 / 4), vector.as_ptr());
    vector = [half_width.wrapping_shl(16), half_height.wrapping_shl(16),
              words.add(0x148 / 4).read_volatile()];
    copy_fixed16_vec3(words.add(0x140 / 4), vector.as_ptr());
    refresh(engine);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_dimensions_only_latch_first_error() {
        for (width, height) in [(-1, 0), (0, -1), (i32::MIN, i32::MAX), (-1, -1)] {
            for error in [0, 0x500] {
                let mut engine = [0xdead_beefu32; 0x150 / 4];
                engine[0] = error;
                let mut expected = engine;
                expected[0] = if error == 0 { 0x501 } else { error };
                unsafe {
                    set_output_rect_with_refresh(engine.as_mut_ptr(), 17, -23, width, height,
                        |_| panic!("invalid dimensions must not refresh"));
                }
                assert_eq!(engine, expected);
            }
        }
    }

    #[test]
    fn rectangle_fixed_point_rounding_wrapping_and_preserved_fields() {
        for (x, y, width, height) in [
            (0, 0, 0, 0), (-7, -11, 1, 3), (13, -19, 320, 241),
            (i32::MAX, i32::MIN, i32::MAX, i32::MAX),
            (65535, -65537, 65537, 131073),
        ] {
            let mut engine = [0x1234_abcdu32; 0x150 / 4];
            engine[0x13c / 4] = 0x7654_3210;
            engine[0x148 / 4] = 0xfedc_ba98;
            let mut expected = engine;
            expected[0x108 / 4..0x118 / 4].copy_from_slice(
                &[x as u32, y as u32, width as u32, height as u32]);
            let fixed = |value: i64| (value * 65536) as u32;
            expected[0x134 / 4] = fixed(x as i64 + width as i64 / 2);
            expected[0x138 / 4] = fixed(y as i64 + height as i64 / 2);
            expected[0x140 / 4] = fixed(width as i64 / 2);
            expected[0x144 / 4] = fixed(height as i64 / 2);
            unsafe {
                set_output_rect_with_refresh(engine.as_mut_ptr(), x, y, width, height, |live| {
                    // All stores must be visible before the firmware refresh runs.
                    assert_eq!(core::slice::from_raw_parts(live, expected.len()), &expected);
                });
            }
            assert_eq!(engine, expected);
        }
    }
}
