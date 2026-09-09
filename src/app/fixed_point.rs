//! `fixed_point_set` — original: `FUN_08280184` @ **0x08280184** (8 bytes,
//! 0x08280184..0x0828018c; **12 direct `bl` call sites**, all unconditional,
//! zero predicated forms, and no tail `b` calls), verified by decoding every
//! ARM B/BL word in `osos.dec`.
//!
//! Raw ARM is `stm r0, {r1, r2}; bx lr`: store the two Q16.16 coordinate words
//! in ascending order, `x` then `y`, through an unguarded point pointer.
//! The four callers in `FUN_08142dac` make the unit-square corners, while the
//! eight in `FUN_0828c874` build two fixed-point quads. No aligned image word
//! contains 0x08280184, so the function is statically called rather than
//! vtable-dispatched.
//!
//! Deliberate deviations: none.

/// Two signed Q16.16 coordinates, stored as consecutive target words.
#[repr(C)]
pub struct FixedPoint {
    /// +0x00
    pub x: i32,
    /// +0x04
    pub y: i32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 8] = [0; core::mem::size_of::<FixedPoint>()];

/// fixed_point_set — original: `FUN_08280184` @ 0x08280184 (8 bytes; 12
/// unconditional `bl` call sites, binary-scanned).
///
/// Stores Q16.16 `x` and `y` at the two consecutive words of `point`. There
/// is no NULL or alignment guard, matching the original `stm`.
///
/// # Safety
///
/// `point` must be writable and word-aligned for one [`FixedPoint`].
#[cfg_attr(target_os = "none", link_section = ".text.fixed_point_set")]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fixed_point_set(point: *mut FixedPoint, x: i32, y: i32) {
    unsafe {
        (*point).x = x;
        (*point).y = y;
    }
}

#[cfg(test)]
mod tests {
    use super::{fixed_point_set, FixedPoint};

    #[test]
    fn stores_signed_fixed_coordinates_without_touching_neighbors() {
        let mut words = [0xdead_beefu32, 0xa5a5_a5a5, 0x5a5a_5a5a, 0xc001_d00d];
        let point = unsafe { words.as_mut_ptr().add(1).cast::<FixedPoint>() };

        unsafe { fixed_point_set(point, -0x0001_8000, 0x7fff_ffff) };

        assert_eq!(words, [0xdead_beef, 0xfffe_8000, 0x7fff_ffff, 0xc001_d00d]);
    }

    #[test]
    fn overwrites_both_coordinate_words_on_each_call() {
        let mut point = FixedPoint { x: 0x0001_0000, y: -0x0001_0000 };

        unsafe { fixed_point_set(&mut point, 0, 0x0001_0000) };
        assert_eq!((point.x, point.y), (0, 0x0001_0000));

        unsafe { fixed_point_set(&mut point, -1, 0) };
        assert_eq!((point.x, point.y), (-1, 0));
    }
}
