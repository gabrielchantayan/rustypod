//! Outline edge direction classifier at 0x080b5a44, 164 bytes (next entry
//! 0x080b5ae8). Verified raw A32: zero outgoing plain/predicated BLs; two
//! incoming plain BLs at 0x080bf4bc and 0x080bf4e8, zero predicated BLs.
//! Classifies outline coordinate deltas as horizontal (+1/-1), vertical
//! (+2/-2), or oblique (4), using a strict 12:1 dominance threshold.
//! Equality and the zero vector are oblique. Negation and scaling wrap as
//! in ARM registers, including extreme i32 inputs. Deliberate deviation:
//! share the quadrant comparisons through wrapping magnitudes; no behavioral
//! deviations and no external seams.

/// Classify an outline edge without normalizing or modifying its coordinates.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn outline_direction(dx: i32, dy: i32) -> i32 {
    let x = if dx < 0 { dx.wrapping_neg() } else { dx };
    let y = if dy < 0 { dy.wrapping_neg() } else { dy };
    if y > x.wrapping_mul(12) {
        if dy < 0 { -2 } else { 2 }
    } else if x > y.wrapping_mul(12) {
        if dx < 0 { -1 } else { 1 }
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::outline_direction;

    // Independent quadrant transcription of the raw comparisons, not abs().
    fn reference(dx: i32, dy: i32) -> i32 {
        if dx < 0 {
            if dy < 0 {
                if dy.wrapping_neg() > dx.wrapping_mul(-12) { return -2; }
                if dx.wrapping_neg() <= dy.wrapping_mul(-12) { return 4; }
            } else {
                if dy > dx.wrapping_mul(-12) { return 2; }
                if dx.wrapping_neg() <= dy.wrapping_mul(12) { return 4; }
            }
            -1
        } else {
            if dy < 0 {
                if dy.wrapping_neg() > dx.wrapping_mul(12) { return -2; }
                if dx <= dy.wrapping_mul(-12) { return 4; }
            } else {
                if dy > dx.wrapping_mul(12) { return 2; }
                if dx <= dy.wrapping_mul(12) { return 4; }
            }
            1
        }
    }

    #[test]
    fn axes_zero_and_thresholds() {
        assert_eq!(outline_direction(0, 0), 4);
        for sign in [-1, 1] {
            assert_eq!(outline_direction(sign, 0), sign);
            assert_eq!(outline_direction(0, sign), 2 * sign);
        }
        for sx in [-1, 1] {
            for sy in [-1, 1] {
                for minor in [1, 2, 127, 5461] {
                    for delta in [-1, 0, 1] {
                        let major = minor * 12 + delta;
                        assert_eq!(outline_direction(sx * major, sy * minor),
                                   if delta > 0 { sx } else { 4 });
                        assert_eq!(outline_direction(sx * minor, sy * major),
                                   if delta > 0 { 2 * sy } else { 4 });
                    }
                }
            }
        }
    }

    #[test]
    fn signed_coordinate_and_overflow_boundaries() {
        let values = [i32::MIN, i32::MIN + 1, -178956971, -178956970,
                      -65535, -13, -12, -1, 0, 1, 12, 13, 65535,
                      178956970, 178956971, i32::MAX - 1, i32::MAX];
        for dx in values {
            for dy in values {
                assert_eq!(outline_direction(dx, dy), reference(dx, dy),
                           "dx={dx}, dy={dy}");
            }
        }
        for dx in -128..=128 {
            for dy in -128..=128 {
                assert_eq!(outline_direction(dx, dy), reference(dx, dy));
            }
        }
    }
}
