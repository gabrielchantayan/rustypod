//! Classify a coordinate delta by its near-axis direction.
//!
//! FUN_08091504 @ 0x08091504: 92 bytes, ending at the next PUSH at
//! 0x08091560. Raw A32 census: zero outbound plain/predicated BLs;
//! two inbound plain BLs (0x0808ad94, 0x0808adcc), zero predicated.
//! Take wrapping signed magnitudes; if |dx| > 12*|dy| return -2/+2
//! by dx's sign, otherwise if |dy| > 12*|dx| return +1/-1 by dy's
//! sign, otherwise return 4. Both comparisons are signed and strict.
//! The caller stores these codes for incoming/outgoing contour edges.
//! Deliberate deviations: no algorithm changes; LLVM chooses its own
//! register allocation and omits the stock leaf's saved LR scratch slot.

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn vector_axis_classify(dx: i32, dy: i32) -> i32 {
    let x_magnitude = dx.wrapping_abs();
    let y_magnitude = dy.wrapping_abs();
    if x_magnitude > y_magnitude.wrapping_mul(12) {
        if dx < 0 { -2 } else { 2 }
    } else if y_magnitude > x_magnitude.wrapping_mul(12) {
        if dy < 0 { 1 } else { -1 }
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::vector_axis_classify;

    #[test]
    fn strict_axis_boundaries_and_signs() {
        assert_eq!(vector_axis_classify(0, 0), 4);
        for sign_x in [-1, 1] {
            for sign_y in [-1, 1] {
                assert_eq!(vector_axis_classify(sign_x * 12, sign_y), 4);
                assert_eq!(vector_axis_classify(sign_x * 13, sign_y), sign_x * 2);
                assert_eq!(vector_axis_classify(sign_x, sign_y * 12), 4);
                assert_eq!(vector_axis_classify(sign_x, sign_y * 13), -sign_y);
                assert_eq!(vector_axis_classify(sign_x, 0), sign_x * 2);
                assert_eq!(vector_axis_classify(0, sign_y), -sign_y);
            }
        }
    }

    #[test]
    fn signed_wrapping_magnitudes_and_horizontal_precedence() {
        // ARM ADD/LSL wraps before CMP; mathematical absolute values differ.
        let cases = [
            (i32::MIN, 0, 4), (0, i32::MIN, 4),
            (i32::MIN, i32::MIN, 4), (i32::MAX, i32::MAX, 2),
            (-i32::MAX, i32::MAX, -2),
            (0, 178_956_970, -1), (0, 178_956_971, 2),
            (178_956_971, 0, 2),
            (i32::MIN, 1, -1), (1, i32::MIN, 2),
        ];
        for (dx, dy, expected) in cases {
            assert_eq!(vector_axis_classify(dx, dy), expected, "{dx}, {dy}");
        }
    }
}
