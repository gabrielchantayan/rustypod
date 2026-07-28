//! FreeType `fttrigon` — the CORDIC vector-to-polar chain as compiled
//! into retailOS: `FT_Atan2` and its two static helpers `ft_trig_prenorm`
//! and `ft_trig_pseudo_polarize`. Angles are `FT_Angle`, i.e. 16.16
//! fixed-point *degrees* (`FT_ANGLE_PI` == 0xb40000 == 180.0).
//! Pure integer code — no hardware; host tests compare against
//! reference implementations transcribed from the upstream 2.3-era
//! `fttrigon.c` plus `f64::atan2`. Call counts are binary-scanned b/bl
//! words.
//!
//! All arithmetic is 32-bit wrapping, exactly as the original's
//! `add`/`sub`/`rsb` instructions; the shifts are arithmetic (`asr`) with
//! amounts that always stay inside 0..=27, so ARM's register-shift
//! saturation rules never come into play.

use crate::ft::types::FtVector;

/// 180 degrees in 16.16 — upstream `FT_ANGLE_PI` (`2 * FT_ANGLE_PI2`).
/// The original materializes it as `movlt ip, #0xb40000`.
pub const FT_ANGLE_PI: i32 = 0x00b4_0000;

/// Number of pseudo-rotations after the fixed `arctan(2)` pre-rotation —
/// upstream `FT_TRIG_MAX_ITERS`; the original's `cmp lr, #23; blt`.
const FT_TRIG_MAX_ITERS: i32 = 23;

/// Bit the prenormalizer parks the vector's MSB on (the original's
/// `cmp r2, #27` / `#27 - msb`). Upstream calls this `FT_TRIG_SAFE_MSB`.
const FT_TRIG_SAFE_MSB: i32 = 27;

/// `ft_trig_arctan_table` — `arctan(2^(1-k))` in 16.16 degrees:
/// entry 0 is `arctan(2)` (63.435 deg, used by the pre-rotation), entry
/// 1 is 45 deg, entry `k` is `arctan(2^-(k-1))`.
///
/// # Deviations
///
/// The original loads the table through a pointer held in RW data at
/// 0x089011fc (literal `DAT_080ccec0` @ 0x080ccec0). That address holds
/// unrelated bytes in osos.dec — the RW *image* lives at a different
/// file offset than its runtime address — but the table's ROM image is
/// at 0x0890c0dc (runtime + 0xaee0), and the neighboring FreeType
/// `__FILE__` pointer 0x089012e8 resolves into the very same relocated
/// block (+0xaed7, at the `...\freetype\src\base\ftstream.c` string), so
/// the identification is solid. The 24 words there are byte-for-byte
/// upstream's `ft_trig_arctan_table`, so the port embeds them as `const`
/// data instead of chasing the pointer.
static FT_TRIG_ARCTAN_TABLE: [i32; 24] = [
    4157273, 2949120, 1740967, 919879, 466945, 234379, 117304, 58666,
    29335, 14668, 7334, 3667, 1833, 917, 458, 229, 115, 57, 29, 14, 7, 4,
    2, 1,
];

/// ft_trig_prenorm (FreeType `ft_trig_prenorm`) — original:
/// `FUN_080908a0` @ 0x080908a0 (140 bytes; 1 call site, `ft_atan2`).
///
/// Scales `vec` so that the most significant bit of
/// `|x| | |y|` lands on bit [`FT_TRIG_SAFE_MSB`], giving the CORDIC loop
/// its working headroom, and returns the shift applied (negative when
/// the vector had to be scaled *down*).
///
/// The MSB is found by upstream's `FT_MSB` binary search (16/8/4/2/1),
/// which the original inlines with **signed** compares and `asr`. Two
/// quirks follow from that and are preserved:
///
/// - the magnitudes come from `rsblt` (wrapping negate), so
///   `x == i32::MIN` stays negative;
/// - a negative `|x| | |y|` therefore fails every compare, yielding
///   `msb == 0` and a 27-bit left shift.
///
/// `x == y == 0` also yields `msb == 0` (and a harmless `0 << 27`);
/// `ft_atan2` filters that case out before calling.
///
/// # Safety
/// `vector` must be a valid `FtVector` pointer (the original does not
/// null-check it).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_trig_prenorm(vector: *mut FtVector) -> i32 {
    let (x, y) = ((*vector).x, (*vector).y);

    // FT_MSB(|x| | |y|), inlined with signed compares (see above).
    let mut z = x.wrapping_abs() | y.wrapping_abs();
    let mut msb = 0;
    if z >= 0x1_0000 {
        msb = 16;
        z >>= 16;
    }
    if z >= 0x100 {
        z >>= 8;
        msb += 8;
    }
    if z >= 0x10 {
        z >>= 4;
        msb += 4;
    }
    if z >= 4 {
        z >>= 2;
        msb += 2;
    }
    if z >= 2 {
        msb += 1;
    }

    if msb > FT_TRIG_SAFE_MSB {
        let shift = msb - FT_TRIG_SAFE_MSB;
        (*vector).x = x >> shift;
        (*vector).y = y >> shift;
        -shift
    } else {
        let shift = FT_TRIG_SAFE_MSB - msb;
        (*vector).x = x << shift;
        (*vector).y = y << shift;
        shift
    }
}

/// ft_trig_pseudo_polarize (FreeType `ft_trig_pseudo_polarize`) —
/// original: `FUN_080cce10` @ 0x080cce10 (176 bytes; 1 call site,
/// `ft_atan2`).
///
/// CORDIC vector-to-polar: rotates `vec` onto the positive x axis and
/// accumulates the angle it removed. On return `vec.x` holds the
/// (CORDIC-scaled) pseudo-length and `vec.y` the angle in 16.16 degrees.
///
/// 1. Quadrant fold: `x < 0` negates both coordinates and seeds
///    `theta = FT_ANGLE_PI`; `y > 0` then flips that seed's sign.
/// 2. Fixed pre-rotation by `arctan(2)` — multiply by `1 ∓ 2i`
///    (`y >= 0`: `x += 2y, y -= 2x`, `theta += table[0]`; `y < 0` the
///    mirror) — which brings the vector inside the CORDIC's convergence
///    sector.
/// 3. 23 pseudo-rotations `i = 0..22` by `arctan(2^-i)`, each a shift
///    and two adds, accumulating `table[i + 1]` with the sign of the
///    rotation.
/// 4. `theta` is rounded to a multiple of 32 on its magnitude
///    (`FT_PAD_ROUND(theta, 32)`).
///
/// Note the sign decisions in step 1/2 straddle zero differently
/// (`y > 0` flips the seed, `y >= 0` picks the rotation direction *and*
/// the `table[0]` sign) — faithful to the `rsbgt`/`addge`/`sublt`
/// triple, which Ghidra renders with the `table[0]` condition one step
/// off.
///
/// # Safety
/// `vector` must be a valid `FtVector` pointer (the original does not
/// null-check it).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_trig_pseudo_polarize(vector: *mut FtVector) {
    let (mut x, mut y) = ((*vector).x, (*vector).y);

    // Fold into the right half plane.
    let mut theta = if x < 0 {
        x = x.wrapping_neg();
        y = y.wrapping_neg();
        FT_ANGLE_PI
    } else {
        0
    };
    if y > 0 {
        theta = theta.wrapping_neg();
    }

    // Pre-rotation by arctan(2).
    let (nx, ny) = if y >= 0 {
        theta = theta.wrapping_add(FT_TRIG_ARCTAN_TABLE[0]);
        (
            x.wrapping_add(y.wrapping_mul(2)),
            y.wrapping_sub(x.wrapping_mul(2)),
        )
    } else {
        theta = theta.wrapping_sub(FT_TRIG_ARCTAN_TABLE[0]);
        (
            x.wrapping_sub(y.wrapping_mul(2)),
            y.wrapping_add(x.wrapping_mul(2)),
        )
    };
    x = nx;
    y = ny;

    // Pseudo-rotations.
    for i in 0..FT_TRIG_MAX_ITERS {
        let arctan = FT_TRIG_ARCTAN_TABLE[i as usize + 1];
        let (xs, ys) = (x >> i, y >> i);
        if y < 0 {
            x = x.wrapping_sub(ys);
            y = y.wrapping_add(xs);
            theta = theta.wrapping_sub(arctan);
        } else {
            x = x.wrapping_add(ys);
            y = y.wrapping_sub(xs);
            theta = theta.wrapping_add(arctan);
        }
    }

    // FT_PAD_ROUND(theta, 32) on the magnitude.
    let negative = theta < 0;
    let magnitude = if negative { theta.wrapping_neg() } else { theta };
    let rounded = magnitude.wrapping_add(16) & !31;
    (*vector).y = if negative { rounded.wrapping_neg() } else { rounded };
    (*vector).x = x;
}

/// ft_atan2 (FreeType `FT_Atan2`) — original: `FUN_0804c1c4`
/// @ 0x0804c1c4 (44 bytes; 7 call sites).
///
/// Angle of the vector `(x, y)` in 16.16 degrees, in the range
/// (-180, 180]. `(0, 0)` returns 0 (the original tests `orrs x, y`);
/// otherwise the pair goes on the stack as an `FtVector` and through
/// [`ft_trig_prenorm`] (whose shift result is discarded) and
/// [`ft_trig_pseudo_polarize`], and the resulting `vec.y` is the answer.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn ft_atan2(x: i32, y: i32) -> i32 {
    if x | y == 0 {
        return 0;
    }
    let mut vector = FtVector { x, y };
    unsafe {
        ft_trig_prenorm(&mut vector);
        ft_trig_pseudo_polarize(&mut vector);
    }
    vector.y
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference `FT_MSB` — upstream's documented "index of the highest
    /// set bit", computed independently of the port's binary search.
    /// Only meaningful for `z > 0`, which is all the reference prenorm
    /// uses it for.
    fn msb_ref(z: i32) -> i32 {
        31 - (z as u32).leading_zeros() as i32
    }

    /// Reference `ft_trig_prenorm`, transcribed from upstream
    /// `fttrigon.c`. Restricted to inputs where `|x| | |y|` is
    /// non-negative (the port's documented `i32::MIN` quirk has its own
    /// test).
    fn prenorm_ref(v: FtVector) -> (FtVector, i32) {
        let z = v.x.wrapping_abs() | v.y.wrapping_abs();
        assert!(z > 0, "reference is only defined for a non-zero vector");
        let msb = msb_ref(z);
        if msb <= FT_TRIG_SAFE_MSB {
            let shift = FT_TRIG_SAFE_MSB - msb;
            (FtVector { x: v.x << shift, y: v.y << shift }, shift)
        } else {
            let shift = msb - FT_TRIG_SAFE_MSB;
            (FtVector { x: v.x >> shift, y: v.y >> shift }, -shift)
        }
    }

    /// Reference `ft_trig_pseudo_polarize`, transcribed from upstream
    /// `fttrigon.c` in its own idiom (explicit `xi`/`yi` temporaries and
    /// a table cursor) so it is not a copy of the port's control flow.
    fn pseudo_polarize_ref(v: FtVector) -> FtVector {
        let (mut x, mut y) = (v.x, v.y);
        let mut theta: i32 = 0;
        if x < 0 {
            x = x.wrapping_neg();
            y = y.wrapping_neg();
            theta = 2 * (FT_ANGLE_PI / 2);
        }
        if y > 0 {
            theta = -theta;
        }
        let mut arctan = FT_TRIG_ARCTAN_TABLE.iter();
        let first = *arctan.next().unwrap();
        if y < 0 {
            let yi = y.wrapping_add(x << 1);
            x = x.wrapping_sub(y << 1);
            y = yi;
            theta -= first;
        } else {
            let yi = y.wrapping_sub(x << 1);
            x = x.wrapping_add(y << 1);
            y = yi;
            theta += first;
        }
        for i in 0..FT_TRIG_MAX_ITERS {
            let t = *arctan.next().unwrap();
            if y < 0 {
                let yi = y.wrapping_add(x >> i);
                x = x.wrapping_sub(y >> i);
                y = yi;
                theta -= t;
            } else {
                let yi = y.wrapping_sub(x >> i);
                x = x.wrapping_add(y >> i);
                y = yi;
                theta += t;
            }
        }
        // FT_PAD_ROUND( theta, 32 ) == ( theta + 16 ) & ~31
        theta = if theta >= 0 {
            (theta + 16) & !31
        } else {
            -((-theta + 16) & !31)
        };
        FtVector { x, y: theta }
    }

    fn prenorm(v: FtVector) -> (FtVector, i32) {
        let mut v = v;
        let shift = unsafe { ft_trig_prenorm(&mut v) };
        (v, shift)
    }

    fn polarize(v: FtVector) -> FtVector {
        let mut v = v;
        unsafe { ft_trig_pseudo_polarize(&mut v) };
        v
    }

    /// xorshift32, so the sweeps are deterministic.
    fn rng(seed: u32) -> impl FnMut() -> u32 {
        let mut s = seed;
        move || {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            s
        }
    }

    #[test]
    fn arctan_table_is_the_upstream_table() {
        // Entry k is arctan(2^(1-k)) in 16.16 degrees; spot-check the
        // ends against the transcendental values.
        assert_eq!(FT_TRIG_ARCTAN_TABLE.len(), 24);
        for (k, &entry) in FT_TRIG_ARCTAN_TABLE.iter().enumerate() {
            let want = (2f64.powi(1 - k as i32)).atan().to_degrees() * 65536.0;
            assert!(
                (entry as f64 - want).abs() <= 1.0,
                "table[{k}] = {entry}, want ~{want}"
            );
        }
        assert_eq!(FT_TRIG_ARCTAN_TABLE[1], 45 * 65536); // arctan(1)
    }

    #[test]
    fn prenorm_parks_the_msb_on_bit_27() {
        for (x, y) in [
            (1, 0),
            (0, 1),
            (1, 1),
            (-1, 0),
            (0x7fff_ffff, 0),
            (0, i32::MIN + 1),
            (0x0800_0000, 0x0400_0000),
            (0x1000_0000, -1),
        ] {
            let (v, shift) = prenorm(FtVector { x, y });
            let z = v.x.wrapping_abs() | v.y.wrapping_abs();
            assert!(
                (1 << FT_TRIG_SAFE_MSB..1 << (FT_TRIG_SAFE_MSB + 1)).contains(&z)
                    || shift < 0,
                "({x:#x}, {y:#x}) -> {v:?} shift {shift}"
            );
        }
        // Exactly on the boundary bit: no shift at all.
        assert_eq!(prenorm(FtVector { x: 1 << 27, y: 0 }), (FtVector { x: 1 << 27, y: 0 }, 0));
        // One bit above: scaled down by one, shift reported negative.
        assert_eq!(
            prenorm(FtVector { x: 1 << 28, y: 4 }),
            (FtVector { x: 1 << 27, y: 2 }, -1)
        );
    }

    #[test]
    fn prenorm_matches_reference_on_randomized_inputs() {
        let mut rnd = rng(0x0bad_c0de);
        for _ in 0..200_000 {
            let (x, y) = (rnd() as i32, rnd() as i32);
            if x.wrapping_abs() | y.wrapping_abs() <= 0 {
                continue; // (0,0) and the i32::MIN quirk: separate tests
            }
            let v = FtVector { x, y };
            assert_eq!(prenorm(v), prenorm_ref(v), "({x:#x}, {y:#x})");
        }
    }

    #[test]
    fn prenorm_matches_reference_on_powers_of_two() {
        for bit in 0..31 {
            for &sign in &[1i32, -1] {
                let x = sign * (1i32 << bit);
                for y in [0, 1, -1, x >> 1, x] {
                    let v = FtVector { x, y };
                    if v.x.wrapping_abs() | v.y.wrapping_abs() <= 0 {
                        continue;
                    }
                    assert_eq!(prenorm(v), prenorm_ref(v), "{v:?}");
                }
            }
        }
    }

    #[test]
    fn prenorm_int_min_quirk_shifts_up_by_27() {
        // |i32::MIN| stays negative, so every signed compare in the MSB
        // search fails and msb comes out 0.
        let (v, shift) = prenorm(FtVector { x: i32::MIN, y: 3 });
        assert_eq!(shift, 27);
        assert_eq!(v, FtVector { x: i32::MIN << 27, y: 3 << 27 });
        let (v, shift) = prenorm(FtVector { x: 7, y: i32::MIN });
        assert_eq!(shift, 27);
        assert_eq!(v, FtVector { x: 7 << 27, y: i32::MIN << 27 });
    }

    #[test]
    fn prenorm_zero_vector_shifts_up_by_27() {
        assert_eq!(
            prenorm(FtVector { x: 0, y: 0 }),
            (FtVector { x: 0, y: 0 }, 27)
        );
    }

    #[test]
    fn pseudo_polarize_matches_reference_on_randomized_inputs() {
        let mut rnd = rng(0x5eed_1234);
        for _ in 0..200_000 {
            // Prenormalized magnitudes are what the original ever sees.
            let x = (rnd() as i32) >> 4;
            let y = (rnd() as i32) >> 4;
            let v = FtVector { x, y };
            assert_eq!(polarize(v), pseudo_polarize_ref(v), "{v:?}");
        }
    }

    #[test]
    fn pseudo_polarize_matches_reference_on_axes_and_extremes() {
        let vals = [
            0,
            1,
            -1,
            2,
            -2,
            1 << 27,
            -(1 << 27),
            (1 << 27) - 1,
            0x7fff_ffff,
            i32::MIN,
            i32::MIN + 1,
        ];
        for &x in &vals {
            for &y in &vals {
                let v = FtVector { x, y };
                assert_eq!(polarize(v), pseudo_polarize_ref(v), "{v:?}");
            }
        }
    }

    #[test]
    fn pseudo_polarize_angle_is_a_multiple_of_32() {
        let mut rnd = rng(0x1111_2222);
        for _ in 0..1000 {
            let v = FtVector { x: (rnd() as i32) >> 4, y: (rnd() as i32) >> 4 };
            assert_eq!(polarize(v).y % 32, 0, "{v:?}");
        }
    }

    #[test]
    fn atan2_zero_vector_is_zero() {
        assert_eq!(ft_atan2(0, 0), 0);
    }

    #[test]
    fn atan2_cardinal_directions() {
        const DEG: i32 = 0x10000;
        assert_eq!(ft_atan2(1, 0), 0);
        assert_eq!(ft_atan2(0, 1), 90 * DEG);
        assert_eq!(ft_atan2(-1, 0), 180 * DEG);
        assert_eq!(ft_atan2(0, -1), -90 * DEG);
        assert_eq!(ft_atan2(1, 1), 45 * DEG);
        assert_eq!(ft_atan2(-1, 1), 135 * DEG);
        assert_eq!(ft_atan2(-1, -1), -135 * DEG);
        assert_eq!(ft_atan2(1, -1), -45 * DEG);
        // Scale invariance: the prenormalizer removes the magnitude.
        assert_eq!(ft_atan2(1000, 1000), 45 * DEG);
        assert_eq!(ft_atan2(0x4000_0000, 0x4000_0000), 45 * DEG);
    }

    /// The whole chain against `f64::atan2` in degrees — the independent
    /// check that this really computes an angle, not just that it
    /// matches a transcription of the same algorithm.
    fn assert_close_to_atan2(x: i32, y: i32) {
        let got = ft_atan2(x, y) as f64 / 65536.0;
        let want = (y as f64).atan2(x as f64).to_degrees();
        let mut delta = got - want;
        if delta > 180.0 {
            delta -= 360.0;
        }
        if delta < -180.0 {
            delta += 360.0;
        }
        assert!(
            delta.abs() < 0.005,
            "ft_atan2({x}, {y}) = {got} deg, atan2 = {want} deg"
        );
    }

    #[test]
    fn atan2_agrees_with_floating_point_atan2() {
        let mut rnd = rng(0xfeed_beef);
        for _ in 0..100_000 {
            let (x, y) = (rnd() as i32, rnd() as i32);
            if x == 0 && y == 0 {
                continue;
            }
            // i32::MIN hits the documented prenorm quirk (which mangles
            // the vector); everything else must track atan2.
            if x == i32::MIN || y == i32::MIN {
                continue;
            }
            assert_close_to_atan2(x, y);
        }
    }

    #[test]
    fn atan2_agrees_with_floating_point_on_a_degree_sweep() {
        // Unit vectors every half degree at a large radius.
        for half_degrees in -359..=360 {
            let angle = (half_degrees as f64) * 0.5f64.to_radians();
            let r = 1e8;
            let x = (r * angle.cos()).round() as i32;
            let y = (r * angle.sin()).round() as i32;
            assert_close_to_atan2(x, y);
        }
    }

    #[test]
    fn atan2_mirror_symmetry_holds_to_within_one_rounding_step() {
        // The CORDIC shifts truncate toward -infinity, so mirroring y is
        // only symmetric up to the final 32-unit rounding quantum — the
        // port reproduces that asymmetry rather than a clean odd
        // function.
        let mut rnd = rng(0x2468_1357);
        for _ in 0..20_000 {
            let x = (rnd() as i32) >> 2;
            let y = (rnd() as i32) >> 2;
            if y == 0 || x == i32::MIN || y == i32::MIN {
                continue;
            }
            let delta = ft_atan2(x, -y) + ft_atan2(x, y);
            assert!(
                delta.abs() <= 32,
                "mirror symmetry at ({x}, {y}) off by {delta}"
            );
        }
    }

    #[test]
    fn atan2_int_min_quirk_is_preserved() {
        // The prenorm i32::MIN quirk propagates: values verified against
        // the reference transcription of the original algorithm, not
        // against atan2 (they do not agree, by construction).
        for (x, y) in [(i32::MIN, 0), (0, i32::MIN), (i32::MIN, i32::MIN), (i32::MIN, 1)] {
            let mut v = FtVector { x, y };
            let (v_ref, _) = {
                let z = x.wrapping_abs() | y.wrapping_abs();
                assert!(z < 0, "these inputs are exactly the quirk inputs");
                (FtVector { x: x << 27, y: y << 27 }, 27)
            };
            unsafe { ft_trig_prenorm(&mut v) };
            assert_eq!(v, v_ref);
            assert_eq!(ft_atan2(x, y), pseudo_polarize_ref(v_ref).y);
        }
    }
}
