//! `fixed3_add_scaled` — retailOS `FUN_08248580` at **0x08248580**.
//!
//! Raw decoding establishes an **84-byte** body
//! (0x08248580..0x082485d4): the next function begins with `push` at
//! 0x082485d8, so Ghidra's 88-byte extent includes that first word. There
//! are **6 BL call sites**, independently counted by decoding every ARM B/BL
//! word in `osos.dec`: 3 plain `bl` calls (0x0824c168, 0x0824c1d8,
//! 0x0824c38c) and 3 `bleq` calls (0x0824c128, 0x0824c2d8, 0x0824c31c).
//! The conditional calls are gated by caller flag tests; this helper has no
//! NULL guard.
//!
//! Adds a scalar-scaled Q16.16 triple into a three-word accumulator. For each
//! component, `smull` forms the signed 64-bit product, the `lsl`/`orr` pair
//! selects bits 16..47 (an arithmetic signed product shifted right by 16),
//! and `add` wraps that Q16.16 delta into the corresponding accumulator word.
//! Components are loaded and stored strictly in ascending order.
//!
//! # Deliberate deviations
//!
//! Rust expresses the `smull`/bit-selection sequence as signed `i64`
//! multiplication and arithmetic shifting. Volatile accesses preserve the
//! firmware's per-component load/add/store order, including effects from
//! partially overlapping `accumulator` and `value` ranges; they are otherwise
//! semantically identical.

/// Adds `scale * value` in Q16.16 to the three-word `accumulator` in place —
/// retailOS `FUN_08248580` at 0x08248580 (84 bytes; 6 decoded BL call sites).
///
/// # Safety
///
/// `accumulator` must be valid for three writable, aligned `i32` values and
/// `value` for three readable, aligned `i32` values. The ranges may overlap;
/// accesses occur in ascending component order. Neither pointer is NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fixed3_add_scaled(
    accumulator: *mut i32,
    value: *const i32,
    scale: i32,
) {
    let value_0 = core::ptr::read_volatile(value);
    let accumulator_0 = core::ptr::read_volatile(accumulator);
    core::ptr::write_volatile(
        accumulator,
        accumulator_0.wrapping_add(((scale as i64 * value_0 as i64) >> 16) as i32),
    );

    let value_1 = core::ptr::read_volatile(value.add(1));
    let accumulator_1 = core::ptr::read_volatile(accumulator.add(1));
    core::ptr::write_volatile(
        accumulator.add(1),
        accumulator_1.wrapping_add(((scale as i64 * value_1 as i64) >> 16) as i32),
    );

    let value_2 = core::ptr::read_volatile(value.add(2));
    let accumulator_2 = core::ptr::read_volatile(accumulator.add(2));
    core::ptr::write_volatile(
        accumulator.add(2),
        accumulator_2.wrapping_add(((scale as i64 * value_2 as i64) >> 16) as i32),
    );
}

#[cfg(test)]
mod tests {
    use super::fixed3_add_scaled;

    #[test]
    fn adds_signed_q16_16_products() {
        let mut accumulator = [5, -7, 9];
        let value = [0x0001_8000, -0x0001_8000, -1];

        unsafe { fixed3_add_scaled(accumulator.as_mut_ptr(), value.as_ptr(), 0x0001_8000) };

        assert_eq!(accumulator, [0x0002_4005, -0x0002_4007, 7]);
    }
    #[test]
    fn wraps_the_accumulator_and_keeps_negative_fractional_products_negative() {
        let mut accumulator = [i32::MAX, i32::MIN, 0];
        let value = [0x0001_0000, -0x0001_0000, -1];

        unsafe { fixed3_add_scaled(accumulator.as_mut_ptr(), value.as_ptr(), 0x0001_0000) };

        assert_eq!(
            accumulator,
            [
                i32::MAX.wrapping_add(0x0001_0000),
                i32::MIN.wrapping_sub(0x0001_0000),
                -1,
            ],
        );
    }

    #[test]
    fn partially_overlapping_ranges_observe_component_order() {
        let mut words = [10, 20, 30, 40];

        unsafe { fixed3_add_scaled(words.as_mut_ptr().add(1), words.as_ptr(), 0x0001_0000) };

        assert_eq!(words, [10, 30, 60, 100]);
    }
}
