//! validate_span — `FUN_08027b08` @ 0x08027b08 (52 bytes).
//!
//! Argument validator shared by five retailOS callers. It validates a
//! `(handle, length)` pair describing a 16-byte-aligned span, propagating a
//! caller-computed pending error first. Return codes in r0:
//!
//! - `pending_error` itself when nonzero (callers pass `is_zero(flag)`, so
//!   code 1 means "a required input was zero");
//! - 2 when `handle` is null;
//! - 0 when `length` is positive and a multiple of 16;
//! - 3 otherwise (`length` signed non-positive or not 16-byte aligned).
//!
//! The raw ARM body is a pure leaf — zero `bl` sites of its own; the five
//! call sites are the incoming callers:

//! ```text
//! cmp  r2, #0        ; pending_error != 0 ?
//! movne r0, r2       ;   return pending_error
//! bxne lr
//! cmp  r0, #0        ; handle == null ?
//! moveq r0, #2       ;   return 2
//! bxeq lr
//! cmp  r1, #0        ; signed length <= 0 ?
//! ble  bad_length
//! tst  r1, #0xf      ; length & 15 == 0 ?
//! moveq r0, #0       ;   return 0 (valid)
//! bxeq lr
//! bad_length:
//! mov  r0, #3        ;   return 3
//! bx  lr
//! ```
//!
//! No deliberate deviations. Ghidra's 52-byte extent and zero outgoing calls
//! match the raw words; the `ble` is signed, so negative lengths (including
//! `i32::MIN`) also yield 3.

/// The span described by `handle`/`length` is usable.
pub const SPAN_OK: u32 = 0;
/// `handle` was null.
pub const SPAN_ERR_NULL_HANDLE: u32 = 2;
/// `length` was non-positive or not a multiple of 16.
pub const SPAN_ERR_BAD_LENGTH: u32 = 3;

/// validate_span — original: `FUN_08027b08` @ 0x08027b08 (52 bytes).
///
/// Validates a `(handle, length)` span, propagating `pending_error` first.
/// See the module header for the return-code contract.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn validate_span(handle: u32, length: i32, pending_error: u32) -> u32 {
    if pending_error != 0 {
        return pending_error;
    }
    if handle == 0 {
        return SPAN_ERR_NULL_HANDLE;
    }
    if length > 0 && length & 0xf == 0 {
        return SPAN_OK;
    }
    SPAN_ERR_BAD_LENGTH
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference truth table derived directly from the ARM listing.
    fn reference(handle: u32, length: i32, pending_error: u32) -> u32 {
        if pending_error != 0 {
            pending_error
        } else if handle == 0 {
            2
        } else if length <= 0 || length & 0xf != 0 {
            3
        } else {
            0
        }
    }

    #[test]
    fn pending_error_passes_through_verbatim() {
        assert_eq!(validate_span(0, 0, 1), 1);
        assert_eq!(validate_span(0xdead_beef, 16, 7), 7);
        assert_eq!(validate_span(0, -4, u32::MAX), u32::MAX);
    }

    #[test]
    fn null_handle_yields_code_2() {
        assert_eq!(validate_span(0, 16, 0), SPAN_ERR_NULL_HANDLE);
        assert_eq!(validate_span(0, 0, 0), SPAN_ERR_NULL_HANDLE);
        assert_eq!(validate_span(0, -32, 0), SPAN_ERR_NULL_HANDLE);
    }

    #[test]
    fn positive_aligned_length_is_valid() {
        assert_eq!(validate_span(1, 16, 0), SPAN_OK);
        assert_eq!(validate_span(0x0800_0000, 0x1000, 0), SPAN_OK);
        assert_eq!(validate_span(u32::MAX, i32::MAX & !0xf, 0), SPAN_OK);
    }

    #[test]
    fn bad_lengths_yield_code_3() {
        // Zero, negative, and misaligned-but-positive lengths all fail.
        assert_eq!(validate_span(1, 0, 0), SPAN_ERR_BAD_LENGTH);
        assert_eq!(validate_span(1, -16, 0), SPAN_ERR_BAD_LENGTH);
        assert_eq!(validate_span(1, i32::MIN, 0), SPAN_ERR_BAD_LENGTH);
        assert_eq!(validate_span(1, 1, 0), SPAN_ERR_BAD_LENGTH);
        assert_eq!(validate_span(1, 15, 0), SPAN_ERR_BAD_LENGTH);
        assert_eq!(validate_span(1, 17, 0), SPAN_ERR_BAD_LENGTH);
        assert_eq!(validate_span(1, 0x7fff_ffff, 0), SPAN_ERR_BAD_LENGTH);
    }

    #[test]
    fn matches_reference_over_sweep() {
        for &handle in &[0u32, 1, 0x0800_0000, u32::MAX] {
            for &length in &[
                i32::MIN,
                -17,
                -16,
                -1,
                0,
                1,
                15,
                16,
                17,
                32,
                0x7fff_fff0,
                i32::MAX,
            ] {
                for &err in &[0u32, 1, 2, 3, u32::MAX] {
                    assert_eq!(
                        validate_span(handle, length, err),
                        reference(handle, length, err),
                        "handle={handle:#x} length={length} err={err:#x}"
                    );
                }
            }
        }
    }
}
