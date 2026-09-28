//! pointer_in_span_or_null — original: `FUN_0839bacc` @ 0x0839bacc (20 bytes;
//! 2 incoming `bl` call sites, both unconditional; no predicated `bl` calls).
//!
//! Returns `pointer` only when it lies in the half-open unsigned range
//! `[start, start + byte_len)`; otherwise returns zero. The ARM routine first
//! rejects pointers below `start`, then performs wrapping u32 addition and
//! rejects `start + byte_len <= pointer`. Thus a span whose end wraps does not
//! cover addresses after the wrap, deliberately matching the stock compare
//! sequence. No deliberate deviations.
//!
//! ```text
//! cmp   r0, r1
//! addcs r1, r1, r2
//! cmpcs r1, r0
//! movls r0, #0
//! bx    lr
//! ```

/// Returns `pointer` when it is strictly before the wrapping span end and not
/// below `start`; otherwise returns zero.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn pointer_in_span_or_null(pointer: u32, start: u32, byte_len: u32) -> u32 {
    if pointer < start || start.wrapping_add(byte_len) <= pointer {
        0
    } else {
        pointer
    }
}

#[cfg(test)]
mod tests {
    use super::pointer_in_span_or_null;

    #[test]
    fn accepts_the_half_open_span_interior() {
        assert_eq!(pointer_in_span_or_null(0x1000, 0x1000, 4), 0x1000);
        assert_eq!(pointer_in_span_or_null(0x1003, 0x1000, 4), 0x1003);
    }

    #[test]
    fn rejects_both_half_open_boundaries() {
        assert_eq!(pointer_in_span_or_null(0x0fff, 0x1000, 4), 0);
        assert_eq!(pointer_in_span_or_null(0x1004, 0x1000, 4), 0);
        assert_eq!(pointer_in_span_or_null(0x1000, 0x1000, 0), 0);
    }

    #[test]
    fn rejects_wrapping_span_even_before_the_wrapped_end() {
        assert_eq!(pointer_in_span_or_null(0xffff_fffe, 0xffff_fffe, 4), 0);
        assert_eq!(pointer_in_span_or_null(1, 0xffff_fffe, 4), 0);
    }
}
