//! `always_succeeds` — original: `FUN_081b11f8` @ `0x081b11f8` (8 bytes;
//! true extent `0x081b11f8..0x081b1200`, followed by the distinct predicate
//! `FUN_081b1200`).
//!
//! Raw ARM is `mov r0,#1; bx lr`. Decoding every ARM B/BL word in
//! `work/firmware/osos.dec` finds five direct call sites, all plain
//! unconditional `bl` (`0x080db820`, `0x08167288`, `0x081af580`,
//! `0x081c86a8`, and `0x08201a3c`); there are no predicated `bl` forms.
//! It unconditionally returns the successful nonzero predicate value and
//! neither reads arguments nor changes memory. Deliberate deviations: none.

/// Returns the stock successful predicate value, one.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn always_succeeds() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::always_succeeds;

    #[test]
    fn returns_the_stock_success_value() {
        assert_eq!(always_succeeds(), 1);
    }
}
