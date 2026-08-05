//! `ui_operation_unavailable` — original: `FUN_08005f10` @ `0x08005f10` (8 bytes).
//!
//! The ARM leaf executes `mvn r0, #0; bx lr`: it consumes no arguments or
//! state and returns the signed error sentinel `-1` in r0. No direct callers
//! survive in the retailOS image, so the name describes that complete,
//! observable ABI contract.
//!
//! Deviations: none.

/// Returns the UI operation-unavailable sentinel.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn ui_operation_unavailable() -> i32 {
    -1
}

#[cfg(test)]
mod tests {
    use super::ui_operation_unavailable;

    #[test]
    fn returns_the_signed_all_bits_set_error_sentinel() {
        assert_eq!(ui_operation_unavailable(), -1);
        assert_eq!(ui_operation_unavailable() as u32, u32::MAX);
    }
}
