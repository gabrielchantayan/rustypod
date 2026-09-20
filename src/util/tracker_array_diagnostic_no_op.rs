//! An empty Tracker-array diagnostic target retained as a distinct hookable entry.

/// `tracker_array_diagnostic_no_op` — retailOS `FUN_083d48f8` @ **0x083d48f8**
/// (4 bytes exactly; true extent `0x083d48f8..0x083d48fc`; the separately
/// linked next function begins at `0x083d48fc`).
///
/// Raw ARM is exactly `bx lr`: it neither reads its diagnostic arguments nor
/// changes memory, and retains the incoming `r0` value. Decoding the full
/// decrypted image finds three direct inbound plain unconditional `bl` calls
/// (`0x081061c4`, `0x083d4a04`, and `0x083d4b28`) and no predicated direct
/// `bl` calls. Its callers pass Tracker-array diagnostic formatting arguments
/// after allocation, relocation, and destruction work. Algorithm: return
/// immediately without emitting a diagnostic or accessing its arguments.
///
/// Deliberate deviations: the host implementation returns `context` explicitly
/// so tests can verify the ARM `r0` pass-through; the ARM target is naked and
/// uses the original single instruction.
///
/// # Safety
///
/// `context` is not accessed and may be null.
#[cfg(all(target_os = "none", target_arch = "arm"))]
#[unsafe(naked)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tracker_array_diagnostic_no_op(_context: *mut u8) -> *mut u8 {
    core::arch::naked_asm!("bx lr");
}

/// Host-callable equivalent of the empty Tracker-array diagnostic target.
#[cfg(not(all(target_os = "none", target_arch = "arm")))]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tracker_array_diagnostic_no_op(context: *mut u8) -> *mut u8 {
    context
}

#[cfg(test)]
mod tests {
    use super::tracker_array_diagnostic_no_op;

    #[test]
    fn preserves_non_null_context_without_mutating_it() {
        let mut context = [0x11, 0x22, 0x33, 0x44];
        let pointer = context.as_mut_ptr();

        let returned = unsafe { tracker_array_diagnostic_no_op(pointer) };

        assert_eq!(returned, pointer);
        assert_eq!(context, [0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn accepts_a_null_context() {
        assert_eq!(unsafe { tracker_array_diagnostic_no_op(core::ptr::null_mut()) }, core::ptr::null_mut());
    }
}
