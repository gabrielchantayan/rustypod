//! An empty cleanup target used before fatal-error termination.

/// `fatal_cleanup_no_op` — retailOS `FUN_0815556c` @ **0x0815556c** (4 bytes
/// exactly; true extent `0x0815556c..0x08155570`; the separately linked next
/// function begins at `0x08155570`).
///
/// Raw ARM is exactly `bx lr`: it neither reads the cleanup object nor changes
/// memory, and retains the incoming `r0` value. Decoding the full decrypted
/// image finds four direct inbound plain unconditional `bl` calls
/// (`0x081c2744`, `0x081c2f74`, `0x081c3674`, and `0x081c4470`) and no
/// predicated direct `bl` calls. Each caller invokes it with a non-null cleanup
/// object immediately before the non-returning fatal-error handler. Algorithm:
/// return immediately without cleaning up the object.
///
/// Deliberate deviations: the host implementation returns `object` explicitly
/// so tests can verify the ARM `r0` pass-through; the ARM target is naked and
/// uses the original single instruction.
///
/// # Safety
///
/// `object` is not accessed and may be null.
#[cfg(all(target_os = "none", target_arch = "arm"))]
#[unsafe(naked)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fatal_cleanup_no_op(_object: *mut u8) -> *mut u8 {
    core::arch::naked_asm!("bx lr");
}

/// Host-callable equivalent of the empty fatal cleanup target.
#[cfg(not(all(target_os = "none", target_arch = "arm")))]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fatal_cleanup_no_op(object: *mut u8) -> *mut u8 {
    object
}

#[cfg(test)]
mod tests {
    use super::fatal_cleanup_no_op;

    #[test]
    fn preserves_a_non_null_cleanup_object_without_mutating_it() {
        let mut object = [0x11, 0x22, 0x33, 0x44];
        let pointer = object.as_mut_ptr();

        let returned = unsafe { fatal_cleanup_no_op(pointer) };

        assert_eq!(returned, pointer);
        assert_eq!(object, [0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn accepts_a_null_cleanup_object() {
        assert_eq!(unsafe { fatal_cleanup_no_op(core::ptr::null_mut()) }, core::ptr::null_mut());
    }
}
