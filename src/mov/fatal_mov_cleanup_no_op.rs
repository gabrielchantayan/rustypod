//! `fatal_mov_cleanup_no_op` — retailOS `FUN_08154048` @ **0x08154048**
//! (4 bytes exactly; true extent `0x08154048..0x0815404c`; the separately
//! linked next function begins at `0x0815404c`).
//!
//! Raw ARM is exactly `bx lr`: it neither reads the cleanup object nor changes
//! memory, and retains the incoming `r0` value. Decoding the full decrypted
//! image finds four direct inbound plain unconditional `bl` calls
//! (`0x081c2814`, `0x081c3034`, `0x081c3748`, and `0x081c4538`) and no
//! predicated direct `bl` calls. Each caller invokes it with an opaque MOV
//! cleanup object immediately before the non-returning fatal-error handler at
//! `0x082aad24`. Algorithm: return immediately without cleaning up the object.
//!
//! Deliberate deviations: the host implementation returns `object` explicitly
//! so tests can verify the ARM `r0` pass-through; the ARM target is naked and
//! uses the original single instruction.

/// Returns the MOV cleanup object unchanged without accessing it.
///
/// # Safety
///
/// `object` is not accessed and may be null, unaligned, or dangling.
#[cfg(all(target_os = "none", target_arch = "arm"))]
#[unsafe(naked)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fatal_mov_cleanup_no_op(_object: *mut u8) -> *mut u8 {
    core::arch::naked_asm!("bx lr");
}

/// Host-callable equivalent of the empty fatal cleanup target.
#[cfg(not(all(target_os = "none", target_arch = "arm")))]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fatal_mov_cleanup_no_op(object: *mut u8) -> *mut u8 {
    object
}

#[cfg(test)]
mod tests {
    use super::fatal_mov_cleanup_no_op;

    #[test]
    fn preserves_object_words_without_accessing_memory() {
        for object_word in [0usize, 1, 0x0800_0001, 0x08a2_55e4, usize::MAX] {
            let object = object_word as *mut u8;
            assert_eq!(unsafe { fatal_mov_cleanup_no_op(object) }, object, "object={object_word:#x}");
        }
    }

    #[test]
    fn does_not_mutate_a_valid_cleanup_object() {
        let mut object = [0xa5u8; 32];
        let before = object;
        let returned = unsafe { fatal_mov_cleanup_no_op(object.as_mut_ptr()) };

        assert_eq!(returned, object.as_mut_ptr());
        assert_eq!(object, before, "the bare return writes no object byte");
    }
}
