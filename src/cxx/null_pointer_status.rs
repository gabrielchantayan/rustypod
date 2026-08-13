//! `cxx_null_pointer_status` — original: `FUN_08027940` @ 0x08027940
//! (16 bytes).
//!
//! Source: `ipod-decomp/decomp/c/001/08027940_FUN_08027940.c`.
//!
//! Leaf status helper: it compares its pointer-shaped argument with null and
//! returns status 4 when it is null, otherwise 0. The raw ARM is `cmp r0,#0`,
//! followed by conditional moves for those two values; it performs no memory
//! access. Recovered callers use the result as a status-derived byte, so the
//! pointer's pointee type is intentionally not assumed.

/// cxx_null_pointer_status — original: `FUN_08027940` @ 0x08027940
/// (16 bytes).
///
/// Returns the retailOS null-argument status: 4 for a null pointer and 0 for
/// every non-null pointer. The argument is only compared, never dereferenced.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_null_pointer_status(pointer: *const u8) -> u32 {
    if pointer.is_null() { 4 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_pointer_returns_status_four() {
        assert_eq!(unsafe { cxx_null_pointer_status(core::ptr::null()) }, 4);
    }

    #[test]
    fn non_null_pointer_returns_success_status() {
        let value = 0u8;
        assert_eq!(unsafe { cxx_null_pointer_status(&value) }, 0);
    }
}
