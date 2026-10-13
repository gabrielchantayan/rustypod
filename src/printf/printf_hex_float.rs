//! Disabled hexadecimal float conversion — `FUN_083ed07c` @ **0x083ed07c**.
//!
//! True size: 4 bytes. Raw A32 word `0xe1a0f00e` is `mov pc, lr`;
//! the trap decoder starts at 0x083ed080 with `and r3, ip, #15`.
//! Whole-image raw decoding verifies one incoming plain BL (0x080347e8),
//! zero predicated BLs, and zero outgoing calls; no literal DATA references.
//!
//! Algorithm: the printf engine consumes an aligned double for `%a/%A`,
//! passes its state in r0, the conversion character in r1, and a pointer to
//! the double in r2. This body accesses nothing, emits nothing, and preserves
//! r0. It is neither a destructor nor a veneer. Deliberate deviations: unused
//! r1/r2 arguments are omitted; the ARM export retains the exact return word,
//! while the host implementation expresses the preserved state as a return.

use super::printf_helpers::PrintfState;

/// Return the state unchanged without accessing it or emitting a conversion.
/// NULL, dangling, and unaligned pointers are accepted.
#[cfg(target_os = "none")]
#[unsafe(naked)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn printf_hex_float(_state: *mut PrintfState) -> *mut PrintfState {
    core::arch::naked_asm!("mov pc, lr");
}

#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn printf_hex_float(state: *mut PrintfState) -> *mut PrintfState {
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_null_unaligned_and_dangling_state_words() {
        for word in [0usize, 1, 0x0800_0001, 0xffff_ffff, usize::MAX] {
            let state = word as *mut PrintfState;
            assert_eq!(unsafe { printf_hex_float(state) }, state);
        }
    }

    #[test]
    fn leaves_state_storage_untouched() {
        let mut storage = [0xa5u32; 64];
        let before = storage;
        let state = storage.as_mut_ptr().cast();
        assert_eq!(unsafe { printf_hex_float(state) }, state);
        assert_eq!(storage, before);
    }
}
