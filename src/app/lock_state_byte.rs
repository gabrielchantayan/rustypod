//! `lock_state_byte_at_0xcc` — original: `FUN_081a6304` at load address
//! `0x081a6304` (8 bytes: `ldrb r0,[r0,#0xcc]; bx lr`). The next real
//! function begins at `0x081a630c`.
//!
//! Full-image raw A32 decoding finds three inbound plain `bl` calls
//! (`0x081099ac`, `0x0812fe84`, and `0x082306e4`) and no predicated `bl`
//! calls.
//!
//! Algorithm: return the byte at offset `0xcc` in the lock-state object. The
//! callers obtain that object from the shared state accessor before the call.
//!
//! # Deliberate deviations
//!
//! LLVM emits a standard frame setup and teardown instead of the stock leaf's
//! bare `bx lr`; it preserves the ABI result and performs the same load.
//! The field's role beyond its use as a lock-state gate is not established, so
//! the offset remains in the semantic symbol name rather than assigning an
//! unverified boolean meaning.

/// Reads the lock-state byte at target offset `0xcc`.
///
/// `lock_state` must point to a readable object containing that byte.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn lock_state_byte_at_0xcc(lock_state: *const u8) -> u8 {
    unsafe { core::ptr::read(lock_state.add(0xcc)) }
}

#[cfg(test)]
mod tests {
    use super::lock_state_byte_at_0xcc;

    #[test]
    fn returns_the_byte_at_the_target_offset_without_interpreting_it() {
        for value in [0, 1, 0x7f, 0x80, 0xff] {
            let mut lock_state = [0xa5_u8; 0xcd];
            lock_state[0xcc] = value;

            assert_eq!(unsafe { lock_state_byte_at_0xcc(lock_state.as_ptr()) }, value);
            assert!(lock_state[..0xcc].iter().all(|&byte| byte == 0xa5));
        }
    }
}
