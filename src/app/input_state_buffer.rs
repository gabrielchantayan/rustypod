//! Fixed input-state buffer accessor — original: `FUN_0819ccec` @
//! 0x0819ccec. True extent: 12 bytes, comprising `ldr r0, [pc]`, `bx lr`,
//! and the literal 0x08a7794c at 0x0819ccf4; the next function starts at
//! 0x0819ccf8. Whole-image ARM decoding finds two inbound plain BLs at
//! 0x08112ac0 and 0x081139d0, zero predicated BLs; no outbound calls.
//!
//! Return the address of the input-state buffer, not the word stored there.
//! Consumers examine input flags at +4+selector and +0x73. The sibling input
//! transition routine updates the leading counter and those flags, then
//! dispatches key-down/key-up messages. No allocation, validation, or memory
//! access occurs here. Incoming registers are unused. Deliberate deviations:
//! none; hosts also receive the firmware address and must not dereference it.

/// Return the fixed firmware input-state buffer without accessing its memory.
/// Dereferencing the result requires the original firmware RAM mapping.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn input_state_buffer_get() -> *mut u8 {
    0x08a7_794cusize as *mut u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_buffer_address_not_literal_pool_or_buffer_contents() {
        // Reference: e59f0000 loads the literal at PC+8, e12fff1e returns it.
        // Host execution without a firmware mapping also proves no dereference.
        let literal = u32::from_le_bytes([0x4c, 0x79, 0xa7, 0x08]);
        assert_eq!(input_state_buffer_get() as usize, literal as usize);
    }
}
