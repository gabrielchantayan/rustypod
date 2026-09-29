//! Submit a retail control code — original: `FUN_0836e224` @ `0x0836e224` (16 bytes).
//!
//! Raw `osos.dec` words establish the exact A32 extent
//! `0x0836e224..0x0836e234`; `0x0836e234` begins the next real function.
//! It contains no `bl` instruction (plain or predicated); two plain `bl`
//! call sites target it. The function complements `code`, retains its low
//! byte, loads register 3, then tail-branches to
//! [`crate::drivers::i2c::i2c_0x39_write_register`].
//!
//! Deviation: Rust makes an ordinary call to the existing port instead of the
//! stock tail branch. The callee's status remains the ABI return value.

#[inline(always)]
unsafe fn submit_code_with(
    code: u32,
    write_register: unsafe extern "C" fn(u32, u32) -> i32,
) -> i32 {
    unsafe { write_register(3, (!code) & 0xff) }
}

/// Writes the low-byte complement of `code` to register 3 on I2C slave 0x39.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn retail_control_submit_code(code: u32) -> i32 {
    unsafe { submit_code_with(code, crate::drivers::i2c::i2c_0x39_write_register) }
}

#[cfg(test)]
mod tests {
    use super::*;

    static mut REGISTER: u32 = 0;
    static mut VALUE: u32 = 0;

    unsafe extern "C" fn write_register(register: u32, value: u32) -> i32 {
        unsafe { REGISTER = register; VALUE = value; }
        -7
    }

    #[test]
    fn complements_only_the_low_input_byte_and_preserves_write_status() {
        for (code, expected) in [
            (0, 0xff),
            (0xff, 0),
            (0x1234_5678, 0x87),
            (0xffff_ff00, 0xff),
            (0xffff_ffff, 0),
        ] {
            unsafe {
                REGISTER = 0; VALUE = 0;
                assert_eq!(submit_code_with(code, write_register), -7);
                assert_eq!(REGISTER, 3);
                assert_eq!(VALUE, expected);
            }
        }
    }
}
