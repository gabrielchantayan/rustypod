//! Initializes proprietary cipher context metadata.
//!
//! `FUN_0802e910` @ `0x0802e910`: 52 executable bytes through
//! `0x0802e944`; two literal words precede the next function at `0x0802e94c`.
//! Verified raw A32: one outbound plain BL to `cipher_name_is_standard`,
//! two inbound plain BLs (0x0802a948, 0x0802a9b4), zero predicated BLs.
//! Writes mode/round count at +0xf0/+0xf4 before validating the name,
//! stores zero for STANDARD or auxiliary otherwise at +0xfc, then clears
//! only the byte at +0xf8. Returns the validator's low word left in r0.
//! Deliberate deviations: calls the existing Rust validator; explicit u32
//! return preserves r0 without exposing the incidental r1 value. Volatile
//! stores preserve ordering when the name aliases context storage.

use super::cipher_name::cipher_name_is_standard;

/// # Safety
/// `context` must be word-aligned and writable through byte 0xff; `name`
/// must remain a readable NUL-terminated string after the first two writes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn standard_cipher_initialize(
    context: *mut u32, mode: u32, round_count: u32, name: *const u8, auxiliary: u32,
) -> u32 {
    context.add(0xf0 / 4).write_volatile(mode);
    context.add(0xf4 / 4).write_volatile(round_count);
    let status = cipher_name_is_standard(name) as u32;
    context.add(0xfc / 4).write_volatile(if status == 0 { 0 } else { auxiliary });
    context.cast::<u8>().add(0xf8).write_volatile(0);
    status
}

#[cfg(test)]
mod tests {
    use super::standard_cipher_initialize;

    #[test]
    fn names_control_auxiliary_and_only_documented_fields_change() {
        for name in [b"STANDARD\0".as_slice(), b"standard\0", b"\0", b"STANDARDx\0", b"STANDARD\0ignored"] {
            for auxiliary in [0, 0xdead_beef, u32::MAX] {
                let mut context = [0xa5a5_a5a5u32; 65];
                let mut expected = context;
                let status = u32::from(&name[..name.iter().position(|&b| b == 0).unwrap()] != b"STANDARD");
                expected[60] = u32::MAX;
                expected[61] = 0;
                expected[62] = 0xa5a5_a500;
                expected[63] = if status == 0 { 0 } else { auxiliary };
                let returned = unsafe { standard_cipher_initialize(context.as_mut_ptr(), u32::MAX, 0, name.as_ptr(), auxiliary) };
                assert_eq!(returned, status);
                assert_eq!(context, expected);
            }
        }
    }

    #[test]
    fn validates_after_mode_and_round_count_writes() {
        let mut context = [0xa5a5_a5a5u32; 65];
        context[62] = 0;
        let pointer = context.as_mut_ptr();
        let returned = unsafe { standard_cipher_initialize(pointer,
            u32::from_le_bytes(*b"STAN"), u32::from_le_bytes(*b"DARD"),
            pointer.add(60).cast(), 0xdead_beef) };
        assert_eq!(returned, 0);
        assert_eq!(context[63], 0);
        assert_eq!(&context[..60], &[0xa5a5_a5a5; 60]);
        assert_eq!(context[64], 0xa5a5_a5a5);
    }
}
