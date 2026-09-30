/// char_traits_not_eof — original: `FUN_082a78c4` @ 0x082a78c4.
/// True size: 16 bytes; two inbound plain BLs, zero predicated BLs;
/// zero outbound BLs. The next independently called function is 0x082a78d4.
///
/// Load the aligned 32-bit integer character value. Return zero for EOF
/// (-1), otherwise preserve every bit. This is the char_traits::not_eof
/// operation used by the stream-buffer callers at 0x083d9318 and 0x083dab68.
/// Raw words: e5900000 e3700001 03a00000 e12fff1e.
/// No deliberate behavioral deviations; no input write or NULL check.
///
/// # Safety
/// `value` must point to one aligned, initialized, readable i32.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.char_traits_not_eof")]
#[inline(never)]
pub unsafe extern "C" fn char_traits_not_eof(value: *const i32) -> i32 {
    let value = value.read();
    if value == -1 { 0 } else { value }
}

#[cfg(test)]
mod tests {
    use super::char_traits_not_eof;

    #[test]
    fn eof_becomes_zero_without_modifying_input() {
        let eof = -1;
        assert_eq!(unsafe { char_traits_not_eof(&eof) }, 0);
        assert_eq!(eof, -1);
    }

    #[test]
    fn non_eof_preserves_full_word_including_negative_values() {
        for value in [i32::MIN, -65536, -256, -2, 0, 1, 127, 128, 255, 256, i32::MAX] {
            let input = value;
            assert_eq!(unsafe { char_traits_not_eof(&input) }, value);
            assert_eq!(input, value);
        }
    }
}
