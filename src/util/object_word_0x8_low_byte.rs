//! `object_word_0x8_low_byte` — original: `FUN_0829f23c` @ `0x0829f23c`
//! (12 bytes; `0x0829f23c..0x0829f247`).
//!
//! Raw `osos.dec` words establish the complete function: `ldr r0,[r0,#8];
//! and r0,r0,#0xff; bx lr`. The next separately linked function starts at
//! `0x0829f248`, confirming the three-word extent. It reads the aligned word
//! at offset 8 of an unchecked opaque object and returns its low byte.
//!
//! Decoding every ARM B/BL immediate in `osos.dec` finds three inbound direct
//! calls, all unconditional plain `bl`; there are no predicated calls. The
//! pointer remains unchecked, preserving the firmware's fault behavior.
//! Deliberate deviation: a volatile word load prevents LLVM from narrowing
//! the verified ARM `ldr` plus mask into a byte load.

/// Returns the low byte of the aligned word at offset 8 of `object`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.object_word_0x8_low_byte")]
#[inline(never)]
pub unsafe extern "C" fn object_word_0x8_low_byte(object: *const u32) -> u32 {
    core::ptr::read_volatile(object.add(2)) & 0xff
}

#[cfg(test)]
mod tests {
    use super::object_word_0x8_low_byte;

    #[test]
    fn returns_only_the_word_low_byte_at_offset_eight() {
        let object = [0x1122_3344u32, 0xaabb_ccdd, 0xdead_beefu32, 0x7788_99aa];

        assert_eq!(unsafe { object_word_0x8_low_byte(object.as_ptr()) }, 0xef);
    }

    #[test]
    fn handles_zero_and_maximum_low_bytes() {
        let mut object = [0u32; 3];
        assert_eq!(unsafe { object_word_0x8_low_byte(object.as_ptr()) }, 0);

        object[2] = 0xffff_ffff;
        assert_eq!(unsafe { object_word_0x8_low_byte(object.as_ptr()) }, 0xff);
    }
}
