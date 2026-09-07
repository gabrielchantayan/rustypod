//! `tagged_pointer_init` — original: `FUN_08166a2c` @ 0x08166a2c (12 bytes).
//!
//! Raw ARM extent is three instruction words, 0x08166a2c..0x08166a38: `strb
//! r1, [r0]`; `mov r1, #0`; `str r1, [r0, #4]`; `bx lr`. The separately
//! linked empty destructor starts at 0x08166a3c, so Ghidra's reported 16-byte
//! extent includes that sibling function. Decoding every ARM B/BL word in
//! `osos.dec` finds exactly 21 direct call sites: all are unconditional plain
//! `bl`, with no predicated forms or plain-B tail calls. The target appears in
//! no aligned image data word, so it is statically bound rather than a virtual
//! dispatch entry.
//!
//! # Algorithm
//!
//! Store the low byte of `tag` at offset +0, clear the aligned pointer-sized
//! target word at offset +4, then return `this` unchanged in r0. The three
//! intervening bytes are deliberately preserved. There is no NULL or alignment
//! guard. Deliberate deviations: none; `tag` is represented as `u32` because
//! the ARM body accepts the whole argument register and discards its high bits.

/// Initializes an 8-byte tagged-pointer record and returns `this` unchanged.
///
/// # Safety
///
/// `this` must be valid and 4-byte aligned for writes at offsets +0 and +4.
/// The original makes both stores unconditionally and requires at least eight
/// writable bytes. It preserves bytes +1 through +3 and ignores tag bits 8..31.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tagged_pointer_init")]
#[inline(never)]
pub unsafe extern "C" fn tagged_pointer_init(this: *mut u8, tag: u32) -> *mut u8 {
    unsafe {
        this.write(tag as u8);
        this.add(4).cast::<u32>().write(0);
    }
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_only_the_low_tag_byte_and_clears_the_pointer_word() {
        let mut words = [0xfeed_faceu32, 0x4433_2211, 0xa5a5_5a5a, 0xdead_beef];
        let record = unsafe { words.as_mut_ptr().add(1).cast::<u8>() };

        let returned = unsafe { tagged_pointer_init(record, 0x7e91_c2ff) };

        assert_eq!(returned, record);
        assert_eq!(words, [0xfeed_face, 0x4433_22ff, 0, 0xdead_beef]);
    }

    #[test]
    fn zero_tag_does_not_change_the_padding_bytes() {
        let mut words = [0x1122_3344u32, 0x89ab_cdef];
        let record = words.as_mut_ptr().cast::<u8>();

        unsafe { tagged_pointer_init(record, 0) };

        assert_eq!(words, [0x1122_3300, 0]);
    }
}
