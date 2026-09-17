//! Six-bit character lookup used by the 0x08274534 MIME Base64 encoder.
//!
//! `base64_table_char` — original: `FUN_08274458` @ `0x08274458`, 20 bytes
//! (five ARM words). The next independently linked function starts at
//! `0x08274470`. A whole-image raw A32 branch decode finds four inbound plain
//! `bl` calls and no predicated `bl` calls.
//!
//! # Algorithm
//!
//! Returns byte `index` from the 64-byte table fixed at `0x083ed338` when
//! `index < 64`; otherwise returns `b'?'` (`0x3f`).
//!
//! # Deliberate deviations
//!
//! The fixed firmware-memory table is transcribed as a Rust constant. The
//! table contains NUL bytes; they are intentional stock values.

const BASE64_TABLE: [u8; 64] = [
    0x78, 0x27, 0x2c, 0x55, 0x4c, 0x38, 0x2c, 0x58,
    0x32, 0x2c, 0x27, 0x72, 0x31, 0x31, 0x20, 0x3d,
    0x20, 0x30, 0x78, 0x27, 0x2c, 0x55, 0x4c, 0x38,
    0x2c, 0x2f, 0x4e, 0x29, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x00, 0x00, 0x2d, 0x2d, 0x20, 0x4d,
    0x6f, 0x72, 0x65, 0x20, 0x2d, 0x2d, 0x00, 0x00,
    0x0a, 0x20, 0x20, 0x23, 0x20, 0x20, 0x20, 0x4e,
    0x61, 0x6d, 0x65, 0x20, 0x20, 0x20, 0x20, 0x20,
];

/// Returns the stock table character for a six-bit value, or `?` outside it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn base64_table_char(index: u32) -> u8 {
    if index < BASE64_TABLE.len() as u32 {
        BASE64_TABLE[index as usize]
    } else {
        b'?'
    }
}

#[cfg(test)]
mod tests {
    use super::base64_table_char;

    #[test]
    fn returns_stock_values_at_table_boundaries() {
        assert_eq!(base64_table_char(0), b'x');
        assert_eq!(base64_table_char(15), b'=');
        assert_eq!(base64_table_char(27), b')');
        assert_eq!(base64_table_char(28), 0);
        assert_eq!(base64_table_char(32), b'\n');
        assert_eq!(base64_table_char(63), b' ');
    }

    #[test]
    fn rejects_values_outside_the_six_bit_range() {
        assert_eq!(base64_table_char(64), b'?');
        assert_eq!(base64_table_char(u32::MAX), b'?');
    }
}
