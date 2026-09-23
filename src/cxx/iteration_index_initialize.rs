//! `iteration_index_initialize` — original: `FUN_081f3fe8` @ `0x081f3fe8` (8 bytes).
//!
//! Raw `osos.dec` decodes the exact two-instruction A32 body as `strb r1,[r0]`
//! and `bx lr`; the next separately linked function begins at `0x081f3ff0`.
//! Full-image aligned A32 decoding finds three inbound plain BL calls and zero
//! predicated BL forms. The leaf has no calls.
//!
//! Algorithm: store the low byte of the iteration index at its supplied
//! address. Deliberate deviations: none.

/// Initializes the one-byte iteration index used by the adjacent range reader.
///
/// The original issues an unchecked byte store, so NULL, dangling, and
/// unwritable pointers retain their target fault behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn iteration_index_initialize(index: *mut u8, value: u8) {
    unsafe { index.write(value) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_each_byte_value_without_touching_neighbors() {
        for value in [0, 1, 2, 3, 0x7f, 0x80, 0xff] {
            let mut bytes = [0xa5u8; 3];

            unsafe { iteration_index_initialize(bytes[1..].as_mut_ptr(), value) };

            assert_eq!(bytes, [0xa5, value, 0xa5], "value {value:#x}");
        }
    }
}
