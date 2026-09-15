//! `tagged_header_low_bits` — original: `FUN_08164ec4` @ `0x08164ec4`
//! (20 bytes; `0x08164ec4..0x08164ed8`).
//!
//! Raw ARM is `ldrb r0,[r0]; and r0,r0,#3; cmp r0,#3; bxls lr; bl
//! 0x08030f44`. The mask confines r0 to 0..=3, so the unsigned-lower-or-same
//! return is always taken and the fatal call is unreachable. It returns the
//! low two bits of the tagged header's first byte. The next separately linked
//! function begins at `0x08164ed8`, confirming the five-word extent.
//!
//! Decoding every ARM B/BL immediate in `osos.dec` finds five inbound direct
//! calls, all unconditional plain `bl` (0x08163ec4, 0x08164a5c, 0x08164ae4,
//! 0x08164e2c, and 0x08164ee0); there are no predicated calls. Deliberate
//! deviations: the provably unreachable compare and fatal call are omitted.

/// tagged_header_low_bits — original: `FUN_08164ec4` @ `0x08164ec4`
/// (20 bytes; 5 direct plain-`bl` call sites).
///
/// Returns bits [1:0] of the tagged header's first byte. The ARM `ldrb`
/// zero-extends this value before returning it in r0.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tagged_header_low_bits")]
#[inline(never)]
pub unsafe extern "C" fn tagged_header_low_bits(header: *const u8) -> u32 {
    (*header & 3) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_low_two_bits_for_all_header_byte_values() {
        for header_byte in 0u8..=u8::MAX {
            assert_eq!(
                unsafe { tagged_header_low_bits(&header_byte) },
                (header_byte & 3) as u32,
                "header_byte={header_byte:#04x}",
            );
        }
    }

    #[test]
    fn ignores_high_tagged_header_bits() {
        for header_byte in [0x00, 0x03, 0x80, 0x8f, 0xff] {
            assert_eq!(
                unsafe { tagged_header_low_bits(&header_byte) },
                (header_byte & 3) as u32,
            );
        }
    }
}
