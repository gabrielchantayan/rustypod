//! `ber_tlv_encoded_size` — original: `FUN_0803b5a8` at load address
//! `0x0803b5a8` (**72 bytes**, `0x0803b5a8..0x0803b5f0`; all code). Raw
//! `osos.dec` disassembly establishes that the separately linked successor
//! starts with `push {r4,r5,r6,lr}` at `0x0803b5f0`. Decoding every aligned
//! ARM B/BL immediate in the complete image finds **six** direct inbound
//! `bl` call sites, all unconditional: `0x0803b2f0`, `0x0803ba0c`,
//! `0x0803ba2c`, `0x0803bae4`, `0x0805f3b4`, and `0x080bfb84`. There are no
//! predicated calls or direct tail branches.
//!
//! Computes the total BER TLV size emitted by the companion encoder: content
//! length, the tag byte and any high-tag-number base-128 bytes, then either a
//! short or long-form length field. A zero-length indefinite constructed value
//! (`container_kind == 2`) reserves the two end-of-contents bytes. The retail
//! routine uses signed comparisons and wrapping 32-bit arithmetic throughout;
//! this port preserves both, including negative and overflowed inputs. There
//! are no deliberate deviations.

/// Returns the number of bytes required for one BER TLV value.
///
/// `container_kind == 2` denotes the encoder's indefinite constructed form;
/// other values affect this routine only through that comparison. The retail
/// implementation does not validate its signed length or tag-number inputs.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ber_tlv_encoded_size")]
#[inline(never)]
pub extern "C" fn ber_tlv_encoded_size(
    container_kind: i32,
    mut content_length: i32,
    mut tag_number: i32,
) -> i32 {
    let mut size = content_length.wrapping_add(1);

    if tag_number >= 31 {
        while tag_number > 0 {
            tag_number >>= 7;
            size = size.wrapping_add(1);
        }
    }

    if content_length == 0 && container_kind == 2 {
        size = size.wrapping_add(2);
    }

    size = size.wrapping_add(1);
    if content_length > 127 {
        while content_length > 0 {
            content_length >>= 8;
            size = size.wrapping_add(1);
        }
    }

    size
}

#[cfg(test)]
mod tests {
    use super::ber_tlv_encoded_size;

    #[test]
    fn sizes_short_and_high_tag_headers() {
        assert_eq!(ber_tlv_encoded_size(0, 0, 0), 2);
        assert_eq!(ber_tlv_encoded_size(1, 127, 30), 129);
        assert_eq!(ber_tlv_encoded_size(1, 0, 31), 3);
        assert_eq!(ber_tlv_encoded_size(1, 0, 127), 3);
        assert_eq!(ber_tlv_encoded_size(1, 0, 128), 4);
        assert_eq!(ber_tlv_encoded_size(1, 0, 16_383), 4);
        assert_eq!(ber_tlv_encoded_size(1, 0, 16_384), 5);
    }

    #[test]
    fn sizes_short_and_long_form_lengths() {
        assert_eq!(ber_tlv_encoded_size(0, 127, 0), 129);
        assert_eq!(ber_tlv_encoded_size(0, 128, 0), 131);
        assert_eq!(ber_tlv_encoded_size(0, 255, 0), 258);
        assert_eq!(ber_tlv_encoded_size(0, 256, 0), 260);
        assert_eq!(ber_tlv_encoded_size(0, 65_535, 31), 65_540);
    }

    #[test]
    fn indefinite_constructed_empty_value_includes_end_of_contents() {
        assert_eq!(ber_tlv_encoded_size(2, 0, 0), 4);
        assert_eq!(ber_tlv_encoded_size(2, 0, 31), 5);
        assert_eq!(ber_tlv_encoded_size(1, 0, 31), 3);
    }

    #[test]
    fn signed_and_wrapping_inputs_follow_arm_conditions() {
        assert_eq!(ber_tlv_encoded_size(2, -1, -1), 1);
        assert_eq!(ber_tlv_encoded_size(0, i32::MAX, 0), -2_147_483_643);
        assert_eq!(ber_tlv_encoded_size(0, 0, i32::MAX), 7);
    }
}
