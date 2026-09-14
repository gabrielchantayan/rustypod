//! Six-bit padded encoder used by retailOS.
//!
//! `base64_encode` — original: `FUN_0804a734` @ `0x0804a734`, 196 code
//! bytes plus the four-byte alphabet-address literal at `0x0804a7f8`; the
//! next independently linked function begins at `0x0804a7fc`. A complete
//! raw-image decode of every ARM B/BL word in `osos.dec` finds six inbound
//! calls, all unconditional `bl` instructions at `0x0804a824`, `0x0804a914`,
//! `0x0804a938`, `0x080ee6ec`, `0x080f3f24`, and `0x080f3f74`; there are no
//! predicated or tail-`b` callers.
//!
//! # Algorithm
//!
//! Groups positive signed byte counts into triples. Each triple becomes four
//! six-bit table lookups through the 64-byte alphabet at `0x0891fbb4`; a
//! one-byte tail emits `==`, and a two-byte tail emits one `=`. The encoder
//! appends a NUL byte after every result and returns the encoded-byte count.
//! A zero or negative count emits only that NUL and returns zero. The raw
//! alphabet is non-printable in several positions, so this port transcribes
//! its exact decrypted-image bytes rather than assuming a conventional ASCII
//! base64 alphabet.
//!
//! # Deliberate deviations
//!
//! None. The payload uses a static transcription of the stock alphabet in
//! place of its fixed firmware-memory address, with identical table bytes.

/// The 64-byte alphabet at `0x0891fbb4`, transcribed from `osos.dec`.
const BASE64_ALPHABET: [u8; 64] = [
    0x59, 0x5d, 0xec, 0xe1, 0xf4, 0xe9, 0xee, 0xf3, 0xed, 0xe1, 0xec, 0x6c, 0x80, 0x02, 0x63, 0xf3,
    0xf5, 0xf0, 0xe5, 0xf2, 0xe9, 0xef, 0x72, 0x80, 0x02, 0xe0, 0xee, 0xe7, 0xe9, 0xe1, 0xe3, 0xef,
    0xf0, 0xf4, 0xe9, 0x63, 0x80, 0x03, 0xeb, 0x62, 0x02, 0x59, 0x7b, 0x59, 0x85, 0xef, 0xf0, 0xef,
    0xed, 0xef, 0xe6, 0x6f, 0x80, 0x31, 0x0d, 0xf2, 0xe5, 0xf6, 0x65, 0x80, 0x01, 0x1f, 0x63, 0x04,
];

/// `base64_encode` — original: `FUN_0804a734` @ `0x0804a734` (196 code
/// bytes, six plain `bl` callers).
///
/// Encodes `length` source bytes from `input` into `output` with the stock
/// 64-byte alphabet, writes a trailing NUL, and returns the encoded-byte
/// count. `length` is signed: values at or below zero produce an empty C
/// string and return zero.
///
/// # Safety
///
/// `input` must point to at least `length` readable bytes when `length` is
/// positive. `output` must point to at least `4 * ceil(length / 3) + 1`
/// writable bytes. As in retailOS, overlapping ranges are not rejected and
/// can overwrite unread input in later groups.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn base64_encode(mut output: *mut u8, mut input: *const u8, mut length: i32) -> i32 {
    let mut encoded_length = 0;

    while length > 0 {
        let first = *input;
        let second = if length >= 2 { *input.add(1) } else { 0 };
        let third = if length >= 3 { *input.add(2) } else { 0 };

        *output = BASE64_ALPHABET[(first >> 2) as usize];
        *output.add(1) = BASE64_ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize];
        *output.add(2) = if length == 1 {
            b'='
        } else {
            BASE64_ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize]
        };
        *output.add(3) = if length < 3 {
            b'='
        } else {
            BASE64_ALPHABET[(third & 0x3f) as usize]
        };

        encoded_length += 4;
        input = input.add(3);
        output = output.add(4);
        length -= 3;
    }

    *output = 0;
    encoded_length
}

#[cfg(test)]
mod tests {
    use super::base64_encode;

    fn encode(input: &[u8], length: i32) -> (i32, [u8; 17]) {
        let mut output = [0xa5; 17];
        let encoded_length = unsafe { base64_encode(output.as_mut_ptr(), input.as_ptr(), length) };
        (encoded_length, output)
    }

    #[test]
    fn encodes_complete_and_partial_groups_with_stock_alphabet() {
        let cases: &[(&[u8], &[u8])] = &[
            (&[0x00], &[0x59, 0x59, b'=', b'=', 0]),
            (&[0x00, 0x40], &[0x59, 0xf4, 0x59, b'=', 0]),
            (&[0xff, 0x00, 0x01], &[0x04, 0xed, 0x59, 0x5d, 0]),
            (&[0x00, 0x40, 0x80, 0xff], &[0x59, 0xf4, 0xec, 0x59, 0x04, 0xed, b'=', b'=', 0]),
        ];

        for &(input, expected) in cases {
            let (encoded_length, output) = encode(input, input.len() as i32);
            assert_eq!(encoded_length as usize, expected.len() - 1, "input: {input:02x?}");
            assert_eq!(&output[..expected.len()], expected, "input: {input:02x?}");
        }
    }

    #[test]
    fn zero_and_negative_lengths_only_write_terminator() {
        for length in [0, -1, i32::MIN] {
            let (encoded_length, output) = encode(&[0xde, 0xad, 0xbe], length);
            assert_eq!(encoded_length, 0, "length: {length}");
            assert_eq!(output[0], 0, "length: {length}");
            assert!(output[1..].iter().all(|&byte| byte == 0xa5), "length: {length}");
        }
    }
}
