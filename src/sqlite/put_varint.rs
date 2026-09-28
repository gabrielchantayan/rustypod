//! SQLite's `u64` varint encoder.
//!
//! `put_varint` — original: `FUN_083816ec` @ 0x083816ec (212 bytes;
//! 2 plain `bl` call sites, 0 predicated `bl` call sites). Raw osos.dec
//! words establish the body through `bx lr` at 0x083817bc; the next real
//! function begins at 0x083817c0.
//!
//! Algorithm: encode values below 2^56 as big-endian base-128 groups, with
//! the continuation bit set on every group except the last. Values with a
//! nonzero top byte use SQLite's nine-byte form: eight continuation groups
//! followed by the low byte.
//!
//! Deliberate deviations: none.

/// Encode `value` in SQLite's big-endian varint format and return its length.
///
/// Original: `FUN_083816ec` @ 0x083816ec.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn put_varint(out: *mut u8, value: u64) -> u32 {
    if value >> 56 != 0 {
        *out.add(8) = value as u8;
        for index in 0..8 {
            *out.add(index) = ((value >> ((7 - index) * 7 + 8)) as u8 & 0x7f) | 0x80;
        }
        return 9;
    }

    let mut groups = [0u8; 8];
    let mut count = 0;
    let mut remaining = value;
    loop {
        groups[count] = (remaining & 0x7f) as u8;
        count += 1;
        remaining >>= 7;
        if remaining == 0 {
            break;
        }
    }
    for index in 0..count {
        *out.add(index) = groups[count - index - 1] | if index + 1 < count { 0x80 } else { 0 };
    }
    count as u32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn reference(value: u64) -> ([u8; 9], usize) {
        let mut encoded = [0u8; 9];
        if value >> 56 != 0 {
            for index in 0..8 {
                encoded[index] = ((value >> ((7 - index) * 7 + 8)) as u8 & 0x7f) | 0x80;
            }
            encoded[8] = value as u8;
            return (encoded, 9);
        }

        let mut count = 1;
        while value >= (1u64 << (count * 7)) {
            count += 1;
        }
        for index in 0..count {
            encoded[index] = ((value >> ((count - index - 1) * 7)) as u8 & 0x7f)
                | if index + 1 < count { 0x80 } else { 0 };
        }
        (encoded, count)
    }

    #[test]
    fn encodes_each_base_128_width_and_boundaries() {
        for value in [0, 1, 0x7f, 0x80, 0x3fff, 0x4000, 0x1f_ffff, 0x20_0000,
                      0x0f_ff_ff_ff_ff_ff_ff, 0x10_00_00_00_00_00_00] {
            let (expected, length) = reference(value);
            let mut actual = [0xa5u8; 10];
            let written = unsafe { put_varint(actual.as_mut_ptr(), value) } as usize;
            assert_eq!(written, length, "value {value:#x}");
            assert_eq!(&actual[..written], &expected[..length], "value {value:#x}");
            assert_eq!(actual[written], 0xa5, "value {value:#x}");
        }
    }

    #[test]
    fn encodes_nine_byte_values_without_losing_low_byte() {
        for value in [0x01_00_00_00_00_00_00_00, 0x80_00_00_00_00_00_00_00, u64::MAX] {
            let (expected, length) = reference(value);
            let mut actual = [0u8; 9];
            assert_eq!(unsafe { put_varint(actual.as_mut_ptr(), value) }, length as u32);
            assert_eq!(actual, expected, "value {value:#x}");
        }
    }
}
