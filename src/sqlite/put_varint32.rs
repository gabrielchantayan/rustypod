//! SQLite's multibyte `u32` varint encoder.
//!
//! `put_varint32` — original: `FUN_083817c0` @ 0x083817c0 (44 bytes;
//! 2 plain `bl` call sites, 0 predicated `bl` call sites). The 11-instruction
//! function keeps the two-byte case inline and tail-branches to
//! [`put_varint`] at 0x083816ec for values >= 0x4000.
//!
//! Algorithm: write the big-endian base-128 representation. Values below
//! 0x4000 always use two bytes (`0x80 | value >> 7`, `value & 0x7f`); larger
//! `u32` values use three through five bytes, with the continuation bit on
//! every byte except the last. This matches the stock function's caller
//! contract: callers inline the one-byte case before calling it.
//!
//! Deliberate deviation: the Rust call replaces the stock tail branch; both
//! paths produce the same byte sequence and byte-count return value.

use super::put_varint::put_varint;

/// put_varint32 — original: `FUN_083817c0` @ 0x083817c0 (44 bytes;
/// 2 plain `bl` call sites, 0 predicated `bl` call sites).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn put_varint32(out: *mut u8, value: u32) -> u32 {
    if value < 0x4000 {
        *out = 0x80 | (value >> 7) as u8;
        *out.add(1) = (value & 0x7f) as u8;
        return 2;
    }

    put_varint(out, value as u64)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn reference(value: u32) -> ([u8; 5], usize) {
        let mut out = [0u8; 5];
        if value < 0x4000 {
            out[0] = 0x80 | (value >> 7) as u8;
            out[1] = (value & 0x7f) as u8;
            return (out, 2);
        }
        let mut groups = [0u8; 5];
        let mut count = 0;
        let mut remaining = value;
        loop {
            groups[count] = (remaining & 0x7f) as u8;
            remaining >>= 7;
            count += 1;
            if remaining == 0 {
                break;
            }
        }
        for index in 0..count {
            out[index] = groups[count - index - 1] | if index + 1 < count { 0x80 } else { 0 };
        }
        (out, count)
    }

    #[test]
    fn encodes_stock_two_byte_case_including_callers_guarded_values() {
        for value in [0, 0x7f, 0x80, 0x3fff] {
            let mut out = [0xa5; 6];
            let (expected, count) = reference(value);
            let written = unsafe { put_varint32(out.as_mut_ptr(), value) } as usize;
            assert_eq!(written, count, "{value:#x}");
            assert_eq!(&out[..written], &expected[..count], "{value:#x}");
            assert_eq!(out[written], 0xa5, "{value:#x}");
        }
    }

    #[test]
    fn encodes_every_u32_varint_width() {
        for value in [0x4000, 0x1f_ffff, 0x20_0000, 0x0fff_ffff, 0x1000_0000, u32::MAX] {
            let mut out = [0xa5; 6];
            let (expected, count) = reference(value);
            let written = unsafe { put_varint32(out.as_mut_ptr(), value) } as usize;
            assert_eq!(written, count, "{value:#x}");
            assert_eq!(&out[..written], &expected[..count], "{value:#x}");
            assert_eq!(out[written], 0xa5, "{value:#x}");
        }
    }
}
