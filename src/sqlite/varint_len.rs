//! SQLite's base-128 varint length helper.
//!
//! `varint_len` — original: `FUN_083867b8` @ 0x083867b8 (64 bytes,
//! 0x083867b8..0x083867f8; 3 plain `bl` call sites and no predicated `bl`
//! call sites, decoded from `osos.dec`).
//!
//! Algorithm: shift the input right by seven bits and count groups until it
//! becomes zero, with the ninth group as the maximum. The ARM body carries the
//! input in a low/high u32 pair; this u64 implementation is bit-equivalent.
//!
//! Deliberate deviations: none.

/// `sqlite3VarintLen`: return the number of bytes required to encode `value`
/// as SQLite's base-128 varint (1..=9).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn varint_len(mut value: u64) -> u32 {
    let mut len = 0;
    loop {
        value >>= 7;
        len += 1;
        if value == 0 || len == 9 {
            return len;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn counts_each_base_128_boundary() {
        let cases = [
            (0, 1),
            (0x7f, 1),
            (0x80, 2),
            (0x3fff, 2),
            (0x4000, 3),
            ((1u64 << 56) - 1, 8),
            (1u64 << 56, 9),
            (u64::MAX, 9),
        ];

        for (value, expected) in cases {
            assert_eq!(varint_len(value), expected, "value {value:#x}");
        }
    }
}
