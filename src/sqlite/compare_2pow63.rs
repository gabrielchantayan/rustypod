//! SQLite `compare2pow63` — original: `FUN_082c46b8` @ 0x082c46b8 (36 bytes).
//!
//! Raw ARM establishes the true extent as 0x082c46b8..0x082c46db: the
//! `pop {r4,pc}` at 0x082c46d8 ends the 32-byte instruction body, followed by
//! its 4-byte literal pool; the next independent function begins at
//! 0x082c46e0. It has one plain outbound `bl` (to `memcmp` @ 0x08030f64) and
//! no predicated `bl` calls. The two inbound call sites are plain `bl` at
//! 0x082c3fa8 and 0x0836f900.
//!
//! Compares the first 18 decimal digits against 2^63 / 10
//! (`"922337203685477580"`), then subtracts `'8'` from digit 19 only on a
//! prefix match. This is SQLite 3.5.9's `compare2pow63`, used by
//! `sqlite3Atoi64` to distinguish an in-range 19-digit magnitude.
//!
//! Deliberate deviation: the retail literal points at 0x088fd954, whose
//! read-only image content is skewed by +0xaed8; the port names the verified
//! bytes directly rather than modeling that image-address skew.

/// SQLite `compare2pow63`: compare a 19-digit decimal magnitude with 2^63.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_compare_2pow63(z_num: *const u8) -> i32 {
    const POW63_DIV10: &[u8; 18] = b"922337203685477580";

    let prefix_order = crate::libc::memcmp::memcmp(z_num, POW63_DIV10.as_ptr(), POW63_DIV10.len());
    if prefix_order == 0 {
        *z_num.add(18) as i32 - b'8' as i32
    } else {
        prefix_order
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn compares_the_signed_64_bit_boundary() {
        assert_eq!(unsafe { sqlite3_compare_2pow63(b"9223372036854775807".as_ptr()) }, -1);
        assert_eq!(unsafe { sqlite3_compare_2pow63(b"9223372036854775808".as_ptr()) }, 0);
        assert_eq!(unsafe { sqlite3_compare_2pow63(b"9223372036854775809".as_ptr()) }, 1);
    }

    #[test]
    fn returns_memcmp_difference_for_an_earlier_digit() {
        assert_eq!(unsafe { sqlite3_compare_2pow63(b"8223372036854775808".as_ptr()) }, -1);
        assert_eq!(unsafe { sqlite3_compare_2pow63(b"a223372036854775808".as_ptr()) }, 40);
    }
}
