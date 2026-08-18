//! The serial-type payload-length lookup — how the record layer knows
//! how many bytes one packed field occupies before it decodes it.
//!
//! - `vdbe_serial_type_len` — original: `FUN_0838cfe8` @ 0x0838cfe8
//!   (24 bytes, 0x0838cfe8..0x0838d000; **9 `bl` call sites**, all
//!   unconditional, binary-scanned from osos.dec by decoding every
//!   branch word: 0x083883bc, 0x083884a0, 0x08388688, 0x0838b534,
//!   0x0838b5bc, 0x0838c918 — inside
//!   [`vdbe_record_compare`](super::vdbe_record_compare::vdbe_record_compare)
//!   — 0x0838cac0, 0x0838ce38 and 0x0838f5f0; no tail `b`). Upstream
//!   SQLite 3.5.9's `sqlite3VdbeSerialTypeLen` (vdbeaux.c): `u32
//!   sqlite3VdbeSerialTypeLen(u32 serial_type)`. functions.csv's 24
//!   bytes is exact: six instructions plus the 4-byte literal-pool
//!   word at 0x0838d000, then the next function's prologue
//!   (`mov r12,r1`) at 0x0838d004.
//!
//! ### Algorithm
//!
//! ```text
//! 0838cfe8:  cmp    r0,#0xc
//! 0838cfec:  ldrcc  r1,[0x838d000]   ; pool word: table base 0x088fce10
//! 0838cff0:  ldrbcc r0,[r1,r0]       ; t < 12:  aSize[t]
//! 0838cff4:  subcs  r0,r0,#0xc
//! 0838cff8:  movcs  r0,r0, lsr #0x1  ; t >= 12: (t - 12) >> 1
//! 0838cffc:  bx     lr
//! ```
//!
//! A serial type under 12 indexes the byte table whose base pointer
//! the literal-pool word at 0x0838d000 holds: **0x088fce10**, a
//! post-image address — reading the decrypted image there yields
//! unrelated bytes, but with the +0xaed8 image/runtime skew the
//! `sqlite/mod.rs` header documents, the table lives at image offset
//! **0x08907ce8** and reads `00 01 02 03 04 06 08 08 00 00 00 00`
//! (binary-verified against osos.dec) — byte-for-byte upstream's
//! `aSize[]`: type 0 is NULL (0 bytes), 1..=4 are 1/2/3/4-byte
//! integers, 5 is the 6-byte integer, 6 the 8-byte integer, 7 the
//! 8-byte IEEE float, 8/9 are the constants 0 and 1 (0 bytes), and
//! 10/11 are reserved (0 bytes). A serial type of 12 or more is the
//! string/blob tail — even `t` a blob of `(t - 12) / 2` bytes, odd
//! `t` a text string of `(t - 13) / 2` — which the `subcs`/`movcs
//! lsr #1` pair encodes as the single formula `(t - 12) >> 1`.
//!
//! ### Deviations
//!
//! None. The port keeps the original's unsigned shape (`lsr`, never
//! `asr`), so bit 31 of the result is always clear — the property
//! [`vdbe_record_compare`](super::vdbe_record_compare::vdbe_record_compare)'s
//! signed `bgt` length check relies on.

/// Upstream's `aSize[]`: the fixed payload byte counts of serial
/// types 0..12, recovered byte-for-byte from osos.dec at image offset
/// 0x08907ce8 (the literal-pool pointer at 0x0838d000, 0x088fce10,
/// resolved through the +0xaed8 skew — see the module header).
pub const A_SIZE: [u32; 12] = [0, 1, 2, 3, 4, 6, 8, 8, 0, 0, 0, 0];

/// vdbe_serial_type_len — original: `FUN_0838cfe8` @ 0x0838cfe8 (24
/// bytes; 9 `bl` call sites, binary-scanned from osos.dec).
///
/// `sqlite3VdbeSerialTypeLen`: the payload byte length of one record
/// field with serial type `serial_type` — [`A_SIZE`] below 12, the
/// string/blob tail formula `(serial_type - 12) >> 1` at and above.
/// See the module header for the listing and the table recovery.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_serial_type_len(serial_type: u32) -> u32 {
    if serial_type < 12 {
        A_SIZE[serial_type as usize]
    } else {
        (serial_type - 12) >> 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The twelve table bytes at image offset 0x08907ce8 in osos.dec,
    /// reached through the literal-pool pointer 0x088fce10 @
    /// 0x0838d000 plus the documented +0xaed8 skew.
    const EXPECTED_A_SIZE: [u32; 12] = [0, 1, 2, 3, 4, 6, 8, 8, 0, 0, 0, 0];

    #[test]
    fn table_matches_the_bytes_recovered_from_osos_dec() {
        assert_eq!(A_SIZE, EXPECTED_A_SIZE);
    }

    #[test]
    fn every_fixed_serial_type_below_12_indexes_the_table() {
        for serial_type in 0..12u32 {
            assert_eq!(
                unsafe { vdbe_serial_type_len(serial_type) },
                EXPECTED_A_SIZE[serial_type as usize],
                "serial_type={serial_type}"
            );
        }
    }

    #[test]
    fn boundary_types_12_and_13_are_zero_length() {
        // 12 is the smallest blob type (0 bytes), 13 the smallest
        // text type (0 bytes); both leave the table behind.
        assert_eq!(unsafe { vdbe_serial_type_len(12) }, 0);
        assert_eq!(unsafe { vdbe_serial_type_len(13) }, 0);
    }

    #[test]
    fn string_blob_tail_sweeps_both_parities() {
        for serial_type in 12..=4096u32 {
            let expected = if serial_type % 2 == 0 {
                // Even: a blob of (t - 12) / 2 bytes, exact.
                (serial_type - 12) / 2
            } else {
                // Odd: a text string of (t - 13) / 2 bytes — the same
                // (t - 12) >> 1 the subcs/movcs pair encodes.
                (serial_type - 13) / 2
            };
            assert_eq!(
                unsafe { vdbe_serial_type_len(serial_type) },
                expected,
                "serial_type={serial_type}"
            );
        }
    }

    #[test]
    fn huge_serial_types_stay_unsigned() {
        // The original's `subcs` wraps and `lsr` shifts logically, so
        // bit 31 of the result is always clear — the property
        // vdbe_record_compare's signed `bgt` length check relies on.
        for serial_type in [u32::MAX - 1, u32::MAX] {
            let len = unsafe { vdbe_serial_type_len(serial_type) };
            assert_eq!(len, (serial_type - 12) >> 1, "serial_type={serial_type:#x}");
            assert_eq!(len as i32 >= 0, true, "bit 31 clear for {serial_type:#x}");
        }
    }
}
