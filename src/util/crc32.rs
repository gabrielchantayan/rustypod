//! CRC32 support. Two CRC-32 variants coexist in osos, built on the same
//! polynomial (0x04C11DB7) in its two orientations:
//!
//! - MSB-first (non-reflected, CRC-32/BZIP2 family). The table is NOT in the
//!   image; it is built at runtime into RAM @ 0x08ad786c (1KB) by the
//!   table-gen below. Modeled here as the `static mut` `CRC32_MSB_TABLE`.
//! - Reflected (zlib/IEEE, CRC-32/ISO-HDLC). A static 1KB table sits in the
//!   image @ 0x0894289c (entry[0] = 0, entry[1] = 0x77073096,
//!   entry[0x80] = 0xEDB88320 — the first 16 entries were extracted from
//!   osos.dec and are checked by the host tests). Replicated here as the
//!   const `CRC32_REFLECTED_TABLE`, generated from the same reflected
//!   polynomial 0xEDB88320 at compile time.
//!
//! Provenance notes (from osos.dec):
//!
//! - The RAM table @ 0x08ad786c is referenced ONLY by the table-gen's
//!   literal pool; the gen runs once via the guarded wrapper @ 0x082905a4
//!   (once-flag @ 0x089d0180, called from 0x081a0b64). No consumer of this
//!   table exists in the osos image (its user presumably lives in aupd or
//!   the bootloader), so `crc32_msb` implements the standard loop for the
//!   table's lineage.
//! - The static reflected table @ 0x0894289c is likewise unreferenced in
//!   the image (dead data, likely a link-time artifact). The reflected loop
//!   the firmware actually runs is zlib's `crc32` @ 0x807badc — reached
//!   from inflate (@ 0x082d4e88) through the thunk @ 0x082c51cc — a
//!   slicing-by-4 loop over a runtime 4KB table @ 0x089379c4 that is NOT
//!   present in the image either (BSS filled elsewhere). `crc32_reflected`
//!   ports its exact semantics (`mvn` on the seed going in, `mvn` on the
//!   register coming out) in byte-at-a-time form over the static table.
//! - A second real loop @ 0x80f4428 is MSB-first over another runtime 4KB
//!   table @ 0x089389c4 (also absent from the image) and additionally
//!   byte-swaps seed and result around the usual `mvn`s — an adaptation to
//!   big-endian-stored checksums, not a different CRC. `crc32_msb` keeps
//!   the same `~seed`-in / `~crc`-out convention as its reflected twin and
//!   documents the byte-swap as a caller-side concern.
//!
//! Check values ("123456789", seed = 0):
//! - `crc32_reflected` = 0xCBF43926 (CRC-32/ISO-HDLC, zlib).
//! - `crc32_msb`       = 0xFC891918 (CRC-32/BZIP2: poly 0x04C11DB7,
//!   init 0xFFFFFFFF, xorout 0xFFFFFFFF, no reflection).
//! - The bare generated table with a raw register (init = 0, xorout = 0,
//!   no `mvn`s) yields 0x89A1897F — the BZIP2-family parameters stripped
//!   of their complement conventions.
//!
//! Simplifications:
//! - Both compute loops are byte-at-a-time; the originals @ 0x807badc /
//!   0x80f4428 are word-optimized slicing-by-4 loops over 4KB runtime
//!   tables. Semantics are identical.
//! - The original table-gen truncates its loop counters to i16 (movs x16 /
//!   asr x16 pairs); with bounds 0..256 and 0..8 that is unobservable, so
//!   plain `u32`/`usize` counters are used.

/// Polynomial built into the table-gen @ 0x080751a0 (literal pool
/// @ 0x080751f4): CRC-32/BZIP2-family, MSB-first (non-reflected).
const POLY_MSB: u32 = 0x04C1_1DB7;

/// Reflected form of the same polynomial; the static table @ 0x0894289c
/// is the canonical zlib/IEEE table generated from it.
const POLY_REFLECTED: u32 = 0xEDB8_8320;

/// MSB-first CRC-32 table, built by `crc32_table_gen`.
///
/// Original location: RAM @ 0x08ad786c (1KB, writable data). Nothing in
/// the osos image consumes it — see the module header.
pub static mut CRC32_MSB_TABLE: [u32; 256] = [0; 256];

/// Reflected CRC-32 table, a compile-time replica of the static table
/// @ 0x0894289c in osos (verified entry-for-entry identical by
/// construction: same poly, same algorithm).
static CRC32_REFLECTED_TABLE: [u32; 256] = build_reflected_table();

const fn build_reflected_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ POLY_REFLECTED } else { crc >> 1 };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// crc32_table_gen — original: `FUN_080751a0` @ 0x080751a0 (96 bytes).
///
/// Builds the 1KB MSB-first table from poly 0x04C11DB7: for each of the
/// 256 byte values, start from `value << 24` and shift left 8 times,
/// XORing the polynomial whenever the top bit was set. The original
/// stores straight into RAM @ 0x08ad786c (literal pool @ 0x080751f8);
/// here it fills `CRC32_MSB_TABLE`. Must run before `crc32_msb`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn crc32_table_gen() {
    let table = core::ptr::addr_of_mut!(CRC32_MSB_TABLE);
    // `black_box` keeps LLVM from constant-folding the whole table into a
    // .rodata copy loop (observed); the original computes it in registers.
    let poly = core::hint::black_box(POLY_MSB);
    for i in 0..256u32 {
        let mut crc = i << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 { (crc << 1) ^ poly } else { crc << 1 };
        }
        (*table)[i as usize] = crc;
    }
}

/// Reflected (zlib/IEEE) CRC-32, byte-at-a-time port of the loop
/// semantics @ 0x807badc: the register starts at `!seed`, each byte
/// indexes the table with `(crc ^ byte) & 0xff` and shifts the register
/// right 8, and the result is `!crc`.
///
/// `seed = 0` therefore gives the standard CRC-32/ISO-HDLC (init
/// 0xFFFFFFFF, xorout 0xFFFFFFFF); a running CRC is continued by passing
/// the previous return value back in, exactly like zlib's `crc32()`.
/// A NULL pointer or zero length folds to the identity: `seed` back
/// unchanged (the zlib thunk @ 0x082c51cc returns 0 for NULL on a fresh
/// CRC, which is the same rule).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn crc32_reflected(data: *const u8, len: usize, seed: u32) -> u32 {
    let mut crc = !seed;
    for i in 0..len {
        let byte = data.add(i).read() as u32;
        crc = CRC32_REFLECTED_TABLE[((crc ^ byte) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

/// MSB-first (non-reflected, CRC-32/BZIP2 family) CRC-32 over the
/// runtime table built by `crc32_table_gen` (original RAM table
/// @ 0x08ad786c). The compute loop is not in the osos image; this is the
/// standard loop for the table's lineage: register starts at `!seed`,
/// each byte indexes the table with `((crc >> 24) ^ byte) & 0xff` and
/// shifts the register left 8, result is `!crc` — the same `mvn`-in /
/// `mvn`-out convention the original reflected loop @ 0x807badc and the
/// original MSB loop @ 0x80f4428 both use.
///
/// Deviation: the original MSB loop @ 0x80f4428 additionally byte-swaps
/// seed and result (adapting to big-endian-stored checksums); that is a
/// storage convention and is left to the caller here.
///
/// `seed = 0` gives CRC-32/BZIP2 parameters (init/xorout 0xFFFFFFFF).
/// `crc32_table_gen` must have run first; a NULL pointer or zero length
/// returns `seed` unchanged.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn crc32_msb(data: *const u8, len: usize, seed: u32) -> u32 {
    let table = core::ptr::addr_of!(CRC32_MSB_TABLE);
    let mut crc = !seed;
    for i in 0..len {
        let byte = data.add(i).read() as u32;
        crc = (*table)[(((crc >> 24) ^ byte) & 0xff) as usize] ^ (crc << 8);
    }
    !crc
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    const CHECK_DATA: &[u8] = b"123456789";

    /// Reference MSB-first table built from poly 0x04C11DB7, same
    /// algorithm as the original table-gen.
    fn reference_msb_table() -> [u32; 256] {
        let mut table = [0u32; 256];
        for (i, entry) in table.iter_mut().enumerate() {
            let mut crc = (i as u32) << 24;
            for _ in 0..8 {
                crc = if crc & 0x8000_0000 != 0 { (crc << 1) ^ POLY_MSB } else { crc << 1 };
            }
            *entry = crc;
        }
        table
    }

    /// Raw-register MSB-first pass over a table: no `mvn`s, `init` and
    /// `xorout` applied exactly as given.
    fn raw_msb(table: &[u32; 256], data: &[u8], init: u32, xorout: u32) -> u32 {
        let mut crc = init;
        for &b in data {
            crc = table[(((crc >> 24) ^ b as u32) & 0xff) as usize] ^ (crc << 8);
        }
        crc ^ xorout
    }

    #[test]
    fn table_gen_matches_reference() {
        unsafe { crc32_table_gen() };
        let generated = unsafe { &*core::ptr::addr_of!(CRC32_MSB_TABLE) };
        assert_eq!(*generated, reference_msb_table());
        // Spot-check the table's defining features.
        assert_eq!(generated[0], 0);
        assert_eq!(generated[1], 0x04C1_1DB7);
        assert_eq!(generated[0x80], 0x690C_E0EE);
    }

    /// First 16 entries of the static reflected table, extracted from
    /// osos.dec @ 0x0894289c (file offset 0x94289c).
    const BINARY_TABLE_HEAD: [u32; 16] = [
        0x0000_0000, 0x7707_3096, 0xEE0E_612C, 0x9909_51BA,
        0x076D_C419, 0x706A_F48F, 0xE963_A535, 0x9E64_95A3,
        0x0EDB_8832, 0x79DC_B8A4, 0xE0D5_E91E, 0x97D2_D988,
        0x09B6_4C2B, 0x7EB1_7CBD, 0xE7B8_2D07, 0x90BF_1D91,
    ];

    #[test]
    fn static_reflected_table_matches_binary() {
        assert_eq!(CRC32_REFLECTED_TABLE[..16], BINARY_TABLE_HEAD[..]);
        // Anchor entries called out in the reverse engineering notes.
        assert_eq!(CRC32_REFLECTED_TABLE[0x80], 0xEDB8_8320);
        assert_eq!(CRC32_REFLECTED_TABLE[1], 0x7707_3096);
    }

    #[test]
    fn reflected_known_vector() {
        let crc = unsafe { crc32_reflected(CHECK_DATA.as_ptr(), CHECK_DATA.len(), 0) };
        assert_eq!(crc, 0xCBF4_3926); // CRC-32/ISO-HDLC (zlib)
    }

    #[test]
    fn msb_known_vector() {
        unsafe { crc32_table_gen() };
        let crc = unsafe { crc32_msb(CHECK_DATA.as_ptr(), CHECK_DATA.len(), 0) };
        assert_eq!(crc, 0xFC89_1918); // CRC-32/BZIP2
    }

    #[test]
    fn msb_bare_table_lineage() {
        // The generated table with a raw register (init = 0, xorout = 0)
        // yields 0x89A1897F on the check string — the BZIP2-family
        // computation stripped of its complement conventions.
        let table = reference_msb_table();
        assert_eq!(raw_msb(&table, CHECK_DATA, 0, 0), 0x89A1_897F);
        // ... and with the BZIP2 complement conventions, 0xFC891918.
        assert_eq!(raw_msb(&table, CHECK_DATA, 0xFFFF_FFFF, 0xFFFF_FFFF), 0xFC89_1918);
    }

    /// Feeding the data in chunks with the previous CRC as the next seed
    /// must equal one-shot (zlib `crc32()` composition rule).
    #[test]
    fn both_variants_compose_across_chunks() {
        unsafe { crc32_table_gen() };
        let data: Vec<u8> = (0..513u32).map(|i| (i * 37 % 251) as u8).collect();
        for split in [1usize, 7, 64, 255, 256, 512] {
            let one_shot_r = unsafe { crc32_reflected(data.as_ptr(), data.len(), 0) };
            let first_r = unsafe { crc32_reflected(data.as_ptr(), split, 0) };
            let whole_r = unsafe { crc32_reflected(data.as_ptr().add(split), data.len() - split, first_r) };
            assert_eq!(one_shot_r, whole_r, "reflected split at {split}");

            let one_shot_m = unsafe { crc32_msb(data.as_ptr(), data.len(), 0) };
            let first_m = unsafe { crc32_msb(data.as_ptr(), split, 0) };
            let whole_m = unsafe { crc32_msb(data.as_ptr().add(split), data.len() - split, first_m) };
            assert_eq!(one_shot_m, whole_m, "msb split at {split}");
        }
    }

    #[test]
    fn empty_input_is_identity() {
        unsafe { crc32_table_gen() };
        for seed in [0u32, 1, 0xDEAD_BEEF] {
            assert_eq!(unsafe { crc32_reflected(core::ptr::null(), 0, seed) }, seed);
            assert_eq!(unsafe { crc32_msb(core::ptr::null(), 0, seed) }, seed);
        }
    }
}
