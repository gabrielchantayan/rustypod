//! `str_fold_upper_inplace` — original: `FUN_0810b498` @ 0x0810b498
//! (40 bytes: 36 code + the 4-byte fold-table literal @ 0x0810b4c0;
//! 1 `bl` call site, 0x081a3618, binary-scanned).
//!
//! In-place uppercase fold of a NUL-terminated narrow string, reached
//! through a pointer slot: `ldr r0,[r0]` takes the `char *` out of the
//! slot, a NULL string pointer returns immediately (`bxeq lr`), and
//! every byte up to (not including) the first NUL is rewritten through
//! the runtime uppercase fold map — `ldrb` / `cmp #0` / `ldrbne
//! [table, c]` / `strbne [r0], #1` / `bne`. The NUL terminator itself
//! is never stored, the slot word is never written, and nothing is
//! returned.
//!
//! The fold map is the same runtime ADS LC_CTYPE upper map wstr_case_eq
//! uses: the literal-pool word @ 0x0810b4c0 in the cold image holds
//! 0x083ed0dd — the pre-locale-init placeholder one byte into
//! `__dscalb`, binary-verified against osos.dec (file offset
//! 0x10b4c0) — with the real map address (upper map @ 0x83f80b5)
//! installed at runtime by the locale init. Reused here through the
//! shared [`WSTR_FOLD_TABLE`] dispatch slot of util/wstr_casecmp.rs
//! rather than duplicated.
//!
//! Sole caller 0x081a35ec: builds a string object from a C string
//! (0x0810b634), folds it to uppercase through this function, takes a
//! 4-byte hash/key (0x08297df8), converts it (0x0810b654) and compares
//! against a tag literal (0x0810b444) — a case-normalizing tag/key
//! lookup.
//!
//! Deviation: `read_volatile`/`write_volatile` for the slot, byte and
//! table accesses so the fold loop keeps its shape under LLVM's
//! loop-idiom pass (the PORTING.md gotcha). The fold itself is
//! byte-identical to the original's: table[c] for c != 0, loop stops
//! at the first NUL.

use crate::util::wstr_casecmp::WSTR_FOLD_TABLE;

/// str_fold_upper_inplace — original: `FUN_0810b498` @ 0x0810b498
/// (40 bytes).
///
/// Rewrites the NUL-terminated string `*slot` in place, folding each
/// byte through the uppercase fold map until the first NUL. A NULL
/// string pointer is a no-op. The slot itself is only read.
///
/// # Safety
/// `slot` must point at a readable `*mut u8`; when that pointer is
/// non-NULL it must be a writable NUL-terminated byte string.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn str_fold_upper_inplace(slot: *const *mut u8) {
    let mut p = core::ptr::read_volatile(slot);
    if p.is_null() {
        return;
    }
    let table = core::ptr::read_volatile(&raw const WSTR_FOLD_TABLE);
    loop {
        let c = p.read_volatile();
        if c == 0 {
            break;
        }
        p.write_volatile(table.add(c as usize).read_volatile());
        p = p.add(1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// The reference, transcribed from the decomp C with an explicit
    /// fold; `fold` models the byte-exact LC_CTYPE upper map @
    /// 0x83f80b5 (identity except the two fold spans — the same shape
    /// wstr_casecmp's `default_table_matches_the_image_layout` pins).
    fn reference(buf: &mut [u8], fold: impl Fn(u8) -> u8) {
        for b in buf.iter_mut() {
            if *b == 0 {
                break;
            }
            *b = fold(*b);
        }
    }

    fn default_fold(c: u8) -> u8 {
        match c {
            0x61..=0x7a => c - 0x20,
            0xe0..=0xfe if c != 0xf7 => c - 0x20,
            _ => c,
        }
    }

    /// Runs the port over a heap string built from `bytes` plus a NUL.
    /// Returns the full buffer (NUL included) and the slot word.
    fn run(bytes: &[u8]) -> (Vec<u8>, *mut u8) {
        let mut buf = bytes.to_vec();
        buf.push(0);
        let ptr = buf.as_mut_ptr();
        let mut slot: *mut u8 = ptr;
        unsafe { str_fold_upper_inplace(&mut slot) };
        (buf, slot)
    }

    #[test]
    fn a_null_string_pointer_is_a_no_op() {
        let mut slot: *mut u8 = core::ptr::null_mut();
        unsafe { str_fold_upper_inplace(&mut slot) };
        assert!(slot.is_null());
    }

    #[test]
    fn ascii_lowercase_folds_to_uppercase_in_place() {
        let (buf, _) = run(b"ipod classic 6g");
        assert_eq!(&buf, b"IPOD CLASSIC 6G\0");
    }

    #[test]
    fn uppercase_digits_and_punctuation_are_unchanged() {
        let (buf, _) = run(b"ABCXYZ 0129 !~@[`{|}");
        assert_eq!(&buf, b"ABCXYZ 0129 !~@[`{|}\0");
    }

    #[test]
    fn latin1_high_half_folds_with_the_two_exceptions() {
        // 0xe0..=0xfe fold to 0xc0..=0xde, except 0xf7 (division sign)
        // and 0xff (y-diaeresis) which stay.
        let (buf, _) = run(&[0xe0, 0xe9, 0xf7, 0xfe, 0xff]);
        assert_eq!(&buf, &[0xc0, 0xc9, 0xf7, 0xde, 0xff, 0x00]);
    }

    #[test]
    fn an_empty_string_is_untouched() {
        let (buf, _) = run(b"");
        assert_eq!(&buf, b"\0");
    }

    /// The loop stops at the first NUL (`cmp #0` / `bne`): bytes after
    /// it are invisible and the NUL is never stored.
    #[test]
    fn bytes_after_the_first_nul_are_invisible() {
        let mut buf = b"ab\0cd".to_vec();
        let ptr = buf.as_mut_ptr();
        let mut slot: *mut u8 = ptr;
        unsafe { str_fold_upper_inplace(&mut slot) };
        assert_eq!(&buf, b"AB\0cd");
    }

    /// The slot word is only read (`ldr r0,[r0]`); the post-increment
    /// walks a register copy, not the slot.
    #[test]
    fn the_slot_word_is_never_written() {
        let mut buf = b"abc".to_vec();
        buf.push(0);
        let ptr = buf.as_mut_ptr();
        let mut slot: *mut u8 = ptr;
        unsafe { str_fold_upper_inplace(&mut slot) };
        assert_eq!(slot, ptr);
        assert_eq!(&buf, b"ABC\0");
    }

    #[test]
    fn matches_the_reference_on_swept_inputs() {
        let mut rng: u32 = 0xdead_beef;
        let mut next = move || {
            rng = rng.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (rng >> 16) as u8
        };
        for round in 0..200 {
            let n = (next() % 64) as usize;
            // Bytes 1..=0xff before the terminator; every third round
            // plants an interior NUL to sweep the early-stop path.
            let mut bytes: Vec<u8> = (0..n).map(|_| next() % 0xff + 1).collect();
            if round % 3 == 0 && n > 0 {
                bytes[(next() as usize) % n] = 0;
            }
            let mut expected = bytes.clone();
            expected.push(0);
            reference(&mut expected, default_fold);
            let (buf, _) = run(&bytes);
            assert_eq!(buf, expected, "round {round} input {bytes:?}");
        }
    }

    // NOTE: no WSTR_FOLD_TABLE swap test here on purpose — the slot is
    // shared with util/wstr_casecmp.rs's tests (which prove the swap
    // mechanism), and two test bodies writing the same `static mut`
    // concurrently would race.
}
