//! `wstr_case_eq` — original: `FUN_08076370` @ 0x08076370
//! (116 bytes; 94 `bl` call sites, binary-scanned).
//!
//! Length-bounded, case-folded equality between a UTF-16-ish wide buffer
//! and a NUL-terminated narrow string. The wide side is passed as a
//! pointer to an ADS `std::vector<u16>` head (`{begin, end}`); the
//! element count `n` is taken from the vector, each of the `n` wide
//! elements and string bytes is run through a per-character uppercase
//! fold table, and the result is 1 iff every folded pair matches AND
//! `strlen(s) == n`. An empty vector yields 0 — even against `""` (the
//! `n != 0` guard fires first). The return is a 1/0 bool, not a strcmp
//! tri-state. Sampled call sites (0x0811de70 family) walk a list of
//! `vector<u16>` buffers and match them against command/name C strings
//! fetched from object slots — an identifier/verb matcher.
//!
//! The first callee is now an exported `cxx/templates` port; the
//! second stays a private helper here (house precedent for tiny
//! leaves):
//!
//! - [`wide_vec_len`] — original: `FUN_0829db9c` @ 0x0829db9c (24
//!   bytes). The ADS out-of-line `std::vector<u16>::size()`:
//!   `ldmia r0,{r0,r1}; cmp r1,r0; subhi r0,r1,r0; movhi r0,r0,asr#1;
//!   movls r0,#0; bx lr` — an UNSIGNED `end > begin` guard, then the
//!   span halved with an arithmetic shift (positive by the guard, so
//!   `asr` and `lsr` agree). An inverted vector yields 0 here, not a
//!   negative count. Promoted to the exported
//!   [`vector_size_elem2_clamped`] in `cxx/templates`; the private
//!   wrapper below delegates.
//!
//! [`vector_size_elem2_clamped`]: crate::cxx::templates::vector_size_elem2_clamped
//! - [`fold_upper`] — original: `FUN_080f4cbc` @ 0x080f4cbc (16 bytes).
//!   `cmn r0,#1; ldrne r1,[0x080f4cd0]; ldrbne r0,[r1,r0]; mvneq r0,#0`
//!   — EOF (-1) maps to 0xffffffff, every other code to `TABLE[c]`.
//!
//! The fold table needs care. The literal-pool word @ 0x080f4cd0 in the
//! decrypted image holds 0x083ed0dd — one byte into `__dscalb`
//! (0x083ed0dc, live soft-float code, ported in `fp/fp_scalb.rs`), i.e.
//! a pre-locale-init placeholder, not a usable map (verified against
//! osos.dec: the bytes there are ARM code, and 'c'/'C' fold apart).
//! The only fold maps in the image live in a full ADS LC_CTYPE locale
//! block: ctype flags @ 0x83f7eb5, lower map @ 0x83f7fb5, upper map @
//! 0x83f80b5 — a Latin-1 toupper (ASCII fold plus 0xe0..=0xfe ->
//! 0xc0..=0xde, with 0xf7 and 0xff unchanged). No pointer to it exists
//! anywhere in the image either; the address is installed at runtime by
//! the locale init (the ctype.rs 0x08985f01 precedent). Modeled as the
//! [`WSTR_FOLD_TABLE`] dispatch slot (FP_TRAP_HANDLER precedent)
//! defaulting to [`DEFAULT_FOLD_TABLE`], a byte-exact copy of the upper
//! map @ 0x83f80b5. The only other user of the same runtime table is
//! the in-place narrow-string transformer `FUN_0810b498` @ 0x0810b498
//! (not ported).
//!
//! Faithful details:
//! - The wide fold is truncated to 16 bits (`mov r8,r0,lsl#0x10` /
//!   `lsr#0x10`), the byte fold to 8 bits (`and r0,r0,#0xff`), before
//!   the compare.
//! - `begin` is dereferenced only after the `n != 0` guard — an empty
//!   vector with a garbage begin word is never read.
//! - The `strlen == n` gate runs only after all `n` pairs matched;
//!   `strlen` stops at the first NUL, so `"a\0b"` still equals the
//!   one-element wide string "a".
//! - Wide codes above 0xff index PAST the 256-entry map, in the
//!   original as in the default table copy; on target the slot can be
//!   pointed at the real runtime map (whose backing image bytes follow
//!   it) to keep even those reads faithful.
//!
//! Deviation: `read_volatile` for the element and table loads, so the
//! compare loop keeps its shape under LLVM's loop-idiom pass. The
//! ported unguarded [`strlen`] @ 0x08392478 is called directly.

use crate::cxx::templates::{vector_size_elem2_clamped, VectorBounds};
use crate::libc::strlen::strlen;

/// The Latin-1 uppercase fold map from the ADS LC_CTYPE locale block @
/// 0x83f80b5, copied byte-exact from osos.dec (file offset 0x3f80b5).
static DEFAULT_FOLD_TABLE: [u8; 256] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xf7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xff,
];

/// Fold table consulted by [`fold_upper`]. Models the runtime-installed
/// locale upper-map pointer the original loads from its literal pool
/// (which in the cold image still holds the placeholder 0x083ed0dd —
/// see the module header). Default is [`DEFAULT_FOLD_TABLE`], the
/// byte-exact LC_CTYPE upper map @ 0x83f80b5. Replace it to observe or
/// substitute the fold — e.g. to point at the device's live map.
///
/// `static mut`, written at port/bring-up time only — same discipline
/// as the firmware's own hook tables.
pub static mut WSTR_FOLD_TABLE: *const u8 = DEFAULT_FOLD_TABLE.as_ptr();

/// fold_upper — original: `FUN_080f4cbc` @ 0x080f4cbc (16 bytes).
///
/// EOF (-1) maps to 0xffffffff; any other code to `WSTR_FOLD_TABLE[c]`.
/// The original indexes the map with the full `int` argument — codes
/// above 0xff read past the 256-entry default copy, exactly as the
/// original reads past the runtime map.
unsafe fn fold_upper(c: i32) -> u32 {
    if c == -1 {
        return 0xffff_ffff;
    }
    let table = core::ptr::read_volatile(&raw const WSTR_FOLD_TABLE);
    table.add(c as usize).read_volatile() as u32
}

/// wide_vec_len — original: `FUN_0829db9c` @ 0x0829db9c (24 bytes).
///
/// ADS out-of-line `std::vector<u16>::size()`: `(end - begin) >> 1`
/// when `end > begin` (unsigned), else 0. Delegates to the exported
/// [`vector_size_elem2_clamped`] port in `cxx/templates`.
unsafe fn wide_vec_len(wide: *const VectorBounds) -> i32 {
    vector_size_elem2_clamped(wide)
}

/// wstr_case_eq — original: `FUN_08076370` @ 0x08076370 (116 bytes).
///
/// 1 iff the `vector<u16>` at `wide` (through its `{begin, end}` head)
/// and the NUL-terminated string at `s` have the same length AND every
/// element pair folds to the same uppercase code. 0 otherwise,
/// including for an empty vector.
///
/// # Safety
/// `wide` must point at a readable [`VectorBounds`]; when it is
/// non-empty, `begin` must be readable for `(end - begin) / 2` `u16`
/// elements, and `s` must be a readable NUL-terminated string.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn wstr_case_eq(wide: *const VectorBounds, s: *const u8) -> i32 {
    let len = wide_vec_len(wide);
    if len == 0 {
        return 0;
    }
    let begin = core::ptr::read_unaligned(core::ptr::addr_of!((*wide).begin));
    let mut wp = begin as *const u16;
    let mut sp = s;
    let mut i = 0i32;
    while i < len {
        let wide_fold = fold_upper(wp.read_volatile() as i32) & 0xffff;
        let byte_fold = fold_upper(sp.read_volatile() as i32) & 0xff;
        if wide_fold != byte_fold {
            return 0;
        }
        wp = wp.add(1);
        sp = sp.add(1);
        i += 1;
    }
    if strlen(s) as i32 == len {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;
    use std::vec::Vec;

    /// Serializes the tests that swap `WSTR_FOLD_TABLE` (the
    /// FP_TRAP_HANDLER `TRAP_TEST_LOCK` precedent).
    static FOLD_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// A `{begin, end}` head over `buf`, laid out exactly like the ADS
    /// vector head on target.
    fn vector_over(buf: &[u16]) -> VectorBounds {
        VectorBounds {
            begin: buf.as_ptr() as *mut u8,
            end: unsafe { buf.as_ptr().add(buf.len()) } as *mut u8,
        }
    }

    /// The reference, transcribed from the decomp C with an explicit
    /// fold function.
    fn reference(wide: &[u16], s: &[u8], fold: impl Fn(u32) -> u32) -> i32 {
        let n = wide.len();
        if n == 0 {
            return 0;
        }
        for i in 0..n {
            if (fold(wide[i] as u32) & 0xffff) != (fold(s[i] as u32) & 0xff) {
                return 0;
            }
        }
        let slen = s.iter().position(|&b| b == 0).expect("NUL-terminated");
        if slen == n {
            1
        } else {
            0
        }
    }

    fn default_fold(c: u32) -> u32 {
        DEFAULT_FOLD_TABLE[c as usize] as u32
    }

    /// NUL-terminate for the C-string side.
    fn cstr(bytes: &[u8]) -> Vec<u8> {
        let mut v = bytes.to_vec();
        v.push(0);
        v
    }

    // ---- fold_upper ---------------------------------------------------

    #[test]
    fn fold_maps_eof_to_all_ones() {
        assert_eq!(unsafe { fold_upper(-1) }, 0xffff_ffff);
    }

    #[test]
    fn fold_is_the_latin1_upper_map() {
        unsafe {
            assert_eq!(fold_upper(b'a' as i32), b'A' as u32);
            assert_eq!(fold_upper(b'z' as i32), b'Z' as u32);
            assert_eq!(fold_upper(b'A' as i32), b'A' as u32);
            assert_eq!(fold_upper(b'0' as i32), b'0' as u32);
            assert_eq!(fold_upper(0x00), 0x00);
            // Latin-1 high half: 0xe0..=0xfe -> 0xc0..=0xde ...
            assert_eq!(fold_upper(0xe0), 0xc0);
            assert_eq!(fold_upper(0xe9), 0xc9);
            assert_eq!(fold_upper(0xfe), 0xde);
            // ... except the multiplication/division signs and y-diaeresis.
            assert_eq!(fold_upper(0xf7), 0xf7);
            assert_eq!(fold_upper(0xff), 0xff);
        }
    }

    /// The shipped default table is the byte-exact copy of the image's
    /// upper map @ 0x83f80b5: identity except the two fold spans.
    #[test]
    fn default_table_matches_the_image_layout() {
        for c in 0..256u32 {
            let expected = match c {
                0x61..=0x7a => c - 0x20,
                0xe0..=0xfe => {
                    if c == 0xf7 {
                        0xf7
                    } else {
                        c - 0x20
                    }
                }
                _ => c,
            };
            assert_eq!(DEFAULT_FOLD_TABLE[c as usize] as u32, expected, "code {c:#x}");
        }
    }

    // ---- wide_vec_len -------------------------------------------------

    #[test]
    fn len_counts_u16_elements() {
        for n in 0..64usize {
            let buf = std::vec![0u16; n.max(1)];
            let head = vector_over(&buf[..n]);
            assert_eq!(unsafe { wide_vec_len(&head) }, n as i32, "n {n}");
        }
    }

    #[test]
    fn len_is_zero_for_empty_and_inverted_vectors() {
        let buf = [0u16; 4];
        let empty = VectorBounds {
            begin: buf.as_ptr() as *mut u8,
            end: buf.as_ptr() as *mut u8,
        };
        assert_eq!(unsafe { wide_vec_len(&empty) }, 0);
        // Inverted (end < begin): the `movls r0,#0` guard, not a
        // negative count.
        let inverted = VectorBounds {
            begin: unsafe { buf.as_ptr().add(4) } as *mut u8,
            end: buf.as_ptr() as *mut u8,
        };
        assert_eq!(unsafe { wide_vec_len(&inverted) }, 0);
    }

    // ---- wstr_case_eq -------------------------------------------------

    #[test]
    fn equal_ascii_folds_equal_regardless_of_case() {
        let wide = [b'p' as u16, b'L' as u16, b'a' as u16, b'Y' as u16];
        let head = vector_over(&wide);
        for s in [&b"play"[..], b"PLAY", b"PlAy", b"pLaY"] {
            let s = cstr(s);
            assert_eq!(
                unsafe { wstr_case_eq(&head, s.as_ptr()) },
                1,
                "string {s:?}"
            );
        }
    }

    #[test]
    fn latin1_letters_fold_across_the_high_half() {
        // "àbç" wide vs "ÀBÇ" narrow — 0xe0/0xe7 fold to 0xc0/0xc7.
        let wide = [0xe0u16, b'b' as u16, 0xe7u16];
        let head = vector_over(&wide);
        let s = cstr(&[0xc0, b'B', 0xc7]);
        assert_eq!(unsafe { wstr_case_eq(&head, s.as_ptr()) }, 1);
        // ÷ (0xf7) does NOT fold to × (0xd7).
        let wide = [0xf7u16];
        let head = vector_over(&wide);
        let s = cstr(&[0xd7]);
        assert_eq!(unsafe { wstr_case_eq(&head, s.as_ptr()) }, 0);
    }

    #[test]
    fn any_mismatch_fails() {
        let wide = [b'a' as u16, b'b' as u16, b'c' as u16];
        let head = vector_over(&wide);
        let s = cstr(b"abd");
        assert_eq!(unsafe { wstr_case_eq(&head, s.as_ptr()) }, 0);
        let s = cstr(b"zbc");
        assert_eq!(unsafe { wstr_case_eq(&head, s.as_ptr()) }, 0);
    }

    #[test]
    fn the_string_must_have_exactly_the_vector_length() {
        let wide = [b'a' as u16, b'b' as u16];
        let head = vector_over(&wide);
        // Longer string: pairs match, strlen gate fails.
        let s = cstr(b"abc");
        assert_eq!(unsafe { wstr_case_eq(&head, s.as_ptr()) }, 0);
        // Shorter string: fold(wide[1]) vs fold(NUL) = 0 fails in the loop.
        let wide3 = [b'a' as u16, b'b' as u16, b'c' as u16];
        let head3 = vector_over(&wide3);
        let s = cstr(b"ab");
        assert_eq!(unsafe { wstr_case_eq(&head3, s.as_ptr()) }, 0);
    }

    #[test]
    fn an_empty_vector_fails_even_against_an_empty_string() {
        let buf = [0u16; 1];
        let head = vector_over(&buf[..0]);
        let s = cstr(b"");
        assert_eq!(unsafe { wstr_case_eq(&head, s.as_ptr()) }, 0);
    }

    /// `strlen` stops at the first NUL, so trailing bytes after it are
    /// invisible to both the compare and the length gate.
    #[test]
    fn bytes_after_the_nul_are_invisible() {
        let wide = [b'a' as u16];
        let head = vector_over(&wide);
        let s = b"a\0trailing-garbage";
        assert_eq!(unsafe { wstr_case_eq(&head, s.as_ptr()) }, 1);
    }

    /// A wide NUL folds to table[0] = 0, matching a string NUL — but
    /// the strlen gate then sees a shorter string and fails.
    #[test]
    fn an_embedded_wide_nul_shortens_the_string_side() {
        let wide = [b'a' as u16, 0u16];
        let head = vector_over(&wide);
        let s = cstr(b"a");
        // loop: 'a'=='a', 0 == fold(NUL) = 0 passes; strlen("a") = 1 != 2.
        assert_eq!(unsafe { wstr_case_eq(&head, s.as_ptr()) }, 0);
    }

    #[test]
    fn matches_the_reference_on_swept_inputs() {
        let mut rng: u32 = 0x1234_5678;
        let mut next = move || {
            rng = rng.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (rng >> 16) as u16
        };
        for round in 0..200 {
            let n = (next() % 16) as usize;
            let mut wide: Vec<u16> = (0..n).map(|_| (next() % 0x100) as u16).collect();
            let mut bytes: Vec<u8> = (0..n + 2).map(|_| (next() % 0xff) as u8 + 1).collect();
            // Half the rounds: make the string a case-permuted copy of
            // the wide side so equality is reachable.
            if round % 2 == 0 && n > 0 {
                bytes = wide
                    .iter()
                    .map(|&w| {
                        let b = w as u8;
                        match b {
                            0x61..=0x7a if next() % 2 == 0 => b - 0x20,
                            0x41..=0x5a if next() % 2 == 0 => b + 0x20,
                            0xe0..=0xfe if next() % 2 == 0 && b != 0xf7 => b - 0x20,
                            _ => b,
                        }
                    })
                    .collect();
                bytes.truncate(n);
            }
            let s = cstr(&bytes);
            // Keep the wide side free of NULs except as swept.
            for w in wide.iter_mut() {
                *w &= 0xff;
            }
            let head = vector_over(&wide);
            assert_eq!(
                unsafe { wstr_case_eq(&head, s.as_ptr()) },
                reference(&wide, &s, default_fold),
                "round {round} wide {wide:?} s {s:?}"
            );
        }
    }

    // ---- WSTR_FOLD_TABLE slot ------------------------------------------

    /// Codes above 0xff index past the 256-entry map. With a synthetic
    /// 512-entry table swapped in, the out-of-ASCII read is exercised
    /// without touching memory past the default copy.
    #[test]
    fn wide_codes_above_0xff_read_past_the_map() {
        let _guard = FOLD_TEST_LOCK.lock().unwrap();
        static mut BIG_TABLE: [u8; 512] = [0; 512];
        unsafe {
            for (i, e) in BIG_TABLE.iter_mut().enumerate() {
                *e = i as u8; // identity
            }
            BIG_TABLE[0x141] = b'A';
            WSTR_FOLD_TABLE = BIG_TABLE.as_ptr();

            // Identity fold: case now matters.
            let wide = [b'a' as u16];
            let head = vector_over(&wide);
            let s = cstr(b"A");
            assert_eq!(wstr_case_eq(&head, s.as_ptr()), 0);
            let s = cstr(b"a");
            assert_eq!(wstr_case_eq(&head, s.as_ptr()), 1);

            // 0x141 folds through BIG_TABLE[0x141] = 'A'.
            let wide = [0x141u16];
            let head = vector_over(&wide);
            let s = cstr(b"A");
            assert_eq!(wstr_case_eq(&head, s.as_ptr()), 1);

            WSTR_FOLD_TABLE = DEFAULT_FOLD_TABLE.as_ptr();
        }
    }
}
