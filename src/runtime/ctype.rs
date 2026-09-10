//! Ports of the ARM ADS 1.0.1 ctype case-conversion routines: `tolower`
//! (original: `FUN_0802f1bc` @ 0x0802f1bc, 36 bytes) and `toupper`
//! (original: `FUN_0802f1e0` @ 0x0802f1e0, 40 bytes).
//!
//! Both index a 256-byte per-character flag table and conditionally adjust
//! by 0x20: `tolower` returns `c + 32` when the table entry has bit 0x10
//! (uppercase letter), `toupper` returns `c - 32` when bit 0x08 (lowercase
//! letter) is set, with an extra `c != 0xdf` guard (Latin-1 ß has no
//! single-byte uppercase — dead code under the C locale, kept for fidelity).
//! Otherwise `c` is returned unchanged.
//!
//! The original reads the table pointer from libspace+0x24 (libspace base
//! 0x08b31774, filled in at runtime by setlocale @ 0x08030860, which stores
//! block+1 so that index -1/EOF lands on a guard byte before the table).
//! The C-locale table is in osos rodata: flag bytes at load address
//! 0x08985f01 (file offset 0x985f01 in osos.dec), EOF guard byte 0x00 at
//! 0x08985f00. `CTYPE_TABLE` below is a byte-exact copy of those 256 bytes.
//!
//! Deviation: the original has no bounds check at all — any `c` outside
//! -1..=255 reads out of the table. Since EOF (-1) hits the guard byte
//! (0x00, no bits set) it passes through unchanged; this port extends the
//! same "flags = 0, return c unchanged" behavior to every out-of-range `c`
//! instead of performing an out-of-bounds read.

/// Bit set on entries for uppercase letters ('A'..='Z').
const CTYPE_UPPER: u8 = 0x10;
/// Bit set on entries for lowercase letters ('a'..='z').
const CTYPE_LOWER: u8 = 0x08;

/// ADS C-locale ctype flag table, extracted byte-exact from osos rodata
/// (load address 0x08985f01). Known bit meanings in this firmware:
/// 0x40 = control char, 0x20 = digit, 0x10 = uppercase, 0x08 = lowercase,
/// 0x04/0x02 = punctuation/space classes, 0x01 = whitespace, 0x80 = hex
/// digit. Entries 0x80..=0xff are all zero in the C locale.
/// (`const` so runtime/locale.rs can assemble the full LC_CTYPE block —
/// guard byte + flags — from it at compile time.)
pub const CTYPE_FLAGS: [u8; 256] = [
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x41, 0x41, 0x41, 0x41, 0x41, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x05, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x02, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x02, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x02, 0x02, 0x02, 0x02, 0x40,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// The same table as an addressable static (the form the original code
/// indexes through the libspace+0x24 pointer).
pub static CTYPE_TABLE: [u8; 256] = CTYPE_FLAGS;

/// Flag lookup mirroring the original's `ldrb flags, [table, c]`.
/// In-range `c` reads the table; anything else behaves like the original's
/// EOF (-1) case, which reads the zero guard byte preceding the table.
#[inline(always)]
fn ctype_flags(c: i32) -> u8 {
    if (0..256).contains(&c) {
        CTYPE_TABLE[c as usize]
    } else {
        0
    }
}

/// tolower — original: `FUN_0802f1bc` @ 0x0802f1bc (36 bytes).
///
/// `tst flags, #0x10; moveq r0, c; addne r0, c, #32` — uppercase letters
/// are returned + 0x20, everything else (including EOF) unchanged.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tolower(c: i32) -> i32 {
    if ctype_flags(c) & CTYPE_UPPER != 0 {
        c + 0x20
    } else {
        c
    }
}

/// toupper — original: `FUN_0802f1e0` @ 0x0802f1e0 (40 bytes).
///
/// `tst flags, #8; cmpne c, #0xdf; moveq r0, c; subne r0, c, #32` —
/// lowercase letters are returned - 0x20, except 0xdf (Latin-1 ß), which
/// has no single-byte uppercase. Under the C locale table 0xdf has no
/// flags, so the guard never fires; it is kept for fidelity.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn toupper(c: i32) -> i32 {
    if ctype_flags(c) & CTYPE_LOWER != 0 && c != 0xdf {
        c - 0x20
    } else {
        c
    }
}

/// isdigit — original: `FUN_082d731c` @ 0x082d731c (36 bytes).
///
/// Verified by decoding every ARM B/BL word in osos.dec: 10 plain,
/// unconditional `bl` call sites and no predicated forms. Calls
/// `__rt_ctype_table_addr`, loads the current LC_CTYPE table pointer, then
/// returns one exactly when `table[c] == 0x20`. There is deliberately no
/// NULL or bounds guard: as in retailOS, the caller must supply an installed
/// table and an index it can read.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn isdigit(c: i32) -> i32 {
    let table = core::ptr::read_volatile(crate::runtime::errno::__rt_ctype_table_addr())
        as usize as *const u8;
    if core::ptr::read_volatile(table.wrapping_offset(c as isize)) == 0x20 {
        1
    } else {
        0
    }
}


#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::runtime::errno::__rt_ctype_table_addr;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    const ISDIGIT_FIXTURE_LEN: usize = 0x1000;
    static ISDIGIT_TEST_LOCK: Mutex<()> = Mutex::new(());
    static ISDIGIT_FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::CTYPE_ISDIGIT, ISDIGIT_FIXTURE_LEN)
            .map(|pointer| pointer as usize)
    });

    struct CtypeTableSlotReset {
        slot: *mut u32,
        saved: u32,
    }

    impl Drop for CtypeTableSlotReset {
        fn drop(&mut self) {
            unsafe { self.slot.write_volatile(self.saved) };
        }
    }


    /// Independent reference: in this table only ASCII letters carry the
    /// case bits, so plain ASCII rules must agree exactly.
    fn ref_tolower(c: i32) -> i32 {
        if (0x41..=0x5a).contains(&c) {
            c + 0x20
        } else {
            c
        }
    }

    fn ref_toupper(c: i32) -> i32 {
        if (0x61..=0x7a).contains(&c) {
            c - 0x20
        } else {
            c
        }
    }

    /// Every input the original can read within the table (plus EOF=-1,
    /// which hits the guard byte) must match the reference.
    #[test]
    fn matches_reference_full_range() {
        for c in -1..=255 {
            assert_eq!(unsafe { tolower(c) }, ref_tolower(c), "tolower({c})");
            assert_eq!(unsafe { toupper(c) }, ref_toupper(c), "toupper({c})");
        }
    }

    #[test]
    fn spot_checks() {
        unsafe {
            assert_eq!(tolower(0x41), 0x61); // 'A' -> 'a'
            assert_eq!(toupper(0x7a), 0x5a); // 'z' -> 'Z'
            assert_eq!(tolower(0x61), 0x61); // 'a' unchanged
            assert_eq!(toupper(0x5a), 0x5a); // 'Z' unchanged
            assert_eq!(tolower(0x30), 0x30); // '0' unchanged
            assert_eq!(toupper(0x30), 0x30);
            // EOF: original reads the zero guard byte at table[-1].
            assert_eq!(tolower(-1), -1);
            assert_eq!(toupper(-1), -1);
            // 0xdf (ß): no flags in the C locale table; the original's
            // explicit `c != 0xdf` guard means it can never be uppercased.
            assert_eq!(CTYPE_TABLE[0xdf] & CTYPE_LOWER, 0);
            assert_eq!(toupper(0xdf), 0xdf);
            assert_eq!(tolower(0xdf), 0xdf);
            // High bytes: all zero flags in the C locale.
            assert_eq!(tolower(0xff), 0xff);
            assert_eq!(toupper(0x80), 0x80);
        }
    }

    /// The embedded table must only flag ASCII letters for case conversion
    /// (this is what makes the ASCII reference valid).
    #[test]
    fn table_case_bits_are_ascii_only() {
        for c in 0..256i32 {
            let flags = CTYPE_TABLE[c as usize];
            assert_eq!(flags & CTYPE_UPPER != 0, (0x41..=0x5a).contains(&c));
            assert_eq!(flags & CTYPE_LOWER != 0, (0x61..=0x7a).contains(&c));
            // No entry carries both case bits.
            assert_eq!(flags & (CTYPE_UPPER | CTYPE_LOWER) == (CTYPE_UPPER | CTYPE_LOWER), false);
        }
    }

    #[test]
    fn isdigit_reads_the_installed_table_and_requires_exact_digit_class() {
        let _guard = ISDIGIT_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(base) = *ISDIGIT_FIXTURE else {
            assert!(note_missing_u32_fixture("runtime::ctype::isdigit"));
            return;
        };
        unsafe {
            let table = (base as *mut u8).add(1);
            ptr::write_bytes(base as *mut u8, 0, ISDIGIT_FIXTURE_LEN);
            ptr::copy_nonoverlapping(CTYPE_FLAGS.as_ptr(), table, CTYPE_FLAGS.len());

            let slot = __rt_ctype_table_addr();
            let _reset = CtypeTableSlotReset { slot, saved: slot.read_volatile() };
            slot.write_volatile(table as usize as u32);

            for c in -1..=255 {
                let expected = i32::from((b'0' as i32..=b'9' as i32).contains(&c));
                assert_eq!(isdigit(c), expected, "isdigit({c:#x})");
            }

            // The instruction is `cmp table[c], #0x20`, not a range or bit test.
            table.add(b'A' as usize).write(0x20);
            table.add(b'0' as usize).write(0x21);
            assert_eq!(isdigit(b'A' as i32), 1);
            assert_eq!(isdigit(b'0' as i32), 0);
        }
    }
}
