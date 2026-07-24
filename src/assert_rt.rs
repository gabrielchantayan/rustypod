//! ARM ADS C-locale getters — three identical compiler-emitted wrappers of
//! the shape `_get_lc_*(void *unused, const char *name)`:
//!
//! - `get_lc_ctype` — original: `FUN_0803350c` @ 0x0803350c (52 bytes).
//!   Returns the C-locale ctype block @ 0x08985f00, i.e. `ctype_table - 1`
//!   (the ADS __ctype flags table with its EOF guard byte; the table itself
//!   is identified in names.yaml and ported in ctype.rs).
//! - `get_lc_c_block_080355f8` — original: `FUN_080355f8` @ 0x080355f8
//!   (52 bytes). Identical body; returns the block @ 0x08986254 (starts
//!   with 0x0c, 0x0e, 0x0f, '.' — a numeric/monetary-style C-locale data
//!   block; exact ADS category not confirmed).
//! - `get_lc_c_block_08036b80` — original: `FUN_08036b80` @ 0x08036b80
//!   (52 bytes). Identical body; returns the block @ 0x0898654c (an offset
//!   table immediately preceding the ADS signal-name strings "Abnormal
//!   termination"/"Arithmetic exception: "/...; category not confirmed).
//!
//! Algorithm (all three copies, instruction-identical modulo literals):
//! the first argument (r0) is discarded (`movs r0, r1`); if `name` is
//! non-NULL and `name[0] != '\0'`, call the ADS strcmp @ 0x08391e38 with
//! (name, "C") — the "C\0" literal sits in the literal pool right after
//! each copy — and return NULL when the strings differ. Otherwise (name
//! NULL, empty, or exactly "C") return a pc-relative pointer to the
//! compiled-in C-locale data block.
//!
//! Corrections / deviations from the original and from the initial
//! assignment notes:
//! - 0x08391e38 is NOT an assert printer/abort. Disassembly shows a
//!   textbook ADS strcmp (byte loop, returns -1/0/1 on the first
//!   differing byte, unsigned comparison); Ghidra's
//!   034/08391e38_thunk_FUN_08391e44.c agrees. These wrappers are the
//!   ADS per-category C-locale getters, not __assert printer wrappers.
//! - The returned locale data blocks are stubbed: each wrapper hands back
//!   a pointer to a private placeholder `static` below. Only the
//!   pointer-selection contract (NULL vs block pointer, and which block)
//!   is modeled, not the block contents. Original block addresses are
//!   documented above; the real ctype table belongs to ctype.rs.
//! - strcmp @ 0x08391e38 is mirrored as the private helper `strcmp_ads`
//!   (kept crate-private so it cannot collide with a canonical strcmp
//!   port elsewhere in this crate).
//!
//! Host `cargo test` exercises both path selections (NULL/empty/"C" vs
//! any other string) and string passthrough directly — the branch is
//! pure, so no mock hook is needed; only the block pointers are stubbed.

/// Placeholder for the C-locale ctype block (original: `ctype_table - 1`
/// @ 0x08985f00, EOF guard byte + 256 flag bytes). Contents not modeled.
static LC_CTYPE_C_BLOCK: u8 = 0;

/// Placeholder for the C-locale data block @ 0x08986254 in the original.
static LC_C_BLOCK_080355F8: u8 = 0;

/// Placeholder for the C-locale data block @ 0x0898654c in the original.
static LC_C_BLOCK_08036B80: u8 = 0;

/// strcmp — original: `thunk_FUN_08391e44`/`FUN_08391e44` @ 0x08391e38
/// (72 bytes). ADS byte-compare loop: walks while bytes are equal and
/// nonzero, then returns 1 / 0 / -1 from an unsigned comparison of the
/// first differing byte.
#[inline]
unsafe fn strcmp_ads(mut a: *const u8, mut b: *const u8) -> i32 {
    while *a == *b && *a != 0 {
        a = a.add(1);
        b = b.add(1);
    }
    let (x, y) = (*a, *b);
    if x > y {
        1
    } else if x == y {
        0
    } else {
        -1
    }
}

/// Shared body of the three wrappers: NULL when `name` is a nonempty
/// string other than "C", otherwise `c_block`.
#[inline(always)]
unsafe fn select_c_locale_block(name: *const u8, c_block: *const u8) -> *const u8 {
    if !name.is_null() && *name != 0 && strcmp_ads(name, b"C\0".as_ptr()) != 0 {
        return core::ptr::null();
    }
    c_block
}

/// _get_lc_ctype — original: `FUN_0803350c` @ 0x0803350c (52 bytes).
///
/// `unused` (r0) is ignored by the original (`movs r0, r1`); ADS callers
/// pass NULL. Returns the C-locale ctype block for NULL/empty/"C" `name`,
/// NULL for anything else.
#[no_mangle]
pub unsafe extern "C" fn get_lc_ctype(_unused: *const u8, name: *const u8) -> *const u8 {
    select_c_locale_block(name, &LC_CTYPE_C_BLOCK)
}

/// Alias of the same wrapper — original: `FUN_080355f8` @ 0x080355f8
/// (52 bytes). Identical body to `get_lc_ctype`, but returns the C-locale
/// data block @ 0x08986254 in the original.
#[no_mangle]
pub unsafe extern "C" fn get_lc_c_block_080355f8(
    _unused: *const u8,
    name: *const u8,
) -> *const u8 {
    select_c_locale_block(name, &LC_C_BLOCK_080355F8)
}

/// Alias of the same wrapper — original: `FUN_08036b80` @ 0x08036b80
/// (52 bytes). Identical body to `get_lc_ctype`, but returns the C-locale
/// data block @ 0x0898654c in the original.
#[no_mangle]
pub unsafe extern "C" fn get_lc_c_block_08036b80(
    _unused: *const u8,
    name: *const u8,
) -> *const u8 {
    select_c_locale_block(name, &LC_C_BLOCK_08036B80)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;

    const NULLP: *const u8 = ptr::null();

    #[test]
    fn null_name_selects_block() {
        unsafe {
            assert_eq!(get_lc_ctype(NULLP, NULLP), &LC_CTYPE_C_BLOCK as *const u8);
        }
    }

    #[test]
    fn empty_name_selects_block() {
        unsafe {
            assert_eq!(get_lc_ctype(NULLP, b"\0".as_ptr()), &LC_CTYPE_C_BLOCK as *const u8);
        }
    }

    /// String passthrough: "C" is the only nonempty name that selects the
    /// block, and it returns the same pointer as the NULL/empty paths.
    #[test]
    fn c_name_selects_same_block() {
        unsafe {
            let via_null = get_lc_ctype(NULLP, NULLP);
            let via_c = get_lc_ctype(NULLP, b"C\0".as_ptr());
            assert_eq!(via_c, via_null);
            assert!(!via_c.is_null());
        }
    }

    #[test]
    fn other_names_select_null() {
        unsafe {
            for name in [&b"x\0"[..], &b"c\0"[..], &b"CC\0"[..], &b"C \0"[..], &b"POSIX\0"[..]] {
                assert!(
                    get_lc_ctype(NULLP, name.as_ptr()).is_null(),
                    "name {name:?} should select NULL"
                );
            }
        }
    }

    /// The first argument is ignored by the original; a garbage pointer
    /// must not change the result.
    #[test]
    fn first_argument_is_ignored() {
        unsafe {
            let garbage = 0xdeadbeefusize as *const u8;
            assert_eq!(get_lc_ctype(garbage, b"C\0".as_ptr()), &LC_CTYPE_C_BLOCK as *const u8);
            assert!(get_lc_ctype(garbage, b"x\0".as_ptr()).is_null());
        }
    }

    /// Each alias applies the same selection to its own block.
    #[test]
    fn aliases_select_their_own_blocks() {
        unsafe {
            let a = get_lc_c_block_080355f8(NULLP, b"C\0".as_ptr());
            let b = get_lc_c_block_08036b80(NULLP, b"C\0".as_ptr());
            assert_eq!(a, &LC_C_BLOCK_080355F8 as *const u8);
            assert_eq!(b, &LC_C_BLOCK_08036B80 as *const u8);
            assert!(get_lc_c_block_080355f8(NULLP, b"x\0".as_ptr()).is_null());
            assert!(get_lc_c_block_08036b80(NULLP, b"x\0".as_ptr()).is_null());
            assert!(get_lc_c_block_080355f8(NULLP, NULLP) == a);
            assert!(get_lc_c_block_08036b80(NULLP, b"\0".as_ptr()) == b);
        }
    }

    /// Mirror of ADS strcmp @ 0x08391e38: -1/0/1, unsigned byte compare.
    #[test]
    fn strcmp_ads_matches_ads_semantics() {
        unsafe {
            assert_eq!(strcmp_ads(b"C\0".as_ptr(), b"C\0".as_ptr()), 0);
            assert_eq!(strcmp_ads(b"\0".as_ptr(), b"\0".as_ptr()), 0);
            assert_eq!(strcmp_ads(b"a\0".as_ptr(), b"b\0".as_ptr()), -1);
            assert_eq!(strcmp_ads(b"b\0".as_ptr(), b"a\0".as_ptr()), 1);
            // Prefix compares against the NUL, which sorts low.
            assert_eq!(strcmp_ads(b"ab\0".as_ptr(), b"abc\0".as_ptr()), -1);
            assert_eq!(strcmp_ads(b"abc\0".as_ptr(), b"ab\0".as_ptr()), 1);
            // Unsigned comparison: 0xff > 'a'.
            assert_eq!(strcmp_ads(b"\xff\0".as_ptr(), b"a\0".as_ptr()), 1);
            assert_eq!(strcmp_ads(b"a\0".as_ptr(), b"\xff\0".as_ptr()), -1);
        }
    }
}
