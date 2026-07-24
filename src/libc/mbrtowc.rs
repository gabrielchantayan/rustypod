//! Port of the ARM ADS 1.0.1 wide-char → multibyte conversion routine —
//! `wcrtomb` semantics, despite the module name. Original:
//! `FUN_08035588` @ 0x08035588 (112 bytes), called by the printf `%ls`
//! handler @ 0x0803218c to turn each u16 wide char of a wide string into
//! bytes in a caller buffer: `wcrtomb(dst, wide_char, mbstate)`.
//!
//! Algorithm (from the disassembly):
//! 1. Load the active LC_CTYPE locale block pointer (on device:
//!    libspace+0x24, fetched via the helper @ 0x0802eca0).
//! 2. Read the locale's MB_CUR_MAX byte at block+0x101. If it is 1,
//!    tail-call the locale's own converter at
//!    `block + *(u32 __packed*)(block+0x107) + 0x107` (a self-relative
//!    function offset) with `(dst, wc, state)` and return its result.
//! 3. Otherwise: if `wc <= 0xff` and the ctype flag byte `block[wc]` is
//!    nonzero, store `wc` as a single byte to `dst` and return 1;
//!    else return -1 (EILSEQ). `state` is only ever forwarded to the
//!    converter in step 2.
//!
//! Retail-firmware quirk: setlocale @ 0x08030860 only knows the "C" locale
//! and stores block+1 = 0x08985f01 into libspace+0x24. That block is just
//! the 256 ctype flag bytes, so block+0x101 actually reads the second byte
//! of the adjacent leap-year month-length table (29 = February), never 1 —
//! with the retail locale the converter tail-call is dead code and the
//! function is exactly "single byte iff wc < 0x80, else -1" (all C-locale
//! ctype flags for 0x80..=0xff are zero). Both paths are ported anyway.
//!
//! Deviations from the original:
//! - The locale slot is modeled as `static mut LOCALE_CTYPE_PTR`,
//!    initialized to the `C_LOCALE_CTYPE` replica below. On device the
//!    slot is zero until the first setlocale call (the original would
//!    dereference null); retailOS calls setlocale during startup, so the
//!    C block is the state every real caller observes.
//! - The 256 ctype flag bytes are the same values as `ctype::CTYPE_TABLE`
//!    (extracted from osos rodata @ 0x08985f01); they are duplicated here
//!    to keep this module self-contained. The replica extends two bytes
//!    past the flags (0x1f, 0x1d — start of the leap-year month table) so
//!    the MB_CUR_MAX read at block+0x101 sees the same 29 as the original.
//! - The slot read is done with `read_volatile` (the original's is a plain
//!    `ldr`): without it LLVM folds the whole function to "wc < 0x80"
//!    constants, since nothing in the crate ever writes the static.
//! - Ghidra shows the converter address masked with 0xfffffffc; the actual
//!    `mov pc, r3` has no mask, so the port applies none.

/// Replica of the retail "C" LC_CTYPE block as seen through the biased
/// pointer setlocale stores (block base 0x08985f00, stored as base+1):
/// bytes 0..=0xff are the ctype flags, byte 0x100 is 0x1f and byte 0x101
/// (read as MB_CUR_MAX) is 0x1d = 29 — both belong to the leap-year
/// month-length table that follows the flags in rodata.
pub static C_LOCALE_CTYPE: [u8; 0x102] = [
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
    // Trailing rodata the original's out-of-bounds locale reads land on:
    // block[0x100] = 31 (January), block[0x101] = 29 (leap February) — the
    // value the original compares against 1 as "MB_CUR_MAX".
    0x1f, 0x1d,
];

/// Model of the libspace+0x24 locale block pointer slot (the word the
/// original loads after `bl 0x0802eca0`). On device it is filled in by
/// setlocale @ 0x08030860; here it defaults to the retail C-locale block.
/// Read through `read_volatile` in `wcrtomb` so the runtime load is not
/// folded away — on device this word genuinely changes under the program
/// when setlocale runs.
static mut LOCALE_CTYPE_PTR: *const u8 = &C_LOCALE_CTYPE as *const u8;

/// The locale's own wide→multibyte converter, reached by self-relative
/// offset when MB_CUR_MAX == 1 (see module docs).
type LocaleConverter = unsafe extern "C" fn(dst: *mut u8, wc: u32, state: *mut u32) -> i32;

/// Shared body, parameterized on the locale block so host tests can drive
/// both paths without touching the global slot.
#[inline(always)]
unsafe fn convert(locale: *const u8, dst: *mut u8, wc: u32, state: *mut u32) -> i32 {
    // ldrb r1, [locale, #0x101]; cmp r1, #1
    if locale.add(0x101).read() == 1 {
        // Self-relative converter offset: ADS __packed u32 at locale+0x107,
        // target = locale + offset + 0x107 (no alignment mask in the asm).
        // The offset is sign-extended before the add: on 32-bit ARM this is
        // the same wrapping `add r0, r0, r1` either way, but it keeps the
        // arithmetic correct when this path is exercised on a 64-bit host.
        let rel = (locale.add(0x107) as *const u32).read_unaligned();
        let converter: LocaleConverter =
            core::mem::transmute(locale.wrapping_add(rel as i32 as usize).wrapping_add(0x107));
        return converter(dst, wc, state);
    }
    // cmp wc, #0xff; bhi fail
    if wc < 0x100 && locale.add(wc as usize).read() != 0 {
        // movne r0, #1; strbne wc, [dst]
        dst.write(wc as u8);
        1
    } else {
        // mvn r0, #0
        -1
    }
}

/// wcrtomb — original: `FUN_08035588` @ 0x08035588 (112 bytes).
///
/// Converts the wide char `wc` to its multibyte representation in `dst`,
/// returning the number of bytes written (1) or -1 if `wc` has no
/// single-byte representation in the active locale. `state` (mbstate_t*)
/// is only forwarded to the locale converter in the MB_CUR_MAX == 1 path.
#[no_mangle]
pub unsafe extern "C" fn wcrtomb(dst: *mut u8, wc: u32, state: *mut u32) -> i32 {
    // bl __rt_ctype_table_addr; ldr r0, [r0]
    convert(core::ptr::read_volatile(core::ptr::addr_of!(LOCALE_CTYPE_PTR)), dst, wc, state)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::ptr;

    /// Sentinel byte to prove `dst` is untouched on failure.
    const UNTOUCHED: u8 = 0xAA;

    /// Independent reference derived from the asm: valid iff wc <= 0xff
    /// and the locale's ctype flag byte for wc is nonzero.
    fn reference(locale: &[u8], wc: u32) -> Option<u8> {
        if wc < 0x100 && locale[wc as usize] != 0 {
            Some(wc as u8)
        } else {
            None
        }
    }

    /// The embedded C-locale flags are nonzero exactly for 0x00..=0x7f,
    /// so in the retail locale validity reduces to "wc fits in ASCII".
    #[test]
    fn c_locale_flags_nonzero_iff_ascii() {
        for c in 0..256usize {
            assert_eq!(C_LOCALE_CTYPE[c] != 0, c < 0x80, "flags[{c:#x}]");
        }
        // The byte the original reads as MB_CUR_MAX is 29, never 1.
        assert_eq!(C_LOCALE_CTYPE[0x101], 29);
    }

    /// All 256 single-byte candidates through the exported entry point
    /// (default C locale), checked against the independent reference.
    #[test]
    fn c_locale_all_byte_values() {
        for wc in 0..=0xffu32 {
            let mut dst = [UNTOUCHED; 4];
            let mut state = 0xdead_beefu32;
            let ret = unsafe { wcrtomb(dst.as_mut_ptr(), wc, &mut state) };
            match reference(&C_LOCALE_CTYPE, wc) {
                Some(byte) => {
                    assert_eq!(ret, 1, "wc={wc:#x} must convert");
                    assert_eq!(dst[0], byte, "wc={wc:#x} wrong output byte");
                    assert_eq!(&dst[1..], &[UNTOUCHED; 3], "wc={wc:#x} wrote past byte 0");
                }
                None => {
                    assert_eq!(ret, -1, "wc={wc:#x} must fail");
                    assert_eq!(dst, [UNTOUCHED; 4], "wc={wc:#x} clobbered dst on failure");
                }
            }
            assert_eq!(state, 0xdead_beef, "wc={wc:#x} clobbered state");
        }
    }

    /// Anything above 0xff fails without touching dst, however large.
    #[test]
    fn rejects_beyond_single_byte() {
        for wc in [0x100u32, 0x1234, 0xffff, 0x1_0000, 0x7fff_ffff, u32::MAX] {
            let mut dst = [UNTOUCHED; 2];
            let ret = unsafe { wcrtomb(dst.as_mut_ptr(), wc, ptr::null_mut()) };
            assert_eq!(ret, -1, "wc={wc:#x} must fail");
            assert_eq!(dst, [UNTOUCHED; 2], "wc={wc:#x} clobbered dst");
        }
    }

    /// A non-1 MB_CUR_MAX still takes the single-byte path, honoring the
    /// block's own flag bytes (driven via a private block, no globals).
    #[test]
    fn non_one_mb_cur_max_uses_flag_path() {
        let mut block = [0u8; 0x108];
        block[0x101] = 2; // "multibyte" locale, per the original's test
        block[0xe9] = 0x42; // any nonzero flag makes the byte valid
        let mut dst = [UNTOUCHED; 2];
        unsafe {
            assert_eq!(convert(block.as_ptr(), dst.as_mut_ptr(), 0xe9, ptr::null_mut()), 1);
            assert_eq!(dst[0], 0xe9);
            assert_eq!(convert(block.as_ptr(), dst.as_mut_ptr(), b'x' as u32, ptr::null_mut()), -1);
            assert_eq!(convert(block.as_ptr(), dst.as_mut_ptr(), 0x100, ptr::null_mut()), -1);
        }
    }

    /// Record of what the test converter was called with.
    static mut CONV_ARGS: (*mut u8, u32, *mut u32) = (ptr::null_mut(), 0, ptr::null_mut());

    /// Crafted locale block for the MB_CUR_MAX == 1 path. It must be a
    /// static (not a stack buffer) so the 32-bit self-relative offset to
    /// `test_converter` actually fits 32 bits on a 64-bit host.
    static mut CONV_BLOCK: [u8; 0x120] = [0; 0x120];

    unsafe extern "C" fn test_converter(dst: *mut u8, wc: u32, state: *mut u32) -> i32 {
        CONV_ARGS = (dst, wc, state);
        dst.write(0x5a);
        if !state.is_null() {
            state.write(0xc0ff_ee00);
        }
        7
    }

    /// MB_CUR_MAX == 1 tail-calls the converter found by self-relative
    /// offset at block+0x107, forwards (dst, wc, state) verbatim, and
    /// returns its result. The crafted block points the offset at a real
    /// host function exactly the way the locale block would on device.
    #[test]
    fn mb_cur_max_one_calls_locale_converter() {
        let block = core::ptr::addr_of_mut!(CONV_BLOCK) as *mut u8;
        unsafe {
            block.add(0x101).write(1);
            let rel = (test_converter as *const () as usize)
                .wrapping_sub(block as usize)
                .wrapping_sub(0x107);
            core::ptr::copy_nonoverlapping((rel as u32).to_le_bytes().as_ptr(), block.add(0x107), 4);
        }

        let mut dst = [UNTOUCHED; 2];
        let mut state = 0u32;
        let ret = unsafe { convert(block as *const u8, dst.as_mut_ptr(), 0x20ac, &mut state) };
        assert_eq!(ret, 7, "converter result must be returned verbatim");
        assert_eq!(dst[0], 0x5a, "converter did not run");
        assert_eq!(state, 0xc0ff_ee00, "state not forwarded");
        let args = unsafe { core::ptr::addr_of!(CONV_ARGS).read() };
        assert_eq!(args.1, 0x20ac, "wc not forwarded");
        assert_eq!(args.0, dst.as_mut_ptr(), "dst not forwarded");
        assert_eq!(args.2, &mut state as *mut u32, "state pointer not forwarded");
    }
}
