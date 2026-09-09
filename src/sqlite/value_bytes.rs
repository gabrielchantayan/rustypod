//! SQLite value byte counts — public UTF-8 wrapper plus its extractor.
//!
//! - `sqlite_value_bytes` — original: `FUN_083864c0` @ `0x083864c0`
//!   (68 bytes, `0x083864c0..0x08386504`; no `bl` callers, two
//!   unconditional tail branches from the public UTF-8/UTF-16 wrappers).
//! - `sqlite3_value_bytes` — original: `FUN_08391750` @ `0x08391750`
//!   (8 bytes, `0x08391750..0x08391758`; 14 unconditional `bl` call
//!   sites, no predicated forms, binary-scanned). Raw words
//!   `e3a01001 eaffd359`: set `r1 = SQLITE_UTF8` then tail-branch to
//!   `sqlite3ValueBytes` @ `0x083864c0`.
//!
//! Algorithm: `sqlite_value_bytes` reads `Mem.flags` before any guard.
//! A non-blob (`MEM_Blob` clear) is forced through the already-ported
//! [`sqlite_value_text`](super::value_text::sqlite_value_text); a NULL
//! result returns zero. This firmware deliberately gates on `MEM_Blob`
//! (0x10), not upstream SQLite 3.5.9's `MEM_Str` (0x2): blobs skip text
//! coercion. It reloads flags after the potential conversion, returns
//! `Mem.n` normally, and for `MEM_Zero` returns the low 32 bits of the
//! signed 64-bit `Mem.i + Mem.n` add. `Mem.i` holds the zero-tail count
//! in this retailOS layout.
//!
//! Deliberate deviations: none. The source follows the raw retailOS
//! branch predicate rather than upstream's `MEM_Str` predicate.

use super::error::SQLITE_UTF8;
use super::value_new::MEM_FLAGS_OFFSET;
use super::value_text::{sqlite_value_text, MEM_BLOB, MEM_ZERO};

/// Byte offset of `Mem.n` (original: `ldr r0,[r4,#0x18]`).
const MEM_N_OFFSET: usize = 0x18;

/// sqlite_value_bytes — original: `FUN_083864c0` @ `0x083864c0` (68
/// bytes).
///
/// The internal `sqlite3ValueBytes(value, enc)` extractor. It has no
/// NULL guard: like the original's opening `ldrh r2,[r0,#0x1c]`, callers
/// must supply a live, 8-byte-aligned 0x28-byte `Mem`. Returns the byte
/// count in `r0`; `MEM_Zero` preserves the original's wrapping low-word
/// result from the `ldrd`/`adds`/`adc` signed 64-bit addition.
///
/// # Safety
/// `value` must name a live, 8-byte-aligned `Mem` whose `flags` at
/// +0x1c and `n` at +0x18 are readable. For `MEM_Zero`, the `i64` at
/// +0x00 must also be readable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_value_bytes(value: *mut u8, enc: u8) -> i32 {
    let flags_ptr = value.add(MEM_FLAGS_OFFSET) as *const u16;
    if flags_ptr.read() & MEM_BLOB == 0 && sqlite_value_text(value, enc).is_null() {
        return 0;
    }

    let flags = flags_ptr.read();
    let n = (value.add(MEM_N_OFFSET) as *const i32).read();
    if flags & MEM_ZERO != 0 {
        let zero_tail = (value as *const i64).read();
        zero_tail.wrapping_add(i64::from(n)) as i32
    } else {
        n
    }
}

/// sqlite3_value_bytes — original: `FUN_08391750` @ `0x08391750` (8
/// bytes).
///
/// Public SQLite API wrapper: forces `enc = SQLITE_UTF8` (1) and
/// tail-branches to [`sqlite_value_bytes`]. All 14 direct `bl` callers
/// are unconditional, so this wrapper deliberately has no NULL guard;
/// the extractor performs its raw opening flags load before any text
/// conversion.
///
/// # Safety
/// Same contract as [`sqlite_value_bytes`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_value_bytes(value: *mut u8) -> i32 {
    sqlite_value_bytes(value, SQLITE_UTF8)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use super::super::value_new::MEM_SIZE;

    /// Matches the source `ldrd r0,[r4]` alignment requirement.
    #[repr(align(8))]
    struct TestMem([u8; MEM_SIZE as usize]);

    impl TestMem {
        fn new(flags: u16, zero_tail: i64, n: i32) -> Self {
            let mut mem = Self([0xa5; MEM_SIZE as usize]);
            mem.0[..8].copy_from_slice(&zero_tail.to_ne_bytes());
            mem.0[MEM_N_OFFSET..MEM_N_OFFSET + 4].copy_from_slice(&n.to_ne_bytes());
            mem.0[MEM_FLAGS_OFFSET..MEM_FLAGS_OFFSET + 2].copy_from_slice(&flags.to_ne_bytes());
            mem
        }

        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
    }

    #[test]
    fn blobs_skip_text_coercion_even_with_a_null_z() {
        unsafe {
            // A wrong MEM_Str gate would call sqlite_value_text; with
            // its +0x14 z left NULL that path returns zero. The retail
            // MEM_Blob gate returns n without touching text state.
            let mut mem = TestMem::new(MEM_BLOB, 0x1122_3344_5566_7788, 37);
            assert_eq!(sqlite_value_bytes(mem.ptr(), 3), 37);
            assert_eq!(sqlite3_value_bytes(mem.ptr()), 37);
        }
    }

    #[test]
    fn zero_blobs_return_the_wrapping_i_plus_n_low_word() {
        unsafe {
            for (zero_tail, n) in [
                (0i64, 0i32),
                (9, -3),
                (i64::from(i32::MAX), 1),
                (i64::from(i32::MIN), -1),
                (0x0000_0001_ffff_fffe, 5),
            ] {
                let mut mem = TestMem::new(MEM_BLOB | MEM_ZERO, zero_tail, n);
                let want = zero_tail.wrapping_add(i64::from(n)) as i32;
                assert_eq!(sqlite_value_bytes(mem.ptr(), 2), want, "i={zero_tail} n={n}");
            }
        }
    }

    #[test]
    fn a_non_blob_null_value_routes_through_text_and_returns_zero() {
        unsafe {
            // MEM_Null is deliberately not MEM_Blob, so the extractor
            // invokes sqlite_value_text. Its early NULL exit yields the
            // original's `cmp r0,#0; popeq` zero result rather than n.
            let mut mem = TestMem::new(1, 19, 73);
            assert_eq!(sqlite_value_bytes(mem.ptr(), 2), 0);
            assert_eq!(sqlite3_value_bytes(mem.ptr()), 0);
        }
    }
}
