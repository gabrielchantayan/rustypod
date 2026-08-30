//! The two-word runtime-data record name accessor.
//!
//! - `tracker_record_name` — original: `FUN_082a7774` @ `0x082a7774`
//!   (8 bytes; 30 direct `bl` call sites, 0 predicated, 0 tail `b`, 0
//!   data-word references — never dispatched virtually).

/// tracker_record_name — original: `FUN_082a7774` @ `0x082a7774` (8 bytes).
///
/// Assembly decoded from `work/firmware/osos.dec` @
/// `0x082a7774..0x082a777c`:
///
/// ```text
/// 082a7774  ldr r0, [r0, #4]
/// 082a7778  mov pc, lr
/// ```
///
/// Ghidra's 8-byte extent is exact: the next function's
/// `push {r4, r5, r6, lr}` prologue opens at 0x082a777c (the two-record
/// identity comparator `FUN_082a777c`, which calls this accessor twice).
/// Call count verified by decoding every B/BL word in osos.dec: exactly
/// 30 unconditional `bl` sites, zero predicated forms, zero tail `b`
/// references, and no data word in the image holds 0x082a7774 — the
/// accessor is never dispatched virtually and callers never NULL-gate
/// it, so every caller hands it a live record.
///
/// Algorithm: loads and returns the full 32-bit word at byte offset
/// +0x04 of a two-word runtime-data record — the record's name pointer.
/// The record's first word is never read here. Established semantics:
/// the nine `element_arrayN_construct` instantiations (0x083d3c28 …
/// 0x083d56b8, ported in `app/element_table`) call it on a runtime-data
/// record literal (e.g. 0x0897b904) and immediately `strlen` the result
/// and copy it as the container's tracker/fTable name; the comparator
/// at 0x082a777c and the keyed-insert path at 0x0807d93c compare the
/// returned word of two records for identity. The word is written at
/// runtime (the image's record slots hold garbage), so no static name
/// string is recoverable.
///
/// Deviations: none. The read is a single aligned word load exactly
/// like the original's `ldr`. Carries its own `link_section` because
/// `runtime/object_word.rs`'s `object_word_at_4` is a byte-identical
/// body and LLVM's identical-code folding must never collapse the two
/// hook seams.
///
/// # Safety
///
/// `record` must be non-null, word-aligned, and readable through its
/// second `u32` word (+0x04..+0x08).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tracker_record_name")]
pub unsafe extern "C" fn tracker_record_name(record: *const u32) -> u32 {
    record.add(1).read()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    /// A minimal stand-in record: word +0x0 (never read by the
    /// accessor) and the name word at +0x4.
    fn record_with_name(name: u32) -> [u32; 2] {
        [0x0897b904, name]
    }

    #[test]
    fn returns_the_name_word() {
        let record = record_with_name(0x0897d210);
        assert_eq!(unsafe { tracker_record_name(record.as_ptr()) }, 0x0897d210);
    }

    #[test]
    fn ignores_the_first_word() {
        // Same +0x4 word, different +0x0 words: the result must not
        // depend on word zero.
        let a = [0x00000000u32, 0xdec0ded];
        let b = [0xffffffffu32, 0xdec0ded];
        assert_eq!(unsafe { tracker_record_name(a.as_ptr()) }, 0xdec0ded);
        assert_eq!(unsafe { tracker_record_name(b.as_ptr()) }, 0xdec0ded);
    }

    #[test]
    fn preserves_zero_and_all_ones_words() {
        let zero = record_with_name(0);
        let ones = record_with_name(u32::MAX);
        assert_eq!(unsafe { tracker_record_name(zero.as_ptr()) }, 0);
        assert_eq!(unsafe { tracker_record_name(ones.as_ptr()) }, u32::MAX);
    }

    #[test]
    fn leaves_the_record_unmodified() {
        let record = record_with_name(0x11223344);
        let before = record;
        unsafe { tracker_record_name(record.as_ptr()) };
        assert_eq!(record, before);
    }

    #[test]
    fn reads_no_byte_past_the_name_word() {
        extern "C" {
            fn mmap(addr: usize, len: usize, prot: i32, flags: i32, fd: i32, offset: i64)
                -> usize;
            fn mprotect(addr: usize, len: usize, prot: i32) -> i32;
            // arm64 macOS uses 16 KiB pages, x86_64 Linux 4 KiB. mprotect
            // rejects an unaligned base, so a hardcoded 0x1000 silently
            // fails everywhere the page is larger.
            fn getpagesize() -> i32;
        }
        #[cfg(target_os = "macos")]
        const MAP_PRIVATE_ANON: i32 = 0x1002;
        #[cfg(target_os = "linux")]
        const MAP_PRIVATE_ANON: i32 = 0x22;
        const PROT_READ_WRITE: i32 = 3;
        const PROT_NONE: i32 = 0;

        unsafe {
            let page = getpagesize() as usize;
            let base = mmap(0, 2 * page, PROT_READ_WRITE, MAP_PRIVATE_ANON, -1, 0);
            assert_ne!(base, usize::MAX, "mmap failed");
            assert_eq!(mprotect(base + page, page, PROT_NONE), 0, "mprotect failed");
            // End the record exactly at the guard page: the +0x4 word is
            // the last word of the readable page, so any read past +0x8
            // faults.
            let record = (base + page - 8) as *mut u32;
            record.add(1).write(0x5a5a5a5a);
            assert_eq!(tracker_record_name(record as *const u32), 0x5a5a5a5a);
        }
    }
}
