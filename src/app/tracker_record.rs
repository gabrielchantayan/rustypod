//! The two-word runtime-data record name accessor.
//!
//! - `tracker_record_name` — original: `FUN_082a7774` @ `0x082a7774`
//!   (8 bytes; 30 direct `bl` call sites, 0 predicated, 0 tail `b`, 0
//!   data-word references — never dispatched virtually).
//! - `tracker_record_matches` — original: `FUN_082a777c` @ `0x082a777c`
//!   (52 bytes; 7 direct `bl` call sites, all unconditional).

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

/// tracker_record_matches — original: `FUN_082a777c` @ `0x082a777c` (52 bytes).
///
/// Assembly decoded from `work/firmware/osos.dec` @
/// `0x082a777c..0x082a77b0`:
///
/// ```text
/// 082a777c  push    {r4, r5, r6, lr}
/// 082a7780  cmp     r0, r1
/// 082a7788  beq     0x082a77a8
/// 082a778c  bl      0x082a7774
/// 082a7798  bl      0x082a7774
/// 082a779c  cmp     r5, r0
/// 082a77a0  movne   r0, #0
/// 082a77a4  popne   {r4, r5, r6, pc}
/// 082a77a8  mov     r0, #1
/// 082a77ac  pop     {r4, r5, r6, pc}
/// ```
///
/// Ghidra's 52-byte extent is exact: the separately linked next function
/// begins with `push {r4, r5, r6, lr}` at `0x082a77b0`. Decoding every ARM
/// B/BL-immediate word in osos.dec finds seven inbound calls, all plain
/// unconditional `bl` (at 0x080c5344, 0x080c5374, 0x080ccca8, 0x080ccd14,
/// 0x080dd40c, 0x080dd500, and 0x082ab4f4), with zero predicated forms,
/// zero direct tail branches, and no data-word references.
///
/// Algorithm: identical record addresses compare equal without reading
/// either record. Otherwise, load each record's name word at +0x04 through
/// `tracker_record_name` and compare the full 32-bit values. The result is
/// canonicalized to exactly zero or one. Deliberate deviations: none.
///
/// # Safety
///
/// When `left` and `right` differ, each must be non-null, word-aligned, and
/// readable through its second `u32` word (+0x04..+0x08). Equal pointers are
/// compared without dereference.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tracker_record_matches")]
pub unsafe extern "C" fn tracker_record_matches(left: *const u32, right: *const u32) -> u32 {
    if left == right || tracker_record_name(left) == tracker_record_name(right) {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod identity_tests {
    extern crate std;

    use super::*;

    #[test]
    fn identical_record_compares_equal_without_reading_its_name() {
        extern "C" {
            fn mmap(addr: usize, len: usize, prot: i32, flags: i32, fd: i32, offset: i64)
                -> usize;
            fn getpagesize() -> i32;
        }
        #[cfg(target_os = "macos")]
        const MAP_PRIVATE_ANON: i32 = 0x1002;
        #[cfg(target_os = "linux")]
        const MAP_PRIVATE_ANON: i32 = 0x22;
        const PROT_NONE: i32 = 0;

        unsafe {
            let page = getpagesize() as usize;
            let inaccessible = mmap(0, page, PROT_NONE, MAP_PRIVATE_ANON, -1, 0);
            assert_ne!(inaccessible, usize::MAX, "mmap failed");
            let record = inaccessible as *const u32;
            assert_eq!(tracker_record_matches(record, record), 1);
        }
    }

    #[test]
    fn distinct_records_compare_their_name_words() {
        let left = [0x0897b904u32, 0xdec0ded];
        let same_name = [0x00000000u32, 0xdec0ded];
        let different_name = [0xffffffffu32, 0xdec0dee];

        unsafe {
            assert_eq!(tracker_record_matches(left.as_ptr(), same_name.as_ptr()), 1);
            assert_eq!(tracker_record_matches(left.as_ptr(), different_name.as_ptr()), 0);
        }
    }

    #[test]
    fn preserves_zero_and_all_ones_name_words() {
        let zero = [0u32, 0];
        let ones = [u32::MAX, u32::MAX];

        assert_eq!(unsafe { tracker_record_matches(zero.as_ptr(), zero.as_ptr()) }, 1);
        assert_eq!(unsafe { tracker_record_matches(zero.as_ptr(), ones.as_ptr()) }, 0);
    }

    #[test]
    fn leaves_distinct_records_unmodified() {
        let left = [0x11223344u32, 0x55667788];
        let right = [0x99aabbccu32, 0x55667788];
        let left_before = left;
        let right_before = right;

        assert_eq!(unsafe { tracker_record_matches(left.as_ptr(), right.as_ptr()) }, 1);
        assert_eq!(left, left_before);
        assert_eq!(right, right_before);
    }
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

/// tracker_record_from_payload — original: `FUN_082ab68c` @ `0x082ab68c`
/// (52 bytes).
///
/// Raw ARM from `work/firmware/osos.dec`:
///
/// ```text
/// 082ab68c  cmp     r0, #0
/// 082ab690  push    {r4, lr}
/// 082ab694  ldrne   r0, [r0]
/// 082ab698  cmpne   r0, #0
/// 082ab69c  bne     0x082ab6ac
/// 082ab6a0  bl      0x08033714
/// 082ab6a4  mov     r0, #0
/// 082ab6a8  pop     {r4, pc}
/// 082ab6ac  ldr     r4, [r0, #-4]
/// 082ab6b0  cmp     r4, #0
/// 082ab6b4  bleq    0x08033714
/// 082ab6b8  mov     r0, r4
/// 082ab6bc  pop     {r4, pc}
/// ```
///
/// The independently linked next function starts with `push {r4, r5, lr}` at
/// `0x082ab6c0`, confirming Ghidra's 52-byte extent. Complete ARM
/// B/BL-immediate decoding finds seven inbound calls, all unconditional
/// plain `bl` (at 0x080c533c, 0x080c536c, 0x080ccca0, 0x080ccd0c,
/// 0x080dd404, 0x080dd4f8, and 0x082ab4ec); no predicated direct call reaches
/// this entry.
///
/// Algorithm: require a non-null `payload_slot`, then a non-null payload
/// pointer in that slot, then a nonzero tracker-record word immediately
/// preceding the payload. Return that prefix word. Each failure calls
/// `0x08033714`, an ARM branch alias for the already ported `__rt_exit` at
/// `0x08033720`, which does not return. The tracker-record relationship is
/// established by all callers passing the result to `FUN_082a777c`, the
/// record identity/name comparator.
///
/// Deliberate deviation: host tests replace the non-returning exit path with
/// a catchable panic inside the Rust body; firmware builds call `__rt_exit`
/// directly.
///
/// # Safety
///
/// `payload_slot` must be null or point to one readable payload pointer. A
/// non-null payload must be word-aligned and readable for the preceding
/// `u32` tracker-record word.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tracker_record_from_payload")]
pub unsafe extern "C" fn tracker_record_from_payload(payload_slot: *const *const u32) -> u32 {
    tracker_record_from_payload_body(payload_slot)
}

unsafe fn tracker_record_from_payload_body(payload_slot: *const *const u32) -> u32 {
    if payload_slot.is_null() {
        missing_payload_tracker_record();
    }

    let payload = payload_slot.read();
    if payload.is_null() {
        missing_payload_tracker_record();
    }

    let record = payload.sub(1).read();
    if record == 0 {
        missing_payload_tracker_record();
    }
    record
}

#[cfg(not(test))]
unsafe fn missing_payload_tracker_record() -> ! {
    crate::runtime::exit::__rt_exit(0)
}

#[cfg(test)]
unsafe fn missing_payload_tracker_record() -> ! {
    panic!("required payload tracker record is missing")
}

#[cfg(test)]
mod payload_tracker_record_tests {
    extern crate std;

    use super::*;

    #[test]
    fn returns_the_nonzero_prefix_tracker_record() {
        let storage = [0x0897b904u32, 0x11223344];
        let payload = unsafe { storage.as_ptr().add(1) };
        let payload_slot = &payload;

        assert_eq!(
            unsafe { tracker_record_from_payload(payload_slot) },
            0x0897b904
        );
    }

    #[test]
    fn preserves_the_payload_and_prefix_words() {
        let storage = [u32::MAX, 0x55667788];
        let before = storage;
        let payload = unsafe { storage.as_ptr().add(1) };

        assert_eq!(
            unsafe { tracker_record_from_payload(&payload) },
            u32::MAX
        );
        assert_eq!(storage, before);
    }

    #[test]
    fn rejects_null_slot_null_payload_and_zero_prefix() {
        let null_slot = std::panic::catch_unwind(|| unsafe {
            tracker_record_from_payload_body(core::ptr::null())
        });
        assert!(null_slot.is_err());

        let null_payload: *const u32 = core::ptr::null();
        let null_payload = std::panic::catch_unwind(|| unsafe {
            tracker_record_from_payload_body(&null_payload)
        });
        assert!(null_payload.is_err());

        let storage = [0u32, 0x55667788];
        let payload = unsafe { storage.as_ptr().add(1) };
        let zero_prefix = std::panic::catch_unwind(|| unsafe {
            tracker_record_from_payload_body(&payload)
        });
        assert!(zero_prefix.is_err());
    }
}
