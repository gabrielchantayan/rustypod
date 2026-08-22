//! `string_record_range` — original: `FUN_081481ec` @ 0x081481ec
//! (**208 bytes** of code, 0x081481ec..0x081482bc, plus the 4-byte literal
//! pool word 0x089d00b4 @ 0x081482bc; the next function starts at
//! 0x081482c0 with `push {r4, r5, r6, lr}`, so the extent is exact.
//! **50 `bl` call sites, 0 `b`, 0 predicated**, binary-verified by decoding
//! every B/BL word in `osos.dec`.)
//!
//! The string-range accessor of a record object whose UTF-16 string is
//! materialized lazily into the two words at +0x54/+0x58 (begin/end u16
//! pointers). Besides returning that range, it is one of the two feeders of
//! the system-wide **active character set** — the global word @ 0x089d00b4
//! holds a `BitSet *` (the 16-byte set of `cxx/bit_set.rs`) installed by the
//! text-system object constructor @ 0x081b2a38 (`str r0, [r1]` with
//! r0 = this+0xb4) and consumed by the same inlined insert loop @
//! 0x08094034. When the caller passes a nonzero third argument, every
//! codepoint of the record's string is added to that set.
//!
//! # Algorithm
//!
//! ```text
//! 081481ec  push {r0, r1, r2, r4-r9, sl, fp, lr}
//! 081481f0  mov  fp, r1              @ fp = record
//! 081481f4  mov  r0, fp
//! 081481f8  mov  r1, #1
//! 08148200  mov  r4, r2              @ r4 = track
//! 08148204  bl   0x08147f7c          @ materialize(record, 1)
//! 08148208  cmp  r4, #0
//! 0814820c  ldrne sl, [pc, #168]     @ &ACTIVE_SET_WORD (literal 0x089d00b4)
//! 08148210  ldrne r0, [sl]
//! 08148214  cmpne r0, #0
//! 08148218  beq  0x081482a8          @ track==0 or no active set: skip
//! 0814821c  add  r1, fp, #0x54
//! 08148220  add  r0, sp, #8
//! 08148224  bl   0x080f020c          @ string_from_range(&tmp, record+0x54)
//! 08148228  ldr  r0, [sp, #12]       @ tmp.payload
//! 0814822c  bl   0x082770e0          @ utf8_codepoint_count_safe (ported)
//! 08148230  mov  r8, r0              @ r8 = count
//! 08148234  add  r0, sp, #8
//! 08148238  bl   0x082a50b0          @ string_object_c_str (ported)
//! 0814823c  mov  r5, #0              @ i
//! 08148240  mov  r9, #1
//! 08148244  str  r0, [sp, #4]        @ cursor
//! 08148248  b    0x08148298
//!   loop:
//! 0814824c  ldr  r4, [sl]            @ set = *ACTIVE_SET_WORD (reloaded!)
//! 08148250  add  r0, sp, #4
//! 08148254  bl   0x08276214          @ utf8_next_codepoint(&cursor) (ported)
//! 08148258  lsr  r6, r0, #5          @ word = cp >> 5
//! 0814825c  and  r7, r0, #31         @ bit  = cp & 31
//! 08148260  mov  r2, r7
//! 08148264  mov  r0, r4
//! 08148268  mov  r1, r6
//! 0814826c  bl   0x082a4ef8          @ bit_set_test(set, word, bit)
//! 08148270  cmp  r0, #0
//! 08148274  bne  0x08148294          @ already set: no recount
//! 08148278  ldr  r0, [r4, #4]
//! 0814827c  add  r0, r0, #1
//! 08148280  str  r0, [r4, #4]        @ set->cardinality += 1
//! 08148284  ldr  r0, [r4, #8]
//! 08148288  ldr  r1, [r0, r6, lsl #2]
//! 0814828c  orr  r1, r1, r9, lsl r7
//! 08148290  str  r1, [r0, r6, lsl #2] @ set->words[word] |= 1 << bit
//! 08148294  add  r5, r5, #1
//! 08148298  cmp  r5, r8
//! 0814829c  bcc  loop
//! 081482a0  add  r0, sp, #8
//! 081482a4  bl   0x08277484          @ string_object_destroy(&tmp) (ported)
//! 081482a8  ldr  r0, [sp, #16]       @ out (the spilled first argument)
//! 081482ac  add  sp, sp, #28
//! 081482b0  add  r1, fp, #0x54
//! 081482b4  pop  {r4-r9, sl, fp, lr}
//! 081482b8  b    0x081bb6a4          @ tail: copy 8 bytes range -> out
//! 081482bc  .word 0x089d00b4         @ ACTIVE_SET_WORD literal
//! ```
//!
//! The marking loop is the set path of the BitSet write @ 0x082746f4 with
//! value 1, inlined: test first, and only a clear bit bumps the running
//! cardinality. The loop runs exactly `count` iterations — it does NOT stop
//! early when the decoder returns 0 (unlike `bit_set_insert_utf8`), because
//! the trip count is fixed up front by `utf8_codepoint_count_safe`. The
//! active-set pointer is reloaded from the global on EVERY iteration
//! (`ldr r4, [sl]` inside the loop), so a set swapped in mid-walk receives
//! the remaining codepoints.
//!
//! # Callers and argument roles
//!
//! All 50 sites pass the record in r1 and an 8-byte out slot in r0; the
//! sampled clusters (0x08135e50..0x081360bc, 0x081dc718..0x081dca64,
//! 0x0820fbf8..0x0820fce4) all pass r2 = 1 and immediately forward the
//! range to a sibling consumer — r2 is a "track these characters" flag, not
//! a value ever dereferenced. The materializer @ 0x08147f7c has exactly ONE
//! call site — this function — and fills record+0x54/+0x58 behind the
//! done byte at record+0x64.
//!
//! # Deviations
//!
//! - The tail branch to the shared two-word copy @ 0x081bb6a4
//!   (`*out = *src; out[1] = src[1]`, decoded from its own bytes) is
//!   inlined as two word stores; a faithful tail call would need the
//!   unported copy routine as yet another seam for zero behavioral gain.
//! - `materialize` @ 0x08147f7c and `string_from_range` @ 0x080f020c (the
//!   UTF-16 range -> UTF-8 StringObject converter, with quote stripping and
//!   backslash unescaping) are unported and ride [`STRING_RECORD_OPS`]:
//!   target defaults transmute the retail addresses, host defaults panic.
//! - `bit_set_test` @ 0x082a4ef8 is unported but fully decoded (three
//!   instructions, pre-split index; see `cxx/bit_set.rs`), so its host
//!   default is a faithful model over [`BitSet::words`], not a stub — the
//!   cardinality recount decision depends on its result.
//! - The global set word @ 0x089d00b4 is read directly on target; host
//!   builds read the modeled [`ACTIVE_CHARACTER_SET`] static.
//! - `utf8_codepoint_count_safe`, `string_object_c_str`,
//!   `utf8_next_codepoint` and `string_object_destroy` are already ported
//!   and are called directly.

use crate::cxx::bit_set::BitSet;
use crate::cxx::string_object::{
    string_object_c_str, string_object_destroy, utf8_codepoint_count_safe, utf8_next_codepoint,
    StringObject,
};

/// Load address of the global word holding the active character set.
/// Written by the text-system object constructor @ 0x081b2a38; read here
/// and by the inlined sibling insert loop @ 0x08094034.
#[cfg(target_os = "none")]
const ACTIVE_CHARACTER_SET_ADDRESS: usize = 0x089d_00b4;

/// Host model of the global word @ 0x089d00b4: the character set the
/// marking loop feeds, NULL when no text-system object has installed one.
#[cfg(not(target_os = "none"))]
pub static mut ACTIVE_CHARACTER_SET: *mut BitSet = core::ptr::null_mut();

/// Byte offset of the record's materialized UTF-16 range (begin/end u16
/// pointers, one word each).
const STRING_RANGE_OFFSET: usize = 0x54;

/// Reads the active character set, from the firmware global on target and
/// from the modeled static on host. Volatile: the original reloads the
/// word on every loop iteration, and a plain host read of the static would
/// let LLVM hoist it out of the loop.
#[inline(always)]
unsafe fn active_character_set() -> *mut BitSet {
    #[cfg(target_os = "none")]
    {
        core::ptr::read_volatile(ACTIVE_CHARACTER_SET_ADDRESS as *const *mut BitSet)
    }
    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(ACTIVE_CHARACTER_SET))
    }
}

/// Indirect dispatch for the three unported callees (see the module
/// header). Target defaults transmute the retail addresses; host tests
/// install recording models — except `bit_set_test`, whose host default is
/// the faithful three-instruction model.
#[derive(Clone, Copy)]
pub struct StringRecordOps {
    /// `FUN_08147f7c(record, 1)`: lazily decodes the record's string into
    /// the u16 range words at +0x54/+0x58 (no-op once the +0x64 byte is
    /// set). Sole call site in the image is the ported function.
    pub materialize: unsafe extern "C" fn(record: *mut u8, mode: u32),
    /// `FUN_080f020c(this, range)`: builds a StringObject from the UTF-16
    /// range, stripping surrounding quotes and resolving backslash
    /// escapes; the payload ends up as NUL-terminated UTF-8.
    pub string_from_range: unsafe extern "C" fn(this: *mut StringObject, range: *const u8),
    /// `FUN_082a4ef8(set, word, bit)`: tests `set->words[word] & 1 << bit`,
    /// normalized to 0/1. The index arrives PRE-SPLIT by the caller.
    pub bit_set_test: unsafe extern "C" fn(set: *mut BitSet, word: u32, bit: u32) -> u32,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_materialize(record: *mut u8, mode: u32) {
    let f: unsafe extern "C" fn(*mut u8, u32) = core::mem::transmute(0x0814_7f7cusize);
    f(record, mode)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_string_from_range(this: *mut StringObject, range: *const u8) {
    let f: unsafe extern "C" fn(*mut StringObject, *const u8) =
        core::mem::transmute(0x080f_020cusize);
    f(this, range)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_bit_set_test(set: *mut BitSet, word: u32, bit: u32) -> u32 {
    let f: unsafe extern "C" fn(*mut BitSet, u32, u32) -> u32 =
        core::mem::transmute(0x082a_4ef8usize);
    f(set, word, bit)
}

/// Host default for the materializer: unported, no faithful host model
/// (it walks the record's private containers).
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_materialize(_record: *mut u8, _mode: u32) {
    panic!("string_record_range requires materializer 0x08147f7c")
}

/// Host default for the range converter: unported, no faithful host model.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_string_from_range(_this: *mut StringObject, _range: *const u8) {
    panic!("string_record_range requires range converter 0x080f020c")
}

/// Host default for the bit test: the faithful model of the three
/// instructions @ 0x082a4ef8 — `ldr r0, [r0, #8]; ldr r0, [r0, r1, lsl #2];
/// ands r0, r0, #1 << r2`, normalized to 0/1. Not a stub: the caller's
/// cardinality recount decision depends on the result.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn bit_set_test_model(set: *mut BitSet, word: u32, bit: u32) -> u32 {
    let words = (*set).words as usize as *const u32;
    (words.add(word as usize).read() >> bit) & 1
}

/// The active callees of [`string_record_range`]. Host tests replace the
/// table; see the module header for what each slot stands in for.
pub static mut STRING_RECORD_OPS: StringRecordOps = StringRecordOps {
    #[cfg(target_os = "none")]
    materialize: firmware_materialize,
    #[cfg(not(target_os = "none"))]
    materialize: missing_materialize,
    #[cfg(target_os = "none")]
    string_from_range: firmware_string_from_range,
    #[cfg(not(target_os = "none"))]
    string_from_range: missing_string_from_range,
    #[cfg(target_os = "none")]
    bit_set_test: firmware_bit_set_test,
    #[cfg(not(target_os = "none"))]
    bit_set_test: bit_set_test_model,
};

#[inline(always)]
unsafe fn string_record_ops() -> StringRecordOps {
    core::ptr::read_volatile(core::ptr::addr_of!(STRING_RECORD_OPS))
}

/// string_record_range — original: `FUN_081481ec` @ 0x081481ec
/// (208 bytes; 50 `bl` call sites, 0 `b`, 0 predicated, binary-scanned).
///
/// Materializes the record's UTF-16 string range, and when `track` is
/// nonzero and an active character set is installed, adds every codepoint
/// of the string's UTF-8 transcription to that set (clear bits only bump
/// the set's running cardinality). Always copies the two range words
/// (record+0x54, record+0x58) to `out`.
///
/// # Safety
///
/// `record` must be a live record object: it is handed to the materialize
/// and range-convert seams and its +0x54/+0x58 words are read. `out` must
/// point at two writable words. When tracking, the active set's
/// [`BitSet::words`] must name at least as many u32 words as the largest
/// codepoint in the string requires — the original has no capacity check
/// either, and neither does the port.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_record_range(out: *mut u32, record: *mut u8, track: u32) {
    let ops = string_record_ops();
    (ops.materialize)(record, 1);
    if track != 0 && !active_character_set().is_null() {
        let mut text = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        (ops.string_from_range)(&mut text, record.add(STRING_RANGE_OFFSET));
        let count = utf8_codepoint_count_safe(text.payload);
        let mut cursor = string_object_c_str(&text);
        let mut i = 0usize;
        while i < count {
            // The original reloads the global word on every iteration.
            let set = active_character_set();
            let codepoint = utf8_next_codepoint(&mut cursor);
            let word = codepoint >> 5;
            let bit = codepoint & 31;
            if (ops.bit_set_test)(set, word, bit) == 0 {
                (*set).cardinality = (*set).cardinality.wrapping_add(1);
                let slot = ((*set).words as usize as *mut u32).add(word as usize);
                slot.write(slot.read() | (1u32 << bit));
            }
            i += 1;
        }
        string_object_destroy(&mut text);
    }
    let range = record.add(STRING_RANGE_OFFSET) as *const u32;
    out.write(range.read());
    out.add(1).write(range.add(1).read());
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::string_object::tests::STRING_OBJECT_OPS_TEST_LOCK;
    use crate::cxx::string_object::{StringObjectOps, STRING_OBJECT_OPS};
    use std::sync::Mutex;
    use std::vec::Vec;

    /// Serializes the tests that swap [`STRING_RECORD_OPS`] /
    /// [`ACTIVE_CHARACTER_SET`]. Acquired FIRST whenever a test also needs
    /// [`STRING_OBJECT_OPS_TEST_LOCK`] (the path_exists.rs lock-order
    /// precedent).
    static STRING_RECORD_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Restores every seam this module's tests touch, even on panic (the
    /// path_exists.rs SeamGuard precedent).
    struct SeamGuard {
        saved_record_ops: StringRecordOps,
        saved_string_ops: StringObjectOps,
        saved_set: *mut BitSet,
    }

    impl SeamGuard {
        unsafe fn new() -> Self {
            SeamGuard {
                saved_record_ops: core::ptr::addr_of!(STRING_RECORD_OPS).read_volatile(),
                saved_string_ops: core::ptr::addr_of!(STRING_OBJECT_OPS).read_volatile(),
                saved_set: core::ptr::addr_of!(ACTIVE_CHARACTER_SET).read_volatile(),
            }
        }
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(STRING_RECORD_OPS).write_volatile(self.saved_record_ops);
                core::ptr::addr_of_mut!(STRING_OBJECT_OPS).write_volatile(self.saved_string_ops);
                core::ptr::addr_of_mut!(ACTIVE_CHARACTER_SET).write_volatile(self.saved_set);
            }
        }
    }

    static mut MATERIALIZE_CALLS: u32 = 0;
    static mut MATERIALIZE_MODE: u32 = 0;
    static mut CONVERT_CALLS: u32 = 0;
    static mut CONVERT_RANGE: *const u8 = core::ptr::null();
    static mut RELEASE_CALLS: u32 = 0;

    /// Range words the materialize mock writes to record+0x54/+0x58.
    const RANGE_BEGIN: u32 = 0x1111_0000;
    const RANGE_END: u32 = 0x2222_0000;

    unsafe extern "C" fn mock_materialize(record: *mut u8, mode: u32) {
        MATERIALIZE_CALLS += 1;
        MATERIALIZE_MODE = mode;
        let range = record.add(STRING_RANGE_OFFSET) as *mut u32;
        range.write(RANGE_BEGIN);
        range.add(1).write(RANGE_END);
    }

    /// Payload the convert mock plants into the StringObject. Written by
    /// each test before the call; must be NUL-terminated.
    static mut PAYLOAD: [u8; 64] = [0; 64];

    unsafe fn set_payload(bytes: &[u8]) {
        PAYLOAD[..bytes.len()].copy_from_slice(bytes);
        PAYLOAD[bytes.len()] = 0;
    }

    unsafe extern "C" fn mock_string_from_range(this: *mut StringObject, range: *const u8) {
        CONVERT_CALLS += 1;
        CONVERT_RANGE = range;
        (*this).payload = core::ptr::addr_of_mut!(PAYLOAD) as *mut u8;
    }

    /// No-op payload release: the payload names the static PAYLOAD buffer,
    /// which must not be freed.
    unsafe extern "C" fn mock_release_payload(_this: *mut StringObject) {
        RELEASE_CALLS += 1;
    }

    /// OneBitSet fixture: the struct lives anywhere (native pointers), its
    /// `words` u32 must name sub-4-GiB storage, so the words buffer is
    /// carved out of the slab.
    struct SetFixture {
        set: BitSet,
        words: *mut u32,
        word_count: usize,
    }

    impl SetFixture {
        unsafe fn new(slab: *mut u8, word_count: usize) -> Self {
            let words = slab as *mut u32;
            for i in 0..word_count {
                words.add(i).write(0);
            }
            SetFixture {
                set: BitSet {
                    bit_capacity: (word_count * 32) as u32,
                    cardinality: 0,
                    words: words as usize as u32,
                    heap_tag: 0,
                    reserved: [0; 3],
                },
                words,
                word_count,
            }
        }

        unsafe fn bit(&self, codepoint: u32) -> bool {
            let word = (codepoint >> 5) as usize;
            assert!(word < self.word_count, "fixture words too small");
            (self.words.add(word).read() >> (codepoint & 31)) & 1 == 1
        }
    }

    unsafe fn install_ops(release: unsafe extern "C" fn(*mut StringObject)) {
        let mut record_ops = core::ptr::addr_of!(STRING_RECORD_OPS).read_volatile();
        record_ops.materialize = mock_materialize;
        record_ops.string_from_range = mock_string_from_range;
        core::ptr::addr_of_mut!(STRING_RECORD_OPS).write_volatile(record_ops);
        let mut string_ops = core::ptr::addr_of!(STRING_OBJECT_OPS).read_volatile();
        string_ops.release_payload = release;
        core::ptr::addr_of_mut!(STRING_OBJECT_OPS).write_volatile(string_ops);
        MATERIALIZE_CALLS = 0;
        MATERIALIZE_MODE = 0;
        CONVERT_CALLS = 0;
        CONVERT_RANGE = core::ptr::null();
        RELEASE_CALLS = 0;
    }

    /// The record is opaque to the ported function beyond +0x54; 0x60
    /// bytes covers everything it touches.
    fn record_storage() -> Vec<u8> {
        std::vec![0u8; 0x60]
    }

    #[test]
    fn track_zero_skips_tracking_and_copies_range() {
        let _lock = STRING_RECORD_TEST_LOCK.lock().unwrap();
        let _string_lock = STRING_OBJECT_OPS_TEST_LOCK.lock().unwrap();
        let _guard = unsafe { SeamGuard::new() };
        unsafe {
            install_ops(mock_release_payload);
            core::ptr::addr_of_mut!(ACTIVE_CHARACTER_SET).write_volatile(0x1 as *mut BitSet);
            let mut record = record_storage();
            let mut out = [0u32; 2];
            string_record_range(out.as_mut_ptr(), record.as_mut_ptr(), 0);
            assert_eq!(MATERIALIZE_CALLS, 1);
            assert_eq!(MATERIALIZE_MODE, 1);
            assert_eq!(CONVERT_CALLS, 0, "track == 0 must not build the string");
            assert_eq!(RELEASE_CALLS, 0);
            assert_eq!(out, [RANGE_BEGIN, RANGE_END]);
        }
    }

    #[test]
    fn null_active_set_skips_tracking_and_copies_range() {
        let _lock = STRING_RECORD_TEST_LOCK.lock().unwrap();
        let _string_lock = STRING_OBJECT_OPS_TEST_LOCK.lock().unwrap();
        let _guard = unsafe { SeamGuard::new() };
        unsafe {
            install_ops(mock_release_payload);
            core::ptr::addr_of_mut!(ACTIVE_CHARACTER_SET).write_volatile(core::ptr::null_mut());
            let mut record = record_storage();
            let mut out = [0u32; 2];
            string_record_range(out.as_mut_ptr(), record.as_mut_ptr(), 1);
            assert_eq!(MATERIALIZE_CALLS, 1);
            assert_eq!(CONVERT_CALLS, 0, "no active set must not build the string");
            assert_eq!(RELEASE_CALLS, 0);
            assert_eq!(out, [RANGE_BEGIN, RANGE_END]);
        }
    }

    #[test]
    fn new_codepoints_are_marked_and_counted_once() {
        let Some(slab) = crate::testing::try_map_u32_slab(crate::testing::hints::STRING_RECORD, 0x1000)
        else {
            assert!(crate::testing::note_missing_u32_fixture("cxx/string_record"));
            return;
        };
        let _lock = STRING_RECORD_TEST_LOCK.lock().unwrap();
        let _string_lock = STRING_OBJECT_OPS_TEST_LOCK.lock().unwrap();
        let _guard = unsafe { SeamGuard::new() };
        unsafe {
            install_ops(mock_release_payload);
            set_payload(b"AB A");
            let fixture = SetFixture::new(slab, 8);
            let set = &fixture.set as *const BitSet as *mut BitSet;
            core::ptr::addr_of_mut!(ACTIVE_CHARACTER_SET).write_volatile(set);
            let mut record = record_storage();
            let mut out = [0u32; 2];
            string_record_range(out.as_mut_ptr(), record.as_mut_ptr(), 1);
            assert_eq!(CONVERT_CALLS, 1);
            assert_eq!(
                CONVERT_RANGE,
                record.as_ptr().add(STRING_RANGE_OFFSET),
                "the converter is handed record+0x54"
            );
            assert!(fixture.bit(b' ' as u32));
            assert!(fixture.bit(b'A' as u32));
            assert!(fixture.bit(b'B' as u32));
            assert_eq!(
                (*set).cardinality, 3,
                "the duplicate 'A' must not bump the cardinality"
            );
            assert_eq!(RELEASE_CALLS, 1, "the temp string is destroyed once");
            assert_eq!(out, [RANGE_BEGIN, RANGE_END]);
        }
    }

    #[test]
    fn multibyte_codepoint_is_marked() {
        let Some(slab) = crate::testing::try_map_u32_slab(crate::testing::hints::STRING_RECORD, 0x1000)
        else {
            assert!(crate::testing::note_missing_u32_fixture("cxx/string_record"));
            return;
        };
        let _lock = STRING_RECORD_TEST_LOCK.lock().unwrap();
        let _string_lock = STRING_OBJECT_OPS_TEST_LOCK.lock().unwrap();
        let _guard = unsafe { SeamGuard::new() };
        unsafe {
            install_ops(mock_release_payload);
            set_payload(&[0xC3, 0xA9]); // U+00E9
            let fixture = SetFixture::new(slab, 8);
            let set = &fixture.set as *const BitSet as *mut BitSet;
            core::ptr::addr_of_mut!(ACTIVE_CHARACTER_SET).write_volatile(set);
            let mut record = record_storage();
            let mut out = [0u32; 2];
            string_record_range(out.as_mut_ptr(), record.as_mut_ptr(), 1);
            assert!(fixture.bit(0xE9), "word 7 bit 9");
            assert_eq!((*set).cardinality, 1);
        }
    }

    #[test]
    fn preset_bit_is_not_recounted() {
        let Some(slab) = crate::testing::try_map_u32_slab(crate::testing::hints::STRING_RECORD, 0x1000)
        else {
            assert!(crate::testing::note_missing_u32_fixture("cxx/string_record"));
            return;
        };
        let _lock = STRING_RECORD_TEST_LOCK.lock().unwrap();
        let _string_lock = STRING_OBJECT_OPS_TEST_LOCK.lock().unwrap();
        let _guard = unsafe { SeamGuard::new() };
        unsafe {
            install_ops(mock_release_payload);
            set_payload(b"AA");
            let fixture = SetFixture::new(slab, 8);
            fixture.words.add((b'A' as usize) >> 5).write(1 << (b'A' & 31));
            let set = &fixture.set as *const BitSet as *mut BitSet;
            (*set).cardinality = 1;
            core::ptr::addr_of_mut!(ACTIVE_CHARACTER_SET).write_volatile(set);
            let mut record = record_storage();
            let mut out = [0u32; 2];
            string_record_range(out.as_mut_ptr(), record.as_mut_ptr(), 1);
            assert_eq!(
                (*set).cardinality, 1,
                "an already-set bit is neither re-set nor recounted"
            );
        }
    }

    /// Second set the flip-test publishes mid-walk.
    static mut SECOND_SET_WORDS_HINT: usize = 0;

    #[test]
    fn active_set_is_reloaded_every_iteration() {
        let Some(slab) = crate::testing::try_map_u32_slab(crate::testing::hints::STRING_RECORD, 0x1000)
        else {
            assert!(crate::testing::note_missing_u32_fixture("cxx/string_record"));
            return;
        };
        let _lock = STRING_RECORD_TEST_LOCK.lock().unwrap();
        let _string_lock = STRING_OBJECT_OPS_TEST_LOCK.lock().unwrap();
        let _guard = unsafe { SeamGuard::new() };
        unsafe {
            install_ops(mock_release_payload);
            set_payload(b"AB");
            // Two sets in the one slab: words of the first at +0x000, of
            // the second at +0x100.
            let first = SetFixture::new(slab, 8);
            let second = SetFixture::new(slab.add(0x100), 8);
            let first_set = &first.set as *const BitSet as *mut BitSet;
            let second_set = &second.set as *const BitSet as *mut BitSet;
            core::ptr::addr_of_mut!(ACTIVE_CHARACTER_SET).write_volatile(first_set);
            SECOND_SET_WORDS_HINT = second_set as usize;

            unsafe extern "C" fn flipping_test(set: *mut BitSet, word: u32, bit: u32) -> u32 {
                let result = bit_set_test_model(set, word, bit);
                // After the first codepoint's test, swap the active set.
                core::ptr::addr_of_mut!(ACTIVE_CHARACTER_SET)
                    .write_volatile(SECOND_SET_WORDS_HINT as *mut BitSet);
                result
            }

            let mut record_ops = core::ptr::addr_of!(STRING_RECORD_OPS).read_volatile();
            record_ops.bit_set_test = flipping_test;
            core::ptr::addr_of_mut!(STRING_RECORD_OPS).write_volatile(record_ops);

            let mut record = record_storage();
            let mut out = [0u32; 2];
            string_record_range(out.as_mut_ptr(), record.as_mut_ptr(), 1);
            assert!(first.bit(b'A' as u32), "first codepoint lands in the first set");
            assert!(!first.bit(b'B' as u32));
            assert!(second.bit(b'B' as u32), "second codepoint lands in the swapped set");
            assert_eq!((*first_set).cardinality, 1);
            assert_eq!((*second_set).cardinality, 1);
        }
    }

    #[test]
    fn empty_string_marks_nothing_but_still_copies_range() {
        let Some(slab) = crate::testing::try_map_u32_slab(crate::testing::hints::STRING_RECORD, 0x1000)
        else {
            assert!(crate::testing::note_missing_u32_fixture("cxx/string_record"));
            return;
        };
        let _lock = STRING_RECORD_TEST_LOCK.lock().unwrap();
        let _string_lock = STRING_OBJECT_OPS_TEST_LOCK.lock().unwrap();
        let _guard = unsafe { SeamGuard::new() };
        unsafe {
            install_ops(mock_release_payload);
            set_payload(b"");
            let fixture = SetFixture::new(slab, 8);
            let set = &fixture.set as *const BitSet as *mut BitSet;
            core::ptr::addr_of_mut!(ACTIVE_CHARACTER_SET).write_volatile(set);
            let mut record = record_storage();
            let mut out = [0u32; 2];
            string_record_range(out.as_mut_ptr(), record.as_mut_ptr(), 1);
            assert_eq!(CONVERT_CALLS, 1, "the string is built even when empty");
            assert_eq!((*set).cardinality, 0);
            assert_eq!(RELEASE_CALLS, 1);
            assert_eq!(out, [RANGE_BEGIN, RANGE_END]);
        }
    }
}
