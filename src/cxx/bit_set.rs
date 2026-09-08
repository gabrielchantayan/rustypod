//! retailOS's **bit set** — a heap-backed vector of bits with a running
//! cardinality — and its three ported members: the pre-split bit test, bit
//! write, and UTF-8 bulk insert. Everything below is decoded from the raw
//! words of `work/firmware/osos.dec`, not from Ghidra.
//!
//! ## The class
//!
//! Ghidra names none of this cluster, and no single function reveals the
//! layout. Six consecutive functions at 0x082746f4..0x082748d8 do, and they
//! agree on a 16-byte object:
//!
//! ```text
//! +0x00  u32  bit_capacity  — the set's size in bits
//! +0x04  u32  cardinality   — how many bits are currently 1
//! +0x08  u32  words         — heap storage, ((bit_capacity + 31) >> 5) u32s
//! +0x0c  u8   heap_tag      — the allocator tag the storage came from
//! ```
//!
//! - **0x08274834** — the constructor `(this, bit_capacity, tag)`:
//!   `add r0, r1, #31; lsr r0, r0, #5; lsl r0, r0, #2` sizes the buffer at
//!   `((bits + 31) / 32) * 4`, allocates it through `malloc_wrapper` @
//!   0x080eb67c with `tag` in r1, stores it at +0x08, the capacity at +0x00
//!   and the tag byte at +0x0c, then calls 0x082747b8 to clear it. That one
//!   expression pins +0x00 as a *bit* count and +0x08 as *word* storage.
//! - **0x082747b8** — clear-all: `iram_memzero_aligned_veneer` @ 0x08037db8
//!   over the same `((bits + 31) >> 5) * 4` span, then `str #0, [this, #4]`.
//!   Zeroing the buffer and the +0x04 word together is what makes +0x04 a
//!   cardinality rather than a capacity.
//! - **0x082747e4** — the copy constructor: copies +0x00, +0x04 and the
//!   +0x0c byte verbatim, allocates a fresh buffer and `rom_memcpy`s
//!   (0x08037df8) the same span across.
//! - **0x08274874** — the destructor: `if (words && tag != 0x3a)
//!   free_wrapper(words, 0)`, then returns `this`. The 0x3a sentinel marks
//!   storage this object does not own.
//! - **0x082a4ef8** — the test behind [`bit_set_test`], `(this, word_index,
//!   bit_index)`: `ldr r0, [r0, #8]; ldr r0, [r0, r1, lsl #2]; ands r0, r0,
//!   #1 << r2`, normalized to 0/1. Note it takes the index **pre-split** by
//!   the caller.
//! - **0x082746f4** — [`bit_set_write`], `(this, bit, value)`: splits `bit`
//!   into `bit >> 5` / `bit & 31`, tests the current value through
//!   0x082a4ef8, returns untouched if it already matches, and otherwise
//!   adjusts +0x04 by ±1 and ORs or XORs the mask into the word. The
//!   cardinality is maintained exactly because of that early-out.
//!
//! ## bit_set_test — the pre-split test @ 0x082a4ef8
//!
//! Original: `FUN_082a4ef8` @ 0x082a4ef8 (**24 bytes**, 0x082a4ef8..0x082a4f10;
//! the next function opens `push {r4, lr}` at 0x082a4f10 and there is no
//! trailing literal pool, so Ghidra's size is exact. **22 `bl` call sites,
//! 0 `b`, 0 predicated**, binary-scanned by decoding every B/BL word in
//! `osos.dec`.)
//!
//! ```text
//! 082a4ef8  ldr   r0, [r0, #8]        @ set->words
//! 082a4efc  ldr   r0, [r0, r1, lsl #2] @ words[word_index]
//! 082a4f00  mov   r1, #1
//! 082a4f04  ands  r0, r0, r1, lsl r2  @ word & (1 << bit_index)
//! 082a4f08  movne r0, #1              @ normalize to exactly 0/1
//! 082a4f0c  bx    lr
//! ```
//!
//! The index arrives **pre-split**: callers compute `word = bit >> 5` and
//! `bit = bit & 31` themselves — the write @ 0x082746f4 does so in two
//! instructions right before the `bl`, and the marking loop in
//! `string_record_range` shifts the codepoint down by 5. Nothing in the
//! body masks either index, so the port keeps the same contract.
//!
//! ## bit_set_insert_utf8 — the bulk insert @ 0x0827489c
//!
//! `bit_set_insert_utf8` — original: `FUN_0827489c` @ 0x0827489c
//! (**64 bytes**, 0x0827489c..0x082748d8; Ghidra's size is right here — the
//! next function starts at 0x082748dc with `push {r4, r5, r6, r7, r8, lr}`
//! and there is no trailing literal pool. **53 `bl` call sites, 0 `b`**,
//! binary-scanned by decoding every B/BL word in `osos.dec`.)
//!
//! ```text
//! 0827489c  push  {r0, r1, r4, lr}   @ spills the two arguments; sp+4 = text
//! 082748a0  mov   r4, r0
//! 082748a4  ldr   r0, [sp, #4]
//! 082748a8  cmp   r0, #0
//! 082748ac  beq   0x082748d4         @ a NULL string inserts nothing
//! 082748b0  b     0x082748c4
//! 082748b4  mov   r1, r0             @ <- the codepoint just decoded
//! 082748b8  mov   r0, r4
//! 082748bc  mov   r2, #1
//! 082748c0  bl    0x082746f4         @ write(this, codepoint, 1)
//! 082748c4  add   r0, sp, #4         @ &cursor — the spilled argument slot
//! 082748c8  bl    0x08276214         @ utf8_next_codepoint(&cursor)
//! 082748cc  cmp   r0, #0
//! 082748d0  bne   0x082748b4
//! 082748d4  mov   r0, r4
//! 082748d8  pop   {r2, r3, r4, pc}   @ discards the two spill slots
//! ```
//!
//! `push {r0, r1, ...}` is the ADS idiom for "give this argument an
//! address": the string pointer is spilled so `add r0, sp, #4` can hand the
//! decoder a `char **` cursor to advance in place. `pop {r2, r3, ...}` then
//! throws both slots away — r2/r3 are call-clobbered, so the pops are pure
//! stack adjustment, not values.
//!
//! So the whole function is: walk `text` codepoint by codepoint through the
//! ported [`utf8_next_codepoint`] and set the bit named by each one, until
//! the decoder returns 0. Indexing a bit set by codepoint makes it a
//! **character set**, and the call sites agree — of the 53, the two whose
//! argument is a literal pass `"0123456789"` (0x08297808 and 0x08299b1c,
//! both in the text-input UI), and 0x081f99e8 feeds it the result of
//! `string_object_c_str` @ 0x082a50b0. These are the allowed-character sets
//! of the on-screen keyboards.
//!
//! Two inherited edge behaviors, both from the decoder rather than from
//! here: a lead byte of 0xf0..0xff (or an invalid one) makes
//! [`utf8_next_codepoint`] consume three bytes and return 0, which this loop
//! reads as end-of-string and stops early; and codepoint 0 can never be
//! inserted, because it is the terminator.
//!
//! Deviations: none. [`bit_set_write`] and [`utf8_next_codepoint`] are both
//! ported and called directly.

use crate::cxx::string_object::utf8_next_codepoint;

/// The 16-byte bit set. Every field is target-width so the layout stays
/// exact in 64-bit host tests, where a real pointer would not fit in
/// [`Self::words`].
#[repr(C)]
pub struct BitSet {
    /// +0x00: the set's size in bits, as the constructor @ 0x08274834
    /// receives it.
    pub bit_capacity: u32,
    /// +0x04: how many bits are currently 1, maintained by the write @
    /// 0x082746f4 and zeroed by the clear @ 0x082747b8.
    pub cardinality: u32,
    /// +0x08: heap storage, `((bit_capacity + 31) >> 5)` 32-bit words.
    pub words: u32,
    /// +0x0c: the allocator tag the storage came from. The destructor @
    /// 0x08274874 skips the free when this is [`BIT_SET_TAG_BORROWED`].
    pub heap_tag: u8,
    /// +0x0d..+0x0f: never read or written by any of the six members.
    pub reserved: [u8; 3],
}

/// The `heap_tag` value the destructor @ 0x08274874 refuses to free
/// (`cmpne r1, #58`): the storage is not this object's to release.
pub const BIT_SET_TAG_BORROWED: u8 = 0x3a;

/// Target byte size of [`BitSet`].
pub const BIT_SET_SIZE: usize = 0x10;

const _: [u8; 0x00] = [0; core::mem::offset_of!(BitSet, bit_capacity)];
const _: [u8; 0x04] = [0; core::mem::offset_of!(BitSet, cardinality)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(BitSet, words)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(BitSet, heap_tag)];
const _: [u8; BIT_SET_SIZE] = [0; core::mem::size_of::<BitSet>()];

/// bit_set_test — original: `FUN_082a4ef8` @ 0x082a4ef8
/// (24 bytes, 0x082a4ef8..0x082a4f10; the next function opens `push {r4, lr}`
/// at 0x082a4f10 with no trailing literal pool. 22 `bl` call sites, 0 `b`,
/// 0 predicated, binary-scanned by decoding every B/BL word in osos.dec).
///
/// Tests one bit of the set and returns exactly 0 or 1: loads
/// `set->words`, reads `words[word_index]`, masks with `1 << bit_index`
/// and normalizes the nonzero result to 1 (the original's `ands` sets the
/// flags and `movne r0, #1` rewrites the register, so the raw mask value
/// never escapes).
///
/// Both indices arrive **pre-split** by the caller (`word = bit >> 5`,
/// `bit = bit & 31`); nothing in the original masks them, so `bit_index`
/// MUST be in 0..=31 and `word_index` MUST be inside the allocated
/// `((bit_capacity + 31) >> 5)` words. The port keeps the contract and
/// does no masking of its own.
///
/// Deviations: none. `(word >> bit) & 1` is the exact `ands`/`movne`
/// semantics for every in-contract `bit_index`.
///
/// # Safety
///
/// `set` must point at a live [`BitSet`] whose `words` storage holds at
/// least `word_index + 1` words. Read-only: the set is never written.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bit_set_test(set: *mut BitSet, word_index: u32, bit_index: u32) -> u32 {
    let words = (*set).words as usize as *const u32;
    (words.add(word_index as usize).read() >> bit_index) & 1
}

/// bit_set_write — original: `FUN_082746f4` @ 0x082746f4
/// (128 bytes, 0x082746f4..0x08274770; the next function opens `push
/// {r4, r5, r6, lr}` at 0x08274774 and there is no trailing literal pool.
/// 19 `bl` call sites, 0 `b`, 0 predicated, binary-scanned by decoding every
/// B/BL word in osos.dec).
///
/// Splits `bit` into a word index and bit index, then calls [`bit_set_test`].
/// A nonzero `value` is a set request: an already-set bit returns untouched;
/// otherwise cardinality increments and the mask is ORed in. Zero is a clear
/// request: an already-clear bit returns untouched; otherwise cardinality
/// decrements and XOR clears the known-set mask. Thus cardinality changes
/// exactly once for each actual state transition.
///
/// The `movs r0, r2; beq` branch means every nonzero `value`, not merely 1,
/// selects the set path. The original bounds-checks neither `bit` nor the
/// cardinality, so arithmetic wraps exactly as the ARM `add`/`sub` does.
///
/// Deviations: none.
///
/// # Safety
///
/// `set` must point at a live [`BitSet`] whose word storage includes
/// `bit >> 5`. It is mutated in place; callers must synchronize concurrent
/// access just as they must for the retailOS object.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bit_set_write(set: *mut BitSet, bit: u32, value: u32) {
    let word_index = bit >> 5;
    let bit_index = bit & 31;
    let mask = 1u32 << bit_index;

    if value != 0 {
        if bit_set_test(set, word_index, bit_index) != 0 {
            return;
        }
        (*set).cardinality = (*set).cardinality.wrapping_add(1);
        let words = (*set).words as usize as *mut u32;
        let word = words.add(word_index as usize);
        word.write(word.read() | mask);
    } else {
        if bit_set_test(set, word_index, bit_index) == 0 {
            return;
        }
        (*set).cardinality = (*set).cardinality.wrapping_sub(1);
        let words = (*set).words as usize as *mut u32;
        let word = words.add(word_index as usize);
        word.write(word.read() ^ mask);
    }
}

/// The `value` argument the insert passes (`mov r2, #1`): set the bit.
const BIT_SET_VALUE_SET: u32 = 1;

/// bit_set_insert_utf8 — original: `FUN_0827489c` @ 0x0827489c
/// (64 bytes; 53 `bl` call sites, 0 `b`, binary-scanned).
///
/// Decodes `text` as UTF-8 and sets the bit named by every codepoint in it,
/// stopping at the first zero the decoder returns. A NULL `text` inserts
/// nothing — the original's `cmp r0, #0; beq` guards the whole loop, so the
/// decoder is never handed a NULL cursor. An empty string decodes one 0 and
/// stops before the first write. Returns `this`, which the original's
/// `mov r0, r4` before the epilogue makes explicit.
///
/// The write is called directly with value 1, so this can add characters to
/// a set but never remove them.
///
/// # Safety
///
/// `set` must point at a live [`BitSet`] with word storage covering every
/// decoded codepoint. `text`, when non-NULL, must be a NUL-terminated buffer;
/// reads up to three bytes per codepoint without validating continuation
/// bytes, so a truncated multi-byte sequence at the very end can read past
/// the terminator — the same exposure the original has.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bit_set_insert_utf8(set: *mut BitSet, text: *const u8) -> *mut BitSet {
    if !text.is_null() {
        let mut cursor = text;
        loop {
            let codepoint = utf8_next_codepoint(&mut cursor);
            if codepoint == 0 {
                break;
            }
            bit_set_write(set, codepoint, BIT_SET_VALUE_SET);
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::sync::{LazyLock, Mutex};

    const WORDS_BYTES: usize = 0x1000;
    const WORDS_CAPACITY: usize = WORDS_BYTES / core::mem::size_of::<u32>();

    /// Serializes the persistent slabs: fixtures are reset before each test.
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static TEST_SLAB: LazyLock<usize> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(crate::testing::hints::BIT_SET_TEST, WORDS_BYTES)
            .map(|slab| slab as usize)
            .unwrap_or(0)
    });
    static WRITE_SLAB: LazyLock<usize> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(crate::testing::hints::BIT_SET_WRITE, WORDS_BYTES)
            .map(|slab| slab as usize)
            .unwrap_or(0)
    });

    /// A [`BitSet`] backed by the one persistent u32-addressable test slab.
    /// Callers hold [`TEST_LOCK`] while using it.
    fn set_with_words(words: &[u32], cardinality: u32) -> Option<BitSet> {
        assert!(words.len() <= WORDS_CAPACITY);
        let slab = *TEST_SLAB;
        if slab == 0 {
            return None;
        }
        unsafe {
            core::ptr::write_bytes(slab as *mut u8, 0, WORDS_BYTES);
            core::ptr::copy_nonoverlapping(words.as_ptr(), slab as *mut u32, words.len());
        }
        Some(BitSet {
            bit_capacity: (words.len() * 32) as u32,
            cardinality,
            words: slab as u32,
            heap_tag: 0,
            reserved: [0; 3],
        })
    }

    fn write_set(words: &[u32], cardinality: u32) -> Option<BitSet> {
        assert!(words.len() <= WORDS_CAPACITY);
        let slab = *WRITE_SLAB;
        if slab == 0 {
            return None;
        }
        unsafe {
            core::ptr::write_bytes(slab as *mut u8, 0, WORDS_BYTES);
            core::ptr::copy_nonoverlapping(words.as_ptr(), slab as *mut u32, words.len());
        }
        Some(BitSet {
            bit_capacity: (words.len() * 32) as u32,
            cardinality,
            words: slab as u32,
            heap_tag: 0,
            reserved: [0; 3],
        })
    }

    macro_rules! require_set {
        ($words:expr, $cardinality:expr) => {
            match set_with_words($words, $cardinality) {
                Some(set) => set,
                None => {
                    assert!(crate::testing::note_missing_u32_fixture("cxx/bit_set"));
                    return;
                }
            }
        };
    }

    #[test]
    fn a_null_string_inserts_nothing_and_returns_this() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = BitSet {
            bit_capacity: 0,
            cardinality: 0,
            words: 0,
            heap_tag: 0,
            reserved: [0; 3],
        };
        let set = core::ptr::addr_of_mut!(set);

        let returned = unsafe { bit_set_insert_utf8(set, core::ptr::null()) };

        assert_eq!(returned, set, "the original's `mov r0, r4` epilogue");
    }

    #[test]
    fn an_empty_string_decodes_its_terminator_and_stops() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = require_set!(&[0], 0);

        unsafe { bit_set_insert_utf8(&mut set, b"\0".as_ptr()) };

        assert_eq!(set.cardinality, 0);
        assert_eq!(unsafe { bit_set_test(&mut set, 0, 0) }, 0);
    }

    #[test]
    fn the_digit_set_from_the_keyboard_call_sites_is_inserted() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = require_set!(&[0; 4], 0);

        // The literal at 0x08297808 and 0x08299b1c, the two call sites
        // whose argument is a string constant.
        unsafe { bit_set_insert_utf8(&mut set, b"0123456789\0".as_ptr()) };

        assert_eq!(set.cardinality, 10);
        for byte in b'0'..=b'9' {
            assert_eq!(unsafe { bit_set_test(&mut set, (byte as u32) >> 5, (byte as u32) & 31) }, 1);
        }
    }

    #[test]
    fn multibyte_sequences_are_inserted_as_single_codepoints() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = require_set!(&[0; 264], 0);

        // "a¢€b": one, two and three-byte sequences interleaved with ASCII.
        unsafe {
            bit_set_insert_utf8(&mut set, b"a\xc2\xa2\xe2\x82\xacb\0".as_ptr());
        }

        assert_eq!(set.cardinality, 4);
        for codepoint in [0x61, 0x00a2, 0x20ac, 0x62] {
            assert_eq!(unsafe { bit_set_test(&mut set, codepoint >> 5, codepoint & 31) }, 1);
        }
    }

    #[test]
    fn a_four_byte_lead_ends_the_walk_early() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = require_set!(&[0; 4], 0);

        // The decoder @ 0x08276214 returns 0 for a 0xf0..0xff lead, which
        // this loop cannot distinguish from the terminator: the trailing
        // 'z' is never reached.
        unsafe {
            bit_set_insert_utf8(&mut set, b"a\xf0\x9f\x98\x80z\0".as_ptr());
        }

        assert_eq!(set.cardinality, 1);
        assert_eq!(unsafe { bit_set_test(&mut set, 0x61 >> 5, 0x61 & 31) }, 1);
        assert_eq!(unsafe { bit_set_test(&mut set, 0x7a >> 5, 0x7a & 31) }, 0);
    }

    #[test]
    fn repeated_character_preserves_a_single_cardinality_count() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = require_set!(&[0; 4], 0);

        unsafe { bit_set_insert_utf8(&mut set, b"aaa\0".as_ptr()) };

        assert_eq!(set.cardinality, 1, "the write's early-out deduplicates");
        assert_eq!(unsafe { bit_set_test(&mut set, 0x61 >> 5, 0x61 & 31) }, 1);
    }

    #[test]
    fn write_tracks_transitions_across_word_boundaries() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(mut set) = write_set(&[(1u32 << 0) | (1u32 << 31), 0], 2) else {
            assert!(crate::testing::note_missing_u32_fixture("cxx/bit_set"));
            return;
        };
        let set_ptr = core::ptr::addr_of_mut!(set);

        unsafe {
            bit_set_write(set_ptr, 31, 0);
            assert_eq!((*set_ptr).cardinality, 1);
            assert_eq!(((*set_ptr).words as usize as *const u32).read(), 1);

            bit_set_write(set_ptr, 31, 0);
            assert_eq!((*set_ptr).cardinality, 1, "an already-clear bit is untouched");

            bit_set_write(set_ptr, 32, 0xfeed_beef);
            assert_eq!((*set_ptr).cardinality, 2, "every nonzero value sets");
            bit_set_write(set_ptr, 32, 1);
            assert_eq!((*set_ptr).cardinality, 2, "an already-set bit is untouched");

            bit_set_write(set_ptr, 63, 1);
            bit_set_write(set_ptr, 0, 0);
            assert_eq!((*set_ptr).cardinality, 2);
            let words = (*set_ptr).words as usize as *const u32;
            assert_eq!(words.read(), 0);
            assert_eq!(words.add(1).read(), 0x8000_0001);
        }
    }

    // --- bit_set_test @ 0x082a4ef8 ---

    #[test]
    fn test_reports_the_exact_bit_and_no_other() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = require_set!(&[1u32 << 17], 0);
        let set = core::ptr::addr_of_mut!(set);

        for bit in 0..32u32 {
            let expect = u32::from(bit == 17);
            assert_eq!(
                unsafe { bit_set_test(set, 0, bit) },
                expect,
                "bit {bit} of a word holding only bit 17"
            );
        }
    }

    #[test]
    fn test_normalizes_the_mask_to_exactly_one() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Several bits set, including the tested one: the raw mask
        // (1 << 31 = 0x8000_0000) must come back as 1, the `movne r0, #1`.
        let mut set = require_set!(&[0x8000_0401], 0);
        let set = core::ptr::addr_of_mut!(set);

        unsafe {
            assert_eq!(bit_set_test(set, 0, 31), 1, "movne rewrites 0x8000_0000 to 1");
            assert_eq!(bit_set_test(set, 0, 0), 1);
            assert_eq!(bit_set_test(set, 0, 10), 1);
            assert_eq!(bit_set_test(set, 0, 1), 0, "a gap between set bits");
        }
    }

    #[test]
    fn test_indexes_across_words_with_the_pre_split_index() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = require_set!(&[0, 1u32 << 5, 0, 1u32 << 31], 0);
        let set = core::ptr::addr_of_mut!(set);

        unsafe {
            assert_eq!(bit_set_test(set, 1, 5), 1, "bit 37 pre-split as (1, 5)");
            assert_eq!(bit_set_test(set, 3, 31), 1, "bit 127 pre-split as (3, 31)");
            assert_eq!(bit_set_test(set, 0, 5), 0, "word 0 is empty");
            assert_eq!(bit_set_test(set, 2, 31), 0, "word 2 is empty");
            assert_eq!(bit_set_test(set, 1, 31), 0, "the bit index is not crossed with the word");
        }
    }

    #[test]
    fn test_an_empty_set_reports_zero_everywhere() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = require_set!(&[0; 8], 0);
        let set = core::ptr::addr_of_mut!(set);

        for word in 0..8u32 {
            for bit in [0u32, 1, 15, 31] {
                assert_eq!(unsafe { bit_set_test(set, word, bit) }, 0);
            }
        }
    }
}
