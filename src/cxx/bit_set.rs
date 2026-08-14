//! retailOS's **bit set** — a heap-backed vector of bits with a running
//! cardinality — and the one member ported here, the UTF-8 bulk insert that
//! turns a string into a set of codepoints. Everything below is decoded from
//! the raw words of `work/firmware/osos.dec`, not from Ghidra.
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
//! - **0x082a4ef8** — the test, `(this, word_index, bit_index)`:
//!   `ldr r0, [r0, #8]; ldr r0, [r0, r1, lsl #2]; ands r0, r0, #1 << r2`,
//!   normalized to 0/1. Note it takes the index **pre-split** by the caller.
//! - **0x082746f4** — the write behind [`BIT_SET_WRITE`], `(this, bit,
//!   value)`: splits `bit` into `bit >> 5` / `bit & 31`, tests the current
//!   value through 0x082a4ef8, returns untouched if it already matches, and
//!   otherwise adjusts +0x04 by ±1 and ORs or XORs the mask into the word.
//!   The cardinality is maintained exactly because of that early-out.
//!
//! ## The ported function
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
//! Deviations: none. `FUN_082746f4` is unported and rides the
//! [`BIT_SET_WRITE`] seam; [`utf8_next_codepoint`] is already ported and is
//! called directly.

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

/// Indirect call to the unported bit write `FUN_082746f4` @ 0x082746f4
/// (128 bytes; 19 `bl` call sites, binary-scanned), `(set, bit, value)`.
///
/// The target splits `bit` into `bit >> 5` / `bit & 31`, reads the current
/// value through the test @ 0x082a4ef8, returns without a store when it
/// already equals `value`, and otherwise steps `set->cardinality` by ±1 and
/// ORs (set) or XORs (clear) the mask into `set->words[bit >> 5]`. Its own
/// callee 0x082a4ef8 dereferences `words`, so the wired default is a no-op
/// — the `ITERATOR_STATE_RELEASE` precedent. Nothing in
/// [`bit_set_insert_utf8`]'s control flow depends on the write's effects.
pub static mut BIT_SET_WRITE: unsafe extern "C" fn(set: *mut BitSet, bit: u32, value: u32) =
    bit_set_write_unported;

/// Default for [`BIT_SET_WRITE`]: the write is unported, so it has no
/// local effect.
unsafe extern "C" fn bit_set_write_unported(_set: *mut BitSet, _bit: u32, _value: u32) {}

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
/// The write is only ever called with value 1, so this can add characters to
/// a set but never remove them.
///
/// # Safety
///
/// `set` is passed through to [`BIT_SET_WRITE`] and is not dereferenced
/// here. `text`, when non-NULL, must be a NUL-terminated buffer; the decoder
/// reads up to three bytes per codepoint without validating continuation
/// bytes, so a truncated multi-byte sequence at the very end can read past
/// the terminator — the same exposure the original has.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bit_set_insert_utf8(set: *mut BitSet, text: *const u8) -> *mut BitSet {
    if !text.is_null() {
        let write = core::ptr::read_volatile(core::ptr::addr_of!(BIT_SET_WRITE));
        let mut cursor = text;
        loop {
            let codepoint = utf8_next_codepoint(&mut cursor);
            if codepoint == 0 {
                break;
            }
            write(set, codepoint, BIT_SET_VALUE_SET);
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::sync::Mutex;
    use std::vec::Vec;

    /// Every `(bit, value)` pair the seam saw, in order.
    static WRITES: Mutex<Vec<(u32, u32)>> = Mutex::new(Vec::new());

    /// The `set` pointer the seam saw, to prove it is passed through
    /// unchanged.
    static WRITE_SET: Mutex<usize> = Mutex::new(0);

    /// Serializes the [`BIT_SET_WRITE`] swap: it is a crate-global static
    /// and `cargo test` runs these tests on parallel threads.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn recording_write(set: *mut BitSet, bit: u32, value: u32) {
        *WRITE_SET.lock().unwrap() = set as usize;
        WRITES.lock().unwrap().push((bit, value));
    }

    /// Restores the wired default on drop, even when a test panics.
    struct SeamGuard;
    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(BIT_SET_WRITE).write_volatile(bit_set_write_unported);
            }
        }
    }

    fn install_recorder() -> SeamGuard {
        unsafe {
            core::ptr::addr_of_mut!(BIT_SET_WRITE).write_volatile(recording_write);
        }
        WRITES.lock().unwrap().clear();
        *WRITE_SET.lock().unwrap() = 0;
        SeamGuard
    }

    fn writes() -> Vec<(u32, u32)> {
        core::mem::take(&mut *WRITES.lock().unwrap())
    }

    /// A stand-in set: the port never dereferences it, so its contents are
    /// irrelevant — only its identity is checked.
    fn set() -> *mut BitSet {
        static mut OBJECT: [u32; BIT_SET_SIZE / 4] = [0; BIT_SET_SIZE / 4];
        core::ptr::addr_of_mut!(OBJECT).cast()
    }

    #[test]
    fn a_null_string_inserts_nothing_and_returns_this() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _seam = install_recorder();

        let returned = unsafe { bit_set_insert_utf8(set(), core::ptr::null()) };

        assert_eq!(returned, set(), "the original's `mov r0, r4` epilogue");
        assert_eq!(writes(), [], "the entry guard keeps the decoder from seeing NULL");
    }

    #[test]
    fn an_empty_string_decodes_its_terminator_and_stops() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _seam = install_recorder();

        unsafe { bit_set_insert_utf8(set(), b"\0".as_ptr()) };

        assert_eq!(writes(), [], "codepoint 0 breaks the loop before the write");
    }

    #[test]
    fn the_digit_set_from_the_keyboard_call_sites_is_inserted_in_order() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _seam = install_recorder();

        // The literal at 0x08297808 and 0x08299b1c, the two call sites
        // whose argument is a string constant.
        unsafe { bit_set_insert_utf8(set(), b"0123456789\0".as_ptr()) };

        assert_eq!(
            writes(),
            (b'0'..=b'9').map(|c| (c as u32, 1)).collect::<Vec<_>>(),
            "one write per character, always value 1"
        );
        assert_eq!(*WRITE_SET.lock().unwrap(), set() as usize, "`this` is passed through");
    }

    #[test]
    fn multibyte_sequences_are_inserted_as_single_codepoints() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _seam = install_recorder();

        // "a¢€b": one, two and three-byte sequences interleaved with ASCII.
        unsafe {
            bit_set_insert_utf8(set(), b"a\xc2\xa2\xe2\x82\xacb\0".as_ptr());
        }

        assert_eq!(writes(), [(0x61, 1), (0x00a2, 1), (0x20ac, 1), (0x62, 1)]);
    }

    #[test]
    fn a_four_byte_lead_ends_the_walk_early() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _seam = install_recorder();

        // The decoder @ 0x08276214 returns 0 for a 0xf0..0xff lead, which
        // this loop cannot distinguish from the terminator: the trailing
        // 'z' is never reached.
        unsafe {
            bit_set_insert_utf8(set(), b"a\xf0\x9f\x98\x80z\0".as_ptr());
        }

        assert_eq!(writes(), [(0x61, 1)], "astral planes truncate the insert");
    }

    #[test]
    fn a_repeated_character_is_written_every_time_it_appears() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _seam = install_recorder();

        // The idempotence lives in the write @ 0x082746f4, which early-outs
        // when the bit already matches — this function does not dedupe.
        unsafe { bit_set_insert_utf8(set(), b"aaa\0".as_ptr()) };

        assert_eq!(writes(), [(0x61, 1), (0x61, 1), (0x61, 1)]);
    }
}
