//! Out-of-line template members of the C++ block that the compiler
//! emitted once per instantiation instead of sharing.
//!
//! Whole families of byte-identical functions sit in
//! 0x083c0000-0x083dffff, differing only in address: the accessor in
//! [`crate::cxx::handle`] (22 copies), `deque_seg_capacity`
//! @ 0x083d9ec0 in [`crate::heap::block_deque`] (17 copies), and several
//! template members ported here. Each family needs exactly one port;
//! `names.yaml` carries the address lists so a hook can point every copy at it.
//! - [`deque_back_elem4`] — obtains the final 4-byte deque element by
//!   walking a copy of the end iterator back one element.
//!
//! - [`deque_iter_assign`] — the 16-byte deque-iterator copy, 17
//!   byte-identical copies, 99 `bl` call sites. Each copy sits
//!   immediately after that instantiation's `deque_seg_capacity`
//!   (8 bytes + 36 bytes, adjacent), which is what identifies the pair
//!   as the deque template's out-of-line members.
//! - [`deque_iter_init_elem4`] — initializes the 4-byte-element deque
//!   iterator's four fields, including a 128-byte segment end.
//! - [`deque_iter_increment_elem4`] — advances a 4-byte deque iterator,
//!   switching its segment-map slot at the segment boundary.
//! - [`deque_iter_equal`] — equality for the 4-byte deque iterator,
//!   including the representation where a segment end aliases the following
//!   segment's base.
//! - [`less_signed`] / [`less_unsigned`] / [`less_unsigned_byte`] —
//!   `std::less`-shaped comparators taking their operands by
//!   reference, 1, 12 and 2 copies, 45, 73 and 13 call sites.
//! - [`equal_deref`] — the `*a == *b` word comparator, the equality
//!   twin of [`not_equal_deref`]; 41 byte-identical copies (a 39-copy
//!   contiguous run at 0x083cf650-0x083cf9e0 plus strays), 241 direct
//!   `bl` call sites across the family, 12 at the canonical
//!   0x083cf968.
//! - [`container_element_at`] — indexed element access through the
//!   container's virtual element-slot method, 30 copies, 154 call
//!   sites (the largest family in the block after the handle accessor).
//! - [`array_at_checked`] — bounds-checked lookup in a
//!   {base, count} pointer array, 2 copies, 43 call sites.
//! - [`cxx_record_range_destroy_8`] — elementwise destruction of a
//!   half-open vector range whose 8-byte records contain two COW string
//!   objects.
//! - [`cxx_record_range_destroy_16`] — elementwise destruction of a
//!   half-open vector range whose 16-byte records contain two
//!   [`StringObject`] values.
//! - [`pair_assign_guarded`] — the self-assignment-guarded two-word
//!   copy-assign of a pair-shaped value type, the only copy, 14 call
//!   sites.
//! - [`string_object_word_range_copy`] — copy-assigns the StringObject and
//!   copies the trailing word of each 12-byte record in a half-open range.
//! - [`advance_string_object_word_cursor`] — advances a cursor through the
//!   12-byte StringObject-and-word records used by the range-copy template.
//! - [`vector_copy_range_u32`] — copies a half-open range of 4-byte
//!   trivially-copyable vector elements into initialized output storage.
//! - [`vector_copy_range_record8`] — copies the named fields of 8-byte
//!   vector records while leaving their padding byte intact.
//! - [`cxx_vector_find_equal`] — searches the COW-string-keyed records
//!   within the `{unknown, begin, end}` owner shape used by the UI data.
//! - [`vector_size_elem2`] / [`vector_size_elem4`] /
//!   [`vector_size_elem8`] / [`vector_size_elem16`] /
//!   [`vector_size_elem32`] —
//!   `vector<T>::size()`, one instantiation per element size; the five
//!   power-of-two shifts cover 29 functions and 292 call sites.
//! - [`vector_size_elem2_clamped`] — the unsigned-clamped
//!   `vector<u16>::size()` out-of-line body @ 0x0829db9c: empty or
//!   inverted heads yield 0 instead of the family's signed count. One
//!   copy, 23 call sites.
//! - [`vector_size_elem12`] / [`vector_size_elem24`] /
//!   [`vector_size_elem20`] / [`vector_size_elem28`] /
//!   [`vector_size_elem40`] — the
//!   non-power-of-two members of the size family, dividing the span by
//!   12, 24, 20, 28 or 40 through [`__rt_sdiv`] instead of shifting.
//! - [`vector_size_bool`] — `vector<bool>::size()`, the bit-iterator
//!   difference over the `{begin_word, begin_bit, end_word, end_bit}`
//!   head: whole words times 32, plus the end bit offset, minus the
//!   begin bit offset.
//! - [`vector_bool_iter_not_equal`] — the `vector<bool>` bit-iterator
//!   `operator!=`: the word pointers differ, or the bit offsets do.
//! - [`vector_bool_reference_init`] — the `vector<bool>` mask-reference
//!   constructor: copies the iterator's word pointer and stores the
//!   single-bit mask `1 << bit`.
//! - [`vector_bool_iter_advance`] — the `vector<bool>` bit-iterator
//!   `operator+=`: folds a signed bit distance into whole words plus a
//!   bit offset in `0..32`.
//! - [`vector_bool_reference_test`] — the `vector<bool>` mask-reference
//!   dereference: reads the storage word and returns whether the masked
//!   bit is set.
//! - [`vector_bool_reference_assign`] — the `vector<bool>` mask-reference
//!   assignment: sets or clears the selected storage bit from a raw C++ bool.
//! - [`vector_capacity`] / [`vector_capacity_elem12`] /
//!   [`vector_capacity_elem16`] / [`vector_capacity_elem24_copy_77ec`]
//!   / [`vector_capacity_elem40`] / [`vector_capacity_elem8`] /
//!   [`vector_capacity_elem4`] / [`vector_capacity_elem20`] —
//!   `vector<T>::capacity()` for 24-, 12-, 16-, 40-, 8-, 4- and
//!   20-byte elements,
//!   the end-of-storage sibling of the size family (divide-based for
//!   24/12/40/20, shift-based for 16/8/4; the 24-byte copy is a
//!   byte-identical second instantiation of the primary).
//! - [`vector_push_back_elem12`] — `vector<T>::push_back` for a
//!   12-byte trivially-copyable element: append at `end` when capacity
//!   remains, else grow-and-insert through the (unported) helper
//!   0x083e12dc behind [`VECTOR_PUSH_BACK_ELEM12_OPS`]. One copy, 43
//!   call sites.
//!
//! Not to be confused with `deque_iter_copy` @ 0x083dd9e4 (already
//! ported in `heap/block_deque`): that one is the same four-word copy
//! with the **source in r2**, and it exists exactly once.

use crate::cxx::handle::{refcounted_body_attach, RefcountedBody};
use crate::app::scoped_context::scoped_context_destroy;
use crate::cxx::string::cxx_string_release;
use crate::cxx::string_object::{
    string_object_assign, string_object_copy_construct, string_object_destroy, StringObject,
};
use crate::libc::memcmp::memcmp;
use crate::libc::memcpy::memcpy_forward_words;
use crate::runtime::rt_div::__rt_sdiv;
use crate::heap::block_deque::{deque_seg_capacity, DequeIter};
use crate::heap::block_deque::BlockDeque;
use crate::heap::veneers::cxx_array_dealloc;

/// The five-word owner shape consumed by [`container_begin_cursor`].
///
/// `cursor_state` is a raw 32-bit retailOS pointer. Its target's word at
/// byte offset +0x8 is the cursor returned by the member.
#[repr(C)]
pub struct ContainerBeginCursorOwner {
    pub unknown_0: u32,
    pub unknown_4: u32,
    pub unknown_8: u32,
    pub unknown_c: u32,
    pub cursor_state: u32,
}

#[repr(C)]
pub struct ContainerCursorState {
    pub unknown_0: u32,
    pub unknown_4: u32,
    pub begin_cursor: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x10] = [0; core::mem::offset_of!(ContainerBeginCursorOwner, cursor_state)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 8] = [0; core::mem::offset_of!(ContainerCursorState, begin_cursor)];

/// container_begin_cursor — original: `FUN_083dbeec` @ 0x083dbeec
/// (20 bytes; Ghidra reports 20).
///
/// Loads the raw cursor-state pointer at `owner + 0x10`, then returns its raw
/// cursor word at `cursor_state + 0x8`. Raw `osos.dec` fixes the complete
/// body as five instructions: `push {r3,lr}; ldr r0,[r0,#0x10]; ldr
/// r0,[r0,#8]; str r0,[sp]; pop {ip,pc}`. Decoding every aligned ARM B/BL
/// word finds six inbound unconditional `bl` calls at 0x0825b864, 0x0825b910,
/// 0x0825bb08, 0x0825bba0, 0x0825bc44, and 0x0825bcc0; there are no
/// predicated calls or tail branches.
///
/// Its callers compare this cursor against the preceding sibling's
/// `owner + 0x10` cursor and advance until equal, establishing this value as
/// the begin cursor without identifying either containing type. The raw u32
/// result and cursor-state field preserve the target ABI; there are no
/// deliberate deviations.
///
/// # Safety
///
/// `owner` and its non-null `cursor_state` target must be readable. The
/// retailOS body performs no NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_begin_cursor")]
#[inline(never)]
pub unsafe extern "C" fn container_begin_cursor(owner: *const ContainerBeginCursorOwner) -> u32 {
    let cursor_state = (*owner).cursor_state as usize as *const ContainerCursorState;
    (*cursor_state).begin_cursor
}

/// The five-word owner shape consumed by [`container_end_cursor`].
///
/// The retailOS member reads only `end_cursor` at target byte offset +0x10.
/// Its representation remains a raw target word, so the layout stays
/// word-for-word on both ARM and 64-bit test hosts without assuming a host
/// pointer fits in that field.
#[repr(C)]
pub struct ContainerEndCursorOwner {
    pub unknown_0: u32,
    pub unknown_4: u32,
    pub unknown_8: u32,
    pub unknown_c: u32,
    pub end_cursor: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x10] = [0; core::mem::offset_of!(ContainerEndCursorOwner, end_cursor)];

/// container_end_cursor — original: `FUN_083dbedc` @ 0x083dbedc
/// (12 bytes; Ghidra reports 16).
///
/// Returns the raw cursor word at `owner + 0x10`. The independently linked
/// next function starts at 0x083dbeec, so raw `osos.dec` fixes this body's
/// extent as three instructions: `push {r3,lr}; ldr r0,[r0,#0x10]; str
/// r0,[sp]; pop {ip,pc}`. All seven inbound direct calls are unconditional
/// `bl` forms at 0x0825b898, 0x0825b950, 0x0825ba8c, 0x0825bb38,
/// 0x0825bbd0, 0x0825bc78, and 0x0825bcf4; decoding every aligned ARM
/// B/BL word finds no predicated calls or tail branches.
///
/// Those callers initialize a cursor from the sibling accessor that returns
/// `*(*owner + 8)`, then repeatedly compare it with this result and advance
/// it. This establishes the result as their container end cursor but does
/// not identify the owning container or cursor representation. The raw u32
/// result deliberately preserves its target-word ABI without inventing a
/// pointer type; there are no behavioral deviations.
///
/// # Safety
///
/// `owner` must point to a readable [`ContainerEndCursorOwner`].
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_end_cursor")]
#[inline(never)]
pub unsafe extern "C" fn container_end_cursor(owner: *const ContainerEndCursorOwner) -> u32 {
    (*owner).end_cursor
}

/// A 16-byte retailOS record containing two adjacent [`StringObject`]s.
///
/// On the 32-bit target each string object has a vtable and payload word, so
/// this pair is exactly 16 bytes. On 64-bit host tests, Rust pointer width
/// makes it larger; iterating typed records preserves the target's two-object
/// stride without pretending host pointers fit in target words.
#[repr(C)]
pub struct StringObjectPair {
    pub first: StringObject,
    pub second: StringObject,
}

/// A 12-byte retailOS record with a [`StringObject`] followed by an
/// unidentified trailing word.
///
/// The raw copy template assigns the string member, rather than bit-copying
/// it, then copies the trailing word. Typed records make the target offsets
/// (+0x00 string, +0x08 word) exact on ARM while retaining disjoint fields in
/// 64-bit host tests.
#[repr(C)]
pub struct StringObjectWord {
    pub string: StringObject,
    pub trailing_word: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x08] = [0; core::mem::offset_of!(StringObjectWord, trailing_word)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::size_of::<StringObjectWord>()];

/// An 8-byte retailOS record containing two adjacent COW string objects.
///
/// Each COW string object is its one-word data pointer, so `second` is at
/// target offset +4. Host pointers are wider, but iterating typed records
/// preserves the target's two-string stride without conflating host and ARM
/// pointer widths.
#[repr(C)]
pub struct CxxStringPair {
    pub first: *mut u8,
    pub second: *mut u8,
}

/// The three target words consumed by [`cxx_vector_find_equal`].
///
/// The preceding word is not inspected, while `begin` and `end` are the
/// 8-byte-record bounds at target offsets +4 and +8. Keeping it as a typed
/// field makes those offsets exact on ARM and keeps host pointers disjoint.
#[repr(C)]
pub struct CxxStringPairVector {
    /// Unexamined owner word at target offset +0.
    pub prefix: u32,
    /// First 8-byte COW-string-pair record at target offset +4.
    pub begin: *mut CxxStringPair,
    /// One past the final record at target offset +8.
    pub end: *mut CxxStringPair,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x04] = [0; core::mem::offset_of!(CxxStringPairVector, begin)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x08] = [0; core::mem::offset_of!(CxxStringPairVector, end)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::size_of::<CxxStringPairVector>()];

/// COW-string equality used by [`cxx_vector_find_equal`]'s private
/// `FUN_083eac08` callee.
///
/// The string object's word is its character-data pointer and its `_Rep`
/// length is the u32 immediately before that data. The ARM helper gates on
/// equal lengths, calls `memcmp(data_a, data_b, length)`, then turns a zero
/// comparison result into 1. The redundant post-`memcmp` length ordering in
/// its raw body cannot change the result after the initial equality gate.
#[inline(always)]
unsafe fn cxx_string_equal(left: *const *mut u8, right: *const *mut u8) -> bool {
    let left_data = left.read();
    let right_data = right.read();
    let left_length = (left_data as *const u32).sub(1).read();
    let right_length = (right_data as *const u32).sub(1).read();
    left_length == right_length && memcmp(left_data, right_data, left_length as usize) == 0
}

/// cxx_vector_find_equal — original: `FUN_0825c2c0` @ 0x0825c2c0
/// (80 bytes; reference:
/// `ipod-decomp/decomp/c/025/0825c2c0_FUN_0825c2c0.c`).
///
/// Searches the 8-byte [`CxxStringPair`] records in `owner.begin..owner.end`
/// for the first record whose first COW-string word equals `*needle`. The
/// raw ARM body loads its bounds from `this + 4` and `this + 8`, advances the
/// record cursor by 8 only after a failed comparison, writes the found record
/// to `out`, and returns the widened C++ bool 1; a miss returns 0 without
/// touching `out`. Its direct callee `FUN_083eac08` @ 0x083eac08 (152 bytes)
/// is an unported `basic_string::operator==`: raw ARM establishes that it
/// reads the `_Rep` lengths at `data - 4`, rejects unequal lengths, and calls
/// the ported [`memcmp`] @ 0x08030f64 over that length. This is represented
/// exactly by the established `memcmp` seam; no comparator stub or
/// approximation is introduced.
///
/// # Safety
/// `owner` must contain valid `begin..end` bounds over contiguous
/// [`CxxStringPair`] records. `needle` must point to a valid COW-string word,
/// every compared string must have a readable `_Rep` length at `data - 4`,
/// and `out` must be writable on a match.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_vector_find_equal(
    owner: *const CxxStringPairVector,
    needle: *const *mut u8,
    out: *mut *mut CxxStringPair,
) -> i32 {
    let mut record = (*owner).begin;
    while record != (*owner).end {
        if cxx_string_equal(core::ptr::addr_of!((*record).first), needle) {
            out.write(record);
            return 1;
        }
        record = record.add(1);
    }
    0
}

/// cxx_record_range_destroy_8 — original: `FUN_083e35a4` @ 0x083e35a4
/// (40 bytes; 5 direct `bl` callers).
///
/// Destroys the half-open `[first, last)` range of 8-byte [`CxxStringPair`]
/// records. The first ABI argument in r0 is unused; r1 and r2 are the
/// current and end iterators. The raw ARM loop first compares them, then
/// calls `FUN_0825c8fc(current)` and advances by 8. That element destructor
/// releases `current + 4` followed by `current`, so this port uses the
/// established [`cxx_string_release`] seam @ 0x083d8b04 in the same reverse
/// member order. It terminates solely on iterator equality.
///
/// The call sites at 0x0825c790 and 0x083e35cc pass a `{begin, end}` vector
/// head and then free its storage as 8-byte elements. `FUN_0825c790` also
/// destroys COW strings on either side of that vector, independently
/// identifying these records as pairs of the same one-word string object.
///
/// # Safety
/// `first` and `last` must delimit a valid contiguous range of
/// [`CxxStringPair`]s. Each COW string object must be valid for
/// [`cxx_string_release`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_record_range_destroy_8(
    _unused: *mut u8,
    mut first: *mut CxxStringPair,
    last: *mut CxxStringPair,
) {
    while first != last {
        cxx_string_release(core::ptr::addr_of_mut!((*first).second));
        cxx_string_release(core::ptr::addr_of_mut!((*first).first));
        first = first.add(1);
    }
}

/// cxx_record_range_destroy_16 — original: `FUN_083e38a0` @ 0x083e38a0
/// (40 bytes; 5 direct `bl` callers).
///
/// Destroys the half-open `[first, last)` range of 16-byte
/// [`StringObjectPair`] records. The first ABI argument in r0 is unused; r1
/// and r2 are the current and end iterators. Each record destroys `second`
/// before `first`, matching the element destructor `FUN_082677e0`: it calls
/// the ported [`string_object_destroy`] @ 0x08277484 on `this + 8`, then
/// again on `this`. The raw ARM loop advances r4 by 16 only after that pair
/// of calls and terminates solely on iterator equality.
///
/// Callers at 0x083e3aa8 and 0x082679f8 pass a vector head in r0 then load
/// its `{begin, end}` into r1/r2; `FUN_083e3aa8` frees that same allocation
/// as 16-byte elements immediately afterward. The record's two-string shape
/// is independently pinned down by `FUN_082677c8`, which constructs
/// StringObjects at offsets 0 and 8, and by `FUN_082680d8`, which moves them
/// individually at those offsets.
///
/// # Safety
/// `first` and `last` must delimit a valid contiguous range of
/// [`StringObjectPair`]s. Each element is destroyed in place, so its payload
/// ownership must be valid for [`string_object_destroy`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_record_range_destroy_16(
    _unused: *mut u8,
    mut first: *mut StringObjectPair,
    last: *mut StringObjectPair,
) {
    while first != last {
        string_object_destroy(core::ptr::addr_of_mut!((*first).second));
        string_object_destroy(core::ptr::addr_of_mut!((*first).first));
        first = first.add(1);
    }
}


/// deque_iter_assign — original: `FUN_083da458` @ 0x083da458
/// (36 bytes; 31 `bl` call sites there, 99 across all 17 byte-identical
/// copies — see the module header).
///
/// Copies a 16-byte deque iterator (`cur`, `seg_base`, `seg_end`,
/// `seg_slot`) word by word, destination in r0 and source in r1. The
/// original returns `dst` in r0 untouched.
///
/// # Safety
/// Both pointers must be valid, 4-byte aligned and 16 bytes wide; the
/// original does not handle overlap (a plain forward word copy).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn deque_iter_assign(dst: *mut u32, src: *const u32) -> *mut u32 {
    for word in 0..4 {
        dst.add(word).write(src.add(word).read());
    }
    dst
}
/// deque_iter_assign_alias_9ec8 — original: `FUN_083d9ec8` @ 0x083d9ec8
/// (36 bytes, `0x083d9ec8..0x083d9eec`; Ghidra reports 36).
///
/// Raw `osos.dec` establishes four forward aligned u32 loads from `src` and
/// stores to `dst`, followed by `bx lr`. The separately linked function at
/// 0x083d9eec fixes the true extent. Decoding its inbound ARM branch words
/// finds three unconditional plain `bl` instructions at 0x081a8578,
/// 0x081a8670, and 0x081fc0b0, with no predicated `bl` forms.
///
/// This byte-identical deque-iterator assignment copies `cur`, `seg_base`,
/// `seg_end`, and `seg_slot`, preserving `dst` in r0 as its return value.
/// It remains a separate exported, link-sectioned alias so this independently
/// hookable retailOS target cannot be folded into [`deque_iter_assign`];
/// there are no other deliberate deviations.
///
/// # Safety
///
/// Both pointers must be valid, 4-byte aligned and 16 bytes wide; the
/// original is a forward word copy and does not handle overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_iter_assign_alias_9ec8")]
#[inline(never)]
pub unsafe extern "C" fn deque_iter_assign_alias_9ec8(
    dst: *mut u32,
    src: *const u32,
) -> *mut u32 {
    for word in 0..4 {
        dst.add(word).write(src.add(word).read());
    }
    dst
}


/// deque_iter_init_elem4 — original: `FUN_083da47c` @ 0x083da47c
/// (64 bytes; 11 plain `bl` call sites, no predicated forms, verified by
/// decoding every ARM B/BL word in `osos.dec`).
///
/// Initializes a 4-byte-element deque iterator: stores `cur`, reads the
/// segment base from `slot`, sets the segment end to `base + 0x80`, stores
/// `slot`, and returns `iter`. A NULL `slot` zeroes both bounds; a non-NULL
/// slot whose segment value is NULL still produces the raw address `0x80`.
/// The 11 callers are 0x083df930, 0x083df970, 0x083dfa4c, 0x083dfa74,
/// 0x083dfaa0, 0x083dfaf8, 0x083dfc78, 0x083dfcb0, 0x083dfdc4,
/// 0x083dfe68, and 0x083dfea4.
///
/// Deliberate deviation: invokes the existing shared
/// [`deque_seg_capacity`] port rather than duplicating this instantiation's
/// adjacent 8-byte `mov r0,#0x20; bx lr` member at 0x083da450.
///
/// # Safety
/// `iter` must be valid for a [`DequeIter`] write. A non-NULL `slot` must
/// be a valid, aligned segment-pointer slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn deque_iter_init_elem4(
    iter: *mut DequeIter,
    cur: *mut u8,
    slot: *mut *mut u8,
) -> *mut DequeIter {
    (*iter).cur = cur;
    if slot.is_null() {
        (*iter).seg_base = core::ptr::null_mut();
        (*iter).seg_end = core::ptr::null_mut();
    } else {
        (*iter).seg_base = slot.read();
        (*iter).seg_end = slot.read().wrapping_add(deque_seg_capacity() * 4);
    }
    (*iter).seg_slot = slot;
    iter
}

/// deque_iter_increment_elem4 — original: `FUN_083da50c` @ `0x083da50c`
/// (76 bytes; 6 direct `bl` call sites: five unconditional and one
/// `blne` at 0x083ea924, verified by decoding every ARM B/BL word in
/// `osos.dec`).
///
/// Advances a 4-byte deque iterator in place. It first advances `cur` by
/// four. Only when that equals `seg_end` does it call the adjacent segment
/// capacity member, advance `seg_slot` by one map entry, load the next
/// segment base, and reset `cur` and `seg_base` there with
/// `seg_end = base + 0x20 * 4`. The raw body has no null or bounds guard:
/// the one predicated incoming call is gated by its caller's element-compare,
/// not by this iterator member.
///
/// Deliberate deviation: the existing [`deque_seg_capacity`] export is loaded
/// through `read_volatile` so LLVM retains the stock capacity-call boundary
/// instead of folding its constant result into this independently hookable body.
///
/// # Safety
/// `iter` must be a valid [`DequeIter`]. When its advanced `cur` equals
/// `seg_end`, `seg_slot + 1` must be a valid, aligned segment-map entry.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_iter_increment_elem4")]
#[inline(never)]
pub unsafe extern "C" fn deque_iter_increment_elem4(iter: *mut DequeIter) -> *mut DequeIter {
    let advanced_cur = (*iter).cur.wrapping_add(4);
    (*iter).cur = advanced_cur;
    if advanced_cur == (*iter).seg_end {
        let capacity_fn = core::ptr::read_volatile(
            &(deque_seg_capacity as unsafe extern "C" fn() -> usize),
        );
        let segment_capacity = capacity_fn();
        let next_slot = (*iter).seg_slot.add(1);
        (*iter).seg_slot = next_slot;
        let next_base = next_slot.read();
        (*iter).seg_base = next_base;
        (*iter).cur = next_base;
        (*iter).seg_end = next_base.wrapping_add(segment_capacity * 4);
    }
    iter
}

/// deque_iter_distance_elem4 — original: `FUN_083eade0` @ 0x083eade0.
///
/// **104 bytes**, exactly 26 ARM instructions from 0x083eade0 through
/// `pop {r4,r5,pc}` at 0x083eae44; the next separately linked function begins
/// at 0x083eae48. Decoding every ARM B/BL-immediate word in `osos.dec` finds
/// four incoming direct calls, all unconditional plain `bl` at 0x083dfb34,
/// 0x083dfb50, 0x083dfb6c, and 0x083eacc8; there are no predicated forms.
/// Its sole outgoing call is an unconditional `bl` to `deque_seg_capacity`.
///
/// Returns the signed distance, in four-byte elements, between two deque
/// iterators. Iterators in distinct segments include the intervening complete
/// segments, the left offset from its segment base, and the right offset to
/// its segment end; iterators in one segment only subtract cursors.
///
/// Deliberate deviation: arithmetic explicitly wraps at 32 bits before each
/// signed shift, preserving target pointer subtraction on 64-bit hosts where
/// pointer fields occupy eight bytes.
///
/// # Safety
/// `left` and `right` must be valid [`DequeIter`] objects.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn deque_iter_distance_elem4(
    left: *const DequeIter,
    right: *const DequeIter,
) -> i32 {
    let left = &*left;
    let right = &*right;
    let words_between = |a: usize, b: usize| (a as u32).wrapping_sub(b as u32) as i32 >> 2;
    if left.seg_slot != right.seg_slot {
        let capacity_fn = core::ptr::read_volatile(
            &(deque_seg_capacity as unsafe extern "C" fn() -> usize),
        );
        let segment_capacity = capacity_fn() as i32;
        (words_between(left.seg_slot as usize, right.seg_slot as usize) - 1) * segment_capacity
            + words_between(left.cur as usize, left.seg_base as usize)
            + words_between(right.seg_end as usize, right.cur as usize)
    } else {
        words_between(left.cur as usize, right.cur as usize)
    }
}
/// deque_iter_distance_elem4_alias_ad78 — original: `FUN_083ead78` @
/// 0x083ead78.
///
/// **104 bytes**, exactly 26 ARM instructions from 0x083ead78 through
/// `pop {r4,r5,pc}` at 0x083eaddc; the next separately linked function begins
/// at 0x083eade0. Full-image A32 decoding of `osos.dec` finds two inbound
/// direct plain `bl` calls at 0x083de5f8 and 0x083eab80, with no predicated
/// `bl` forms. Its sole outgoing call is an unconditional `bl` to the adjacent
/// `deque_seg_capacity` copy at 0x083d9fcc.
///
/// Returns the signed distance, in four-byte elements, between two deque
/// iterators. Iterators in distinct segments include complete intervening
/// segments, the left offset from its segment base, and the right offset to
/// its segment end; iterators in one segment only subtract cursors.
///
/// Deliberate deviations: the capacity call uses the shared
/// [`deque_seg_capacity`] export instead of an otherwise redundant local seam,
/// and arithmetic wraps at 32 bits before signed shifts to preserve target
/// pointer subtraction on 64-bit hosts.
///
/// # Safety
///
/// `left` and `right` must be valid [`DequeIter`] objects.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_iter_distance_elem4_alias_ad78")]
#[inline(never)]
pub unsafe extern "C" fn deque_iter_distance_elem4_alias_ad78(
    left: *const DequeIter,
    right: *const DequeIter,
) -> i32 {
    let left = &*left;
    let right = &*right;
    let words_between = |a: usize, b: usize| (a as u32).wrapping_sub(b as u32) as i32 >> 2;
    if left.seg_slot != right.seg_slot {
        let capacity_fn = core::ptr::read_volatile(
            &(deque_seg_capacity as unsafe extern "C" fn() -> usize),
        );
        let segment_capacity = capacity_fn() as i32;
        (words_between(left.seg_slot as usize, right.seg_slot as usize) - 1) * segment_capacity
            + words_between(left.cur as usize, left.seg_base as usize)
            + words_between(right.seg_end as usize, right.cur as usize)
    } else {
        words_between(left.cur as usize, right.cur as usize)
    }
}


/// deque_iter_equal — original: `FUN_083eaca0` @ 0x083eaca0.
///
/// **68 bytes**, exactly 17 ARM instructions from 0x083eaca0 through
/// 0x083eace0; the next separately linked function begins at 0x083eace4.
/// Decoding every ARM B/BL-immediate word in `osos.dec` finds five inbound
/// direct calls, all unconditional `bl`: 0x083dfbd4, 0x083dfd30, 0x083ea870,
/// 0x083ea8bc, and 0x083ea938. There are no predicated direct calls.
///
/// Returns the widened C++ bool 1 when two 4-byte deque iterators denote the
/// same position, else 0. Equal `cur` fields are immediately equal. Distinct
/// cursors can only match at a segment boundary, where the original delegates
/// to `FUN_083eade0`: its raw arithmetic treats the end of one segment and
/// the base of the adjacent segment as the same logical position.
///
/// Delegates the boundary arithmetic to the separately hookable
/// `deque_iter_distance_elem4` port.
///
/// # Safety
/// `left` and `right` must be valid [`DequeIter`] objects. For the
/// non-identical cursor path, their segment pointers and slots must describe
/// elements in their respective valid segment and map allocations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn deque_iter_equal(left: *const DequeIter, right: *const DequeIter) -> u32 {
    let left = &*left;
    let right = &*right;
    if left.cur != right.cur {
        if left.cur != left.seg_base && right.cur != right.seg_base {
            return 0;
        }

        if deque_iter_distance_elem4(left, right) != 0 {
            return 0;
        }
    }
    1
}
/// deque_iter_equal_elem4_alias_ab58 — original: `FUN_083eab58` @
/// 0x083eab58.
///
/// **68 bytes**, exactly 17 ARM instructions from 0x083eab58 through
/// 0x083eab98; the next separately linked function begins at 0x083eab9c.
/// Decoding every ARM B/BL-immediate word in `osos.dec` finds four inbound
/// direct calls, all unconditional plain `bl`: 0x083de56c, 0x083de5ac,
/// 0x083de6b8, and 0x083de77c. There are no predicated direct calls.
///
/// Returns the widened C++ bool 1 when two 4-byte deque iterators denote the
/// same position, else 0. Equal `cur` fields are immediately equal. Distinct
/// cursors can only match at a segment boundary; this copy calls its adjacent
/// `deque_iter_distance_elem4` instantiation at 0x083ead78, whose verified
/// arithmetic treats the end of one segment and the following base as the
/// same logical position.
///
/// # Deliberate deviation
///
/// The adjacent distance-member copy has the same verified algorithm as the
/// existing [`deque_iter_distance_elem4`] port at 0x083eade0, so this alias
/// directly calls that port rather than adding a redundant retail-address seam.
///
/// # Safety
///
/// `left` and `right` must be valid [`DequeIter`] objects. For the
/// non-identical cursor path, their segment pointers and slots must describe
/// elements in their respective valid segment and map allocations.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_iter_equal_elem4_alias_ab58")]
#[inline(never)]
pub unsafe extern "C" fn deque_iter_equal_elem4_alias_ab58(
    left: *const DequeIter,
    right: *const DequeIter,
) -> u32 {
    let left = &*left;
    let right = &*right;
    if left.cur != right.cur {
        if left.cur != left.seg_base && right.cur != right.seg_base {
            return 0;
        }

        if deque_iter_distance_elem4(left, right) != 0 {
            return 0;
        }
    }
    1
}



/// deque_iter_init_elem4_alias_a3e4 — original: `FUN_083da3e4` @
/// 0x083da3e4 (64 bytes; 9 plain `bl` call sites, no predicated forms,
/// verified by decoding every ARM B/BL word in `osos.dec`).
///
/// The byte-identical twin of [`deque_iter_init_elem4`] @ 0x083da47c:
/// initializes a 4-byte-element deque iterator by writing `cur`, loading
/// `seg_base` from `slot`, writing `seg_end = seg_base + 0x80`, storing the
/// slot, and returning `iter`. A NULL `slot` writes NULL bounds; a non-NULL
/// slot containing NULL still produces the raw address 0x80 for `seg_end`.
/// The 9 callers are 0x083df5c0, 0x083df600, 0x083df6dc, 0x083df704,
/// 0x083df730, 0x083df788, 0x083df7bc, 0x083df86c, and 0x083df8a4.
///
/// Deliberate deviation: calls the established [`deque_seg_capacity`] export
/// rather than adding a redundant Rust wrapper for this copy's adjacent
/// `mov r0,#0x20; bx lr` capacity member at 0x083da3dc.
///
/// # Safety
/// `iter` must be valid for a [`DequeIter`] write. A non-NULL `slot` must
/// be a valid, aligned segment-pointer slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_iter_init_elem4_alias_a3e4")]
#[inline(never)]
pub unsafe extern "C" fn deque_iter_init_elem4_alias_a3e4(
    iter: *mut DequeIter,
    cur: *mut u8,
    slot: *mut *mut u8,
) -> *mut DequeIter {
    (*iter).cur = cur;
    if slot.is_null() {
        (*iter).seg_base = core::ptr::null_mut();
        (*iter).seg_end = core::ptr::null_mut();
    } else {
        (*iter).seg_base = slot.read();
        (*iter).seg_end = slot.read().wrapping_add(deque_seg_capacity() * 4);
    }
    (*iter).seg_slot = slot;
    iter
}
/// deque_iter_init_elem4_alias_a26c — original: `FUN_083da26c` @
/// 0x083da26c (64 bytes; 9 plain `bl` call sites, no predicated forms,
/// verified by decoding every ARM B/BL word in `osos.dec`).
///
/// The 4-byte-element deque-iterator constructor stores `cur`, reads
/// `seg_base` from `slot`, writes `seg_end = seg_base + 0x80`, retains `slot`,
/// and returns `iter`. A NULL `slot` writes NULL bounds; a non-NULL slot
/// containing NULL still produces the raw address 0x80 for `seg_end`. Its
/// callers are 0x083dec4c, 0x083dec8c, 0x083ded68, 0x083ded90, 0x083dedbc,
/// 0x083dee14, 0x083dee48, 0x083def64, and 0x083def9c.
///
/// Deliberate deviation: calls the established [`deque_seg_capacity`] export
/// rather than adding a redundant Rust wrapper for this copy's adjacent
/// `mov r0,#0x20; bx lr` capacity member at 0x083da240.
///
/// # Safety
/// `iter` must be valid for a [`DequeIter`] write. A non-NULL `slot` must
/// be a valid, aligned segment-pointer slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_iter_init_elem4_alias_a26c")]
#[inline(never)]
pub unsafe extern "C" fn deque_iter_init_elem4_alias_a26c(
    iter: *mut DequeIter,
    cur: *mut u8,
    slot: *mut *mut u8,
) -> *mut DequeIter {
    (*iter).cur = cur;
    if slot.is_null() {
        (*iter).seg_base = core::ptr::null_mut();
        (*iter).seg_end = core::ptr::null_mut();
    } else {
        (*iter).seg_base = slot.read();
        let capacity = core::ptr::read_volatile(&(deque_seg_capacity as unsafe extern "C" fn() -> usize));
        (*iter).seg_end = slot.read().wrapping_add(capacity() * 4);
    }
    (*iter).seg_slot = slot;
    iter
}
/// deque_iter_init_elem4_alias_a304 — original: `FUN_083da304` @
/// 0x083da304 (64 bytes; 7 plain `bl` call sites, no predicated forms,
/// verified by decoding every ARM B/BL word in `osos.dec`).
///
/// This independently hookable 4-byte-element deque-iterator constructor
/// stores `cur`, reads `seg_base` from `slot`, sets `seg_end = seg_base +
/// 0x80`, stores `slot`, and returns `iter`. A NULL `slot` zeroes both bounds;
/// a non-NULL slot containing NULL still produces the raw address 0x80 for
/// `seg_end`. Raw ARM ends with `pop {r4,r5,pc}` at 0x083da340; the next
/// separately linked capacity member begins at 0x083da344. The callers are
/// 0x083df08c, 0x083df0b4, 0x083df0e0, 0x083df138, 0x083df16c, 0x083df228,
/// and 0x083df264.
///
/// Deliberate deviation: calls the established [`deque_seg_capacity`] export
/// through a volatile function pointer rather than adding a redundant wrapper
/// for this copy's adjacent `mov r0,#0x20; bx lr` capacity member at
/// 0x083da2d8. The volatile load retains the call instead of folding its
/// constant result into this independently hookable function.
///
/// # Safety
///
/// `iter` must be valid for a [`DequeIter`] write. A non-NULL `slot` must
/// be a valid, aligned segment-pointer slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_iter_init_elem4_alias_a304")]
#[inline(never)]
pub unsafe extern "C" fn deque_iter_init_elem4_alias_a304(
    iter: *mut DequeIter,
    cur: *mut u8,
    slot: *mut *mut u8,
) -> *mut DequeIter {
    (*iter).cur = cur;
    if slot.is_null() {
        (*iter).seg_base = core::ptr::null_mut();
        (*iter).seg_end = core::ptr::null_mut();
    } else {
        (*iter).seg_base = slot.read();
        let capacity = core::ptr::read_volatile(&(deque_seg_capacity as unsafe extern "C" fn() -> usize));
        (*iter).seg_end = slot.read().wrapping_add(capacity() * 4);
    }
    (*iter).seg_slot = slot;
    iter
}
/// deque_iter_init_elem4_alias_a370 — original: `FUN_083da370` @
/// 0x083da370 (64 bytes; 6 plain `bl` call sites, no predicated forms,
/// verified by decoding every ARM B/BL word in `osos.dec`).
///
/// This independently hookable 4-byte-element deque-iterator constructor
/// stores `cur`, reads `seg_base` from `slot`, sets `seg_end = seg_base +
/// 0x80`, stores `slot`, and returns `iter`. A NULL `slot` zeroes both bounds;
/// a non-NULL slot containing NULL still produces the raw address 0x80 for
/// `seg_end`. Raw ARM ends with `pop {r4,r5,pc}` at 0x083da3ac; the next
/// separately linked capacity member begins at 0x083da3b0. The callers are
/// 0x083df3bc, 0x083df3e4, 0x083df414, 0x083df474, 0x083df524, and
/// 0x083df560.
///
/// Deliberate deviation: calls the established [`deque_seg_capacity`] export
/// through a volatile function pointer rather than adding a redundant wrapper
/// for this copy's adjacent `mov r0,#0x20; bx lr` capacity member at
/// 0x083da344. The volatile load retains the call instead of folding its
/// constant result into this independently hookable function.
///
/// # Safety
///
/// `iter` must be valid for a [`DequeIter`] write. A non-NULL `slot` must
/// be a valid, aligned segment-pointer slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_iter_init_elem4_alias_a370")]
#[inline(never)]
pub unsafe extern "C" fn deque_iter_init_elem4_alias_a370(
    iter: *mut DequeIter,
    cur: *mut u8,
    slot: *mut *mut u8,
) -> *mut DequeIter {
    (*iter).cur = cur;
    if slot.is_null() {
        (*iter).seg_base = core::ptr::null_mut();
        (*iter).seg_end = core::ptr::null_mut();
    } else {
        (*iter).seg_base = slot.read();
        let capacity = core::ptr::read_volatile(&(deque_seg_capacity as unsafe extern "C" fn() -> usize));
        (*iter).seg_end = slot.read().wrapping_add(capacity() * 4);
    }
    (*iter).seg_slot = slot;
    iter
}


/// deque_iter_init_elem4_alias_a1d4 — original: `FUN_083da1d4` @
/// 0x083da1d4 (64 bytes; 9 plain `bl` call sites, no predicated forms,
/// verified by decoding every ARM B/BL word in `osos.dec`).
///
/// The 4-byte-element deque-iterator constructor stores `cur`, reads
/// `seg_base` from `slot`, writes `seg_end = seg_base + 0x80`, retains `slot`,
/// and returns `iter`. A NULL `slot` writes NULL bounds; a non-NULL slot
/// containing NULL still produces the raw address 0x80 for `seg_end`. Its
/// callers are 0x083de884, 0x083de8c4, 0x083de9a0, 0x083de9c8, 0x083de9f4,
/// 0x083dea4c, 0x083dea80, 0x083deb9c, and 0x083debd4.
///
/// Deliberate deviation: calls the established [`deque_seg_capacity`] export
/// rather than adding a redundant Rust wrapper for this copy's adjacent
/// `mov r0,#0x20; bx lr` capacity member at 0x083da1a8.
///
/// # Safety
/// `iter` must be valid for a [`DequeIter`] write. A non-NULL `slot` must
/// be a valid, aligned segment-pointer slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_iter_init_elem4_alias_a1d4")]
#[inline(never)]
pub unsafe extern "C" fn deque_iter_init_elem4_alias_a1d4(
    iter: *mut DequeIter,
    cur: *mut u8,
    slot: *mut *mut u8,
) -> *mut DequeIter {
    (*iter).cur = cur;
    if slot.is_null() {
        (*iter).seg_base = core::ptr::null_mut();
        (*iter).seg_end = core::ptr::null_mut();
    } else {
        (*iter).seg_base = slot.read();
        let capacity = core::ptr::read_volatile(&(deque_seg_capacity as unsafe extern "C" fn() -> usize));
        (*iter).seg_end = slot.read().wrapping_add(capacity() * 4);
    }
    (*iter).seg_slot = slot;
    iter
}
/// deque_iter_init_elem4_alias_9ff8 — original: `FUN_083d9ff8` @
/// 0x083d9ff8 (64 bytes; 9 plain `bl` call sites, no predicated forms,
/// verified by decoding every ARM B/BL word in `osos.dec`).
///
/// The 4-byte-element deque-iterator constructor stores `cur`, reads
/// `seg_base` from `slot`, writes `seg_end = seg_base + 0x80`, retains `slot`,
/// and returns `iter`. A NULL `slot` writes NULL bounds; a non-NULL slot
/// containing NULL still produces the raw address 0x80 for `seg_end`. Its
/// callers are 0x0815b3a4, 0x083de2e8, 0x083de310, 0x083de340, 0x083de39c,
/// 0x083de468, 0x083de490, 0x083de4c4, and 0x083de528.
///
/// Deliberate deviation: calls the established [`deque_seg_capacity`] export
/// rather than this copy's adjacent `mov r0,#0x20; bx lr` capacity member at
/// 0x083d9fcc.
///
/// # Safety
/// `iter` must be valid for a [`DequeIter`] write. A non-NULL `slot` must
/// be a valid, aligned segment-pointer slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_iter_init_elem4_alias_9ff8")]
#[inline(never)]
pub unsafe extern "C" fn deque_iter_init_elem4_alias_9ff8(
    iter: *mut DequeIter,
    cur: *mut u8,
    slot: *mut *mut u8,
) -> *mut DequeIter {
    (*iter).cur = cur;
    if slot.is_null() {
        (*iter).seg_base = core::ptr::null_mut();
        (*iter).seg_end = core::ptr::null_mut();
    } else {
        (*iter).seg_base = slot.read();
        let capacity = core::ptr::read_volatile(&(deque_seg_capacity as unsafe extern "C" fn() -> usize));
        (*iter).seg_end = slot.read().wrapping_add(capacity() * 4);
    }
    (*iter).seg_slot = slot;
    iter
}

/// deque_pop_front_elem4 — original: `FUN_083dfdec` @ 0x083dfdec
/// (204 bytes; raw extent 0x083dfdec..0x083dfeb8).
///
/// Removes the first four-byte element from a block deque. It advances the
/// begin cursor and decrements the count. When that consumes a segment (or
/// empties the deque), it frees the spent 32-element segment, advances the
/// segment-map slot, and either re-anchors begin on the next segment or
/// resets both iterators and frees the map. The entry's initial 16-byte
/// stack copy of begin has no subsequent consumer, but is retained through
/// the existing [`deque_iter_assign`] port.
///
/// Raw ARM has six direct calls: iterator copy @ 0x083da458, capacity @
/// 0x083da450, `cxx_array_dealloc` @ 0x08266f2c twice, and iterator init @
/// 0x083da47c twice. Decoding every ARM B/BL immediate in `osos.dec` finds
/// six inbound calls, all unconditional plain `bl` (0x08143e4c, 0x08144180,
/// 0x081de32c, 0x082e7da4, 0x082e7fe0, and 0x083dff24); no predicated form
/// targets this entry. The independent `push {r4,r5,r6,lr}` at 0x083dfeb8
/// starts the adjacent push member and fixes the 204-byte extent.
///
/// # Deliberate deviations
///
/// LLVM otherwise erases the unused trivial iterator copy and folds the
/// capacity constant. Volatile function-pointer loads retain both existing
/// call boundaries; target code uses indirect calls rather than the retail
/// direct `bl` forms. The private helper receives deallocation as a callback
/// solely to make both retirement paths observable in host tests; this export
/// passes the existing direct `cxx_array_dealloc` port.
///
/// # Safety
///
/// `deque` must point to a writable valid four-byte-element [`BlockDeque`].
/// Its count, iterators, and map must describe a nonempty deque; the active
/// segment slot and, when needed, its successor must be readable. Retired
/// segments and the map must meet `cxx_array_dealloc`'s ownership contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_pop_front_elem4")]
#[inline(never)]
pub unsafe extern "C" fn deque_pop_front_elem4(deque: *mut BlockDeque) {
    deque_pop_front_elem4_with(deque, |ptr, count, elem_size| {
        cxx_array_dealloc(ptr, count, elem_size);
    });
}
/// deque_drain_elem4 — original: `FUN_083dff14` @ 0x083dff14
/// (44 bytes; raw extent 0x083dff14..0x083dff40, bounded by the next
/// independently linked `push {r4,r5,r6,lr}`).
///
/// Raw A32 is `push {r4,lr}; mov r4,r0; b test; mov r0,r4; bl
/// 0x083dfdec; mov r0,r4; bl 0x083d7630; cmp r0,#0; beq loop; mov
/// r0,r4; pop {r4,pc}`. It repeatedly removes the front four-byte deque
/// element until the count-based [`container_is_empty`] predicate succeeds,
/// then returns the original deque pointer. Complete branch-immediate
/// decoding finds three inbound plain `bl` calls (0x081a739c, 0x082e7e14,
/// and 0x082e7f14) and no predicated calls; its body has two plain `bl`
/// calls and no predicated call.
///
/// # Deliberate deviations
///
/// None. The test-only model below supplies a recording deallocator for the
/// already-tested pop operation without changing this target path.
///
/// # Safety
///
/// `deque` must point to a writable valid four-byte-element [`BlockDeque`].
/// Its count, iterators, and map must describe every element removed.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_drain_elem4")]
#[inline(never)]
pub unsafe extern "C" fn deque_drain_elem4(deque: *mut BlockDeque) -> *mut BlockDeque {
    while container_is_empty(deque.cast()) == 0 {
        deque_pop_front_elem4(deque);
    }
    deque
}
#[cfg(test)]
unsafe fn deque_drain_elem4_with<F>(deque: *mut BlockDeque, mut deallocate: F) -> *mut BlockDeque
where
    F: FnMut(*mut u8, usize, usize),
{
    while container_is_empty(deque.cast()) == 0 {
        deque_pop_front_elem4_with(deque, &mut deallocate);
    }
    deque
}



unsafe fn deque_pop_front_elem4_with<F>(deque: *mut BlockDeque, mut deallocate: F)
where
    F: FnMut(*mut u8, usize, usize),
{
    // The original copies begin to sp+20 before it performs the pop. Its
    // destructor is trivial, so no later instruction consumes this local.
    let mut discarded_begin = DequeIter::NULL;
    let iter_assign = core::ptr::read_volatile(
        &(deque_iter_assign as unsafe extern "C" fn(*mut u32, *const u32) -> *mut u32),
    );
    iter_assign(
        (&mut discarded_begin as *mut DequeIter).cast::<u32>(),
        deque.cast::<u32>(),
    );

    let d = &mut *deque;
    d.begin.cur = d.begin.cur.wrapping_add(4);
    d.count = d.count.wrapping_sub(1);
    if d.count != 0 && d.begin.cur != d.begin.seg_end {
        return;
    }

    let old_slot = d.begin.seg_slot;
    d.begin.seg_slot = old_slot.add(1);
    let segment_capacity = core::ptr::read_volatile(&(deque_seg_capacity as unsafe extern "C" fn() -> usize));
    deallocate(old_slot.read(), segment_capacity(), 0);

    if d.count != 0 {
        let mut next_begin = DequeIter::NULL;
        deque_iter_init_elem4(&mut next_begin, d.begin.seg_slot.read(), d.begin.seg_slot);
        d.begin = next_begin;
    } else {
        let mut empty = DequeIter::NULL;
        deque_iter_init_elem4(
            &mut empty,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        d.end = empty;
        d.begin = d.end;
        deallocate(d.map.cast::<u8>(), d.map_cap as usize, 0);
    }
}

/// deque_back_elem4 — original: `FUN_083e0044` @ 0x083e0044 (220 bytes;
/// 7 unconditional plain `bl` call sites, no predicated forms, verified by
/// decoding every ARM B/BL word in `osos.dec`: 0x0815a8f4, 0x0815a9b8,
/// 0x0815aaa0, 0x0815adf8, 0x0815b138, 0x0815b86c, and 0x0815b8d4).
///
/// Copies the end iterator, subtracts one 4-byte element, and returns the
/// resulting element address. When that crosses a segment boundary, it uses
/// the copied iterator's segment-map slot to select the predecessor segment
/// and returns its final element. The raw quotient logic also handles an
/// iterator spanning multiple segment strides.
///
/// Deliberate deviation: none. `wrapping_*` preserves the retailOS's
/// 32-bit modular pointer and signed-index arithmetic without imposing Rust
/// in-bounds pointer-arithmetic preconditions.
///
/// # Safety
/// `deque` must describe a non-empty, valid 4-byte-element deque. In
/// particular, `end.seg_slot` and any map slot selected by the raw quotient
/// must be valid, aligned segment-pointer slots.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn deque_back_elem4(deque: *const BlockDeque) -> *mut u8 {
    let end = (*deque).end;
    let element_index = (((end.cur as usize).wrapping_sub(end.seg_base as usize) as u32 as i32) >> 2)
        .wrapping_sub(1);
    let capacity = deque_seg_capacity() as u32;
    let segment_delta = if element_index < 0 {
        let numerator = (capacity as i32)
            .wrapping_sub(element_index)
            .wrapping_sub(1) as u32;
        -((numerator / capacity) as i32)
    } else {
        ((element_index as u32) / capacity) as i32
    };

    if segment_delta == 0 {
        return end.cur.wrapping_sub(4);
    }

    let base = end.seg_slot.wrapping_offset(segment_delta as isize).read();
    let within_segment = element_index.wrapping_sub(segment_delta.wrapping_mul(capacity as i32));
    base.wrapping_add((within_segment as u32).wrapping_mul(4) as usize)
}






/// deque_iter_assign_alias_9f64 — original: `FUN_083d9f64` @ 0x083d9f64
/// (36 bytes, `0x083d9f64..0x083d9f88`; the next separately linked function
/// starts at 0x083d9f88).
///
/// Raw `osos.dec` is eight forward `ldr`/`str` word pairs followed by `bx lr`.
/// Decoding the incoming branch words finds four unconditional plain `bl`
/// calls (0x083ddf2c, 0x083ddf38, 0x083ddfec, and 0x083de050), with no
/// predicated `bl` calls. The callers use the four words as a deque iterator
/// (`cur`, `seg_base`, `seg_end`, `seg_slot`); r0 remains the destination,
/// despite Ghidra's `void` signature. No deliberate deviations.
///
/// # Safety
/// Both pointers must be valid, 4-byte aligned and 16 bytes wide; the
/// original is a plain forward word copy and does not handle overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_iter_assign_alias_9f64")]
#[inline(never)]
pub unsafe extern "C" fn deque_iter_assign_alias_9f64(
    dst: *mut u32,
    src: *const u32,
) -> *mut u32 {
    for word in 0..4 {
        dst.add(word).write(src.add(word).read());
    }
    dst
}


/// deque_iter_assign_alias_9fd4 — original: `FUN_083d9fd4` @ 0x083d9fd4
/// (36 bytes; 22 `bl` call sites, all plain, none predicated — verified
/// by decoding every BL word in osos.dec).
///
/// A second instantiation of [`deque_iter_assign`] — all 36 bytes
/// verified byte-identical against osos.dec: `ldr r2,[r1]; str r2,[r0];
/// ldr r2,[r1,#4]; str r2,[r0,#4]; ldr r2,[r1,#8]; str r2,[r0,#8];
/// ldr r1,[r1,#0xc]; str r1,[r0,#0xc]; bx lr`. Same 16-byte deque
/// iterator copy (`cur`, `seg_base`, `seg_end`, `seg_slot`), dst in r0
/// returned untouched. The pairing identification holds here too: the
/// 8 bytes immediately before it (@ 0x083d9fcc) are `mov r0,#0x20;
/// bx lr`, byte-identical to `deque_seg_capacity` @ 0x083d9ec0.
///
/// Callers: 0x081cb434 and 0x081cb470 in `FUN_081cb408`/
/// `FUN_081cb458` (deque element-at and insert helpers on a
/// `{header, deque}` object at +4, feeding `FUN_083d6fdc` advance and
/// `FUN_083de544` insert), 0x083d6fc0/0x083d6fd4 in `FUN_083d6fb0` and
/// 0x083d6fec/0x083d7000 in `FUN_083d6fdc` (the deque-iterator
/// retreat/advance pair themselves), and 16 sites in `FUN_083de544`
/// (the deque insert-around-midpoint splitter, which shuffles
/// iterators through stack copies between its two subranges).
///
/// Ported as its own exported symbol (the
/// [`vector_size_elem4_alias_76c8`] precedent: identical body under a
/// distinct `link_section` so LLVM's identical-function folding keeps
/// both labels hookable).
///
/// # Safety
/// Both pointers must be valid, 4-byte aligned and 16 bytes wide; the
/// original does not handle overlap (a plain forward word copy).
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_iter_assign_alias_9fd4")]
#[inline(never)]
pub unsafe extern "C" fn deque_iter_assign_alias_9fd4(dst: *mut u32, src: *const u32) -> *mut u32 {
    for word in 0..4 {
        dst.add(word).write(src.add(word).read());
    }
    dst
}

/// deque_iter_assign_alias_a34c — original: `FUN_083da34c` @ 0x083da34c
/// (36 bytes; 6 direct `bl` call sites, all plain and none predicated,
/// verified by decoding every ARM B/BL word in `osos.dec`).
///
/// A byte-identical `deque_iter_assign` instantiation: it copies the four
/// aligned words of a 16-byte deque iterator (`cur`, `seg_base`, `seg_end`,
/// `seg_slot`) forward from `src` to `dst`, then returns `dst` unchanged.
/// The separately linked `push {r4,r5,lr}` at 0x083da370 fixes this body at
/// 36 bytes. Its six callers are 0x082156d8, 0x08215710, 0x0821575c,
/// 0x08215768, 0x0821580c, and 0x083df4a4; none gates the call with an ARM
/// predicate.
///
/// Deliberate deviation: none. This distinct export and text section keep
/// the independently hookable retailOS address from being folded into the
/// byte-identical [`deque_iter_assign`] or
/// [`deque_iter_assign_alias_9fd4`] bodies.
///
/// # Safety
///
/// Both pointers must be valid, 4-byte aligned and 16 bytes wide; the
/// original does not handle overlap (a plain forward word copy).
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_iter_assign_alias_a34c")]
#[inline(never)]
pub unsafe extern "C" fn deque_iter_assign_alias_a34c(
    dst: *mut u32,
    src: *const u32,
) -> *mut u32 {
    for word in 0..4 {
        dst.add(word).write(src.add(word).read());
    }
    dst
}

/// deque_iter_assign_alias_c774 — original: `FUN_0824c774` @ `0x0824c774`
/// (36 bytes; five unconditional plain-`bl` call sites, zero predicated
/// `bl` call sites, binary-verified).
///
/// Raw ARM fixes the true extent as `0x0824c774..0x0824c798`: four
/// `ldr`/`str` pairs copy the aligned 16-byte deque iterator (`cur`,
/// `seg_base`, `seg_end`, `seg_slot`) forward from `src` to `dst`, and
/// `bx lr` returns the untouched `dst` in r0. The next independently linked
/// function begins with `push {r4,lr}` at `0x0824c798`. Decoding every ARM
/// B/BL-immediate word in `osos.dec` finds the five plain calls at
/// 0x0824ccd8, 0x0824cce4, 0x0824d04c, 0x082520b8, and 0x082a1538.
///
/// Deliberate deviations: none. A distinct text section keeps this
/// independently hookable non-C++-block instance from being folded into the
/// byte-identical [`deque_iter_assign`] family.
///
/// # Safety
///
/// Both pointers must be valid, 4-byte aligned and 16 bytes wide; retailOS
/// performs this as a forward word copy without NULL or overlap handling.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_iter_assign_alias_c774")]
#[inline(never)]
pub unsafe extern "C" fn deque_iter_assign_alias_c774(
    dst: *mut u32,
    src: *const u32,
) -> *mut u32 {
    for word in 0..4 {
        dst.add(word).write(src.add(word).read());
    }
    dst
}

/// deque_iter_assign_alias_a1b0 — original: `FUN_083da1b0` @ 0x083da1b0
/// (36 bytes; four unconditional plain-`bl` call sites, zero predicated
/// forms, verified by decoding every ARM B/BL-immediate word in `osos.dec`).
///
/// Raw ARM establishes the true extent as `0x083da1b0..0x083da1d4`: four
/// forward aligned word copies transfer the 16-byte deque iterator (`cur`,
/// `seg_base`, `seg_end`, `seg_slot`) from `src` to `dst`; `bx lr` returns
/// the untouched destination. The next separately linked function begins
/// with `push {r4,r5,lr}` at 0x083da1d4. Its callers are 0x083deb1c,
/// 0x083e005c, 0x083e0068, and 0x083e0110.
///
/// Deliberate deviations: none. This dedicated export and text section keep
/// this independently hookable copy from being folded into the byte-identical
/// [`deque_iter_assign`] family.
///
/// # Safety
///
/// Both pointers must be valid, 4-byte aligned and 16 bytes wide; retailOS
/// performs a forward word copy with no NULL or overlap handling.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_iter_assign_alias_a1b0")]
#[inline(never)]
pub unsafe extern "C" fn deque_iter_assign_alias_a1b0(
    dst: *mut u32,
    src: *const u32,
) -> *mut u32 {
    for word in 0..4 {
        dst.add(word).write(src.add(word).read());
    }
    dst
}



/// Firmware load address of the unported 4-byte deque iterator advance
/// member `FUN_083da088`, called by [`deque_iter_advance_copy_elem4`].
pub const DEQUE_ITER_ADVANCE_ELEM4_ADDRESS: usize = 0x083d_a088;

/// Indirect dispatch for the unported `DequeIter::operator+=` member.
///
/// The member takes its iterator by mutable pointer and a signed element
/// distance, then returns that iterator. Host tests install a model; target
/// builds call the surviving firmware member at
/// [`DEQUE_ITER_ADVANCE_ELEM4_ADDRESS`].
#[derive(Clone, Copy)]
pub struct DequeIterAdvanceElem4Ops {
    pub advance: unsafe extern "C" fn(*mut DequeIter, i32) -> *mut DequeIter,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_deque_iter_advance_elem4(
    iter: *mut DequeIter,
    distance: i32,
) -> *mut DequeIter {
    let f: unsafe extern "C" fn(*mut DequeIter, i32) -> *mut DequeIter =
        core::mem::transmute(DEQUE_ITER_ADVANCE_ELEM4_ADDRESS);
    f(iter, distance)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_deque_iter_advance_elem4(
    _iter: *mut DequeIter,
    _distance: i32,
) -> *mut DequeIter {
    panic!("deque_iter_advance_copy_elem4 requires iterator advance 0x083da088")
}

/// Target default and host-test replacement point for the unported advance
/// member.
pub const DEFAULT_DEQUE_ITER_ADVANCE_ELEM4_OPS: DequeIterAdvanceElem4Ops =
    DequeIterAdvanceElem4Ops {
        advance: firmware_deque_iter_advance_elem4,
    };

/// Active iterator-advance member, read volatile so the target call remains
/// an indirect firmware boundary until 0x083da088 itself is ported.
pub static mut DEQUE_ITER_ADVANCE_ELEM4_OPS: DequeIterAdvanceElem4Ops =
    DEFAULT_DEQUE_ITER_ADVANCE_ELEM4_OPS;

#[inline(always)]
fn deque_iter_advance_elem4_ops() -> DequeIterAdvanceElem4Ops {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DEQUE_ITER_ADVANCE_ELEM4_OPS)) }
}
/// deque_iter_retreat_copy_elem4 — original: `FUN_083d6fb0` @ 0x083d6fb0
/// (44 bytes; 4 plain `bl` call sites, no predicated forms, verified by
/// decoding every ARM B/BL word in `osos.dec`).
///
/// The 4-byte-element deque iterator's non-mutating retreat: copy `source`
/// into a stack iterator, call its signed `operator+=` with the wrapping
/// negation of `distance`, then copy the returned iterator into `dst` and
/// return `dst`. Raw ARM spans the push at 0x083d6fb0 through the
/// `pop {r0,r1,r2,r3,r4,r5,r6,pc}` at 0x083d6fd8; the next sibling begins
/// at 0x083d6fdc. It calls 0x083d9fd4 before and after 0x083da088.
///
/// Deliberate deviation: 0x083da088 is unported, so its call crosses
/// [`DEQUE_ITER_ADVANCE_ELEM4_OPS`]. The target default invokes that
/// firmware address; host tests replace it with a behavioral model. Typed
/// [`DequeIter`] copies retain four disjoint pointer fields on 64-bit hosts
/// while preserving the target's four-word copy.
///
/// # Safety
///
/// `dst` must be writable and `source` readable as complete [`DequeIter`]
/// values. The configured advance member must accept a writable iterator copy.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_iter_retreat_copy_elem4")]
#[inline(never)]
pub unsafe extern "C" fn deque_iter_retreat_copy_elem4(
    dst: *mut DequeIter,
    source: *const DequeIter,
    distance: i32,
) -> *mut DequeIter {
    let mut copy = source.read();
    let retreated = (deque_iter_advance_elem4_ops().advance)(&mut copy, distance.wrapping_neg());
    dst.write(retreated.read());
    dst
}


/// deque_iter_advance_copy_elem4 — original: `FUN_083d6fdc` @ 0x083d6fdc
/// (44 bytes; 9 plain `bl` call sites, no predicated forms, verified by
/// decoding every ARM B/BL word in `osos.dec`).
///
/// The 4-byte-element deque iterator's non-mutating advance: copy `source`
/// into a stack iterator, call its signed `operator+=` with `distance`, then
/// copy the returned iterator into `dst` and return `dst`. Raw ARM places the
/// 16-byte stack copy at `sp`, calls the copy member 0x083d9fd4 before and
/// after `FUN_083da088`, and restores the original `r0`; the next sibling
/// starts at 0x083d7008. The nine unconditional callers are 0x081cb444,
/// 0x081cb480, 0x083de640, 0x083de65c, 0x083de66c, 0x083de688,
/// 0x083de714, 0x083de7ac, and 0x083de7d4.
///
/// Deliberate deviation: 0x083da088 is unported, so its call crosses
/// [`DEQUE_ITER_ADVANCE_ELEM4_OPS`]. The target default invokes that
/// firmware address; host tests replace it with a behavioral model. Typed
/// [`DequeIter`] copies retain four disjoint pointer fields on 64-bit hosts
/// while preserving the target's four-word copy.
///
/// # Safety
///
/// `dst` must be writable and `source` readable as complete [`DequeIter`]
/// values. The configured advance member must accept a writable iterator copy.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_iter_advance_copy_elem4")]
#[inline(never)]
pub unsafe extern "C" fn deque_iter_advance_copy_elem4(
    dst: *mut DequeIter,
    source: *const DequeIter,
    distance: i32,
) -> *mut DequeIter {
    let mut copy = source.read();
    let advanced = (deque_iter_advance_elem4_ops().advance)(&mut copy, distance);
    dst.write(advanced.read());
    dst
}
/// deque_element_at — original: `FUN_081cb408` @ 0x081cb408 (48 bytes,
/// `0x081cb408..0x081cb438`; the next separately linked function starts at
/// 0x081cb438).
///
/// Decoding every aligned ARM branch word in `osos.dec` finds four inbound
/// unconditional plain `bl` calls (0x0815ae04, 0x0815b14c, 0x0815b1c4, and
/// 0x0815b2ac), with no predicated `bl` calls. The body calls
/// [`container_is_empty`] on the deque at `container + 4`; an empty deque
/// returns NULL. Otherwise it copies the begin iterator, advances that private
/// copy by `index`, and returns its `cur` word.
///
/// Deliberate deviation: the target's four contiguous iterator pointer words
/// are decoded individually before calling the existing typed advance seam.
/// This is identical on 32-bit ARM and avoids treating 64-bit host pointers as
/// four-byte fields.
///
/// # Safety
///
/// `container` must point to a target-layout header word followed by a readable
/// block deque. Its iterator advance member must be available through
/// [`DEQUE_ITER_ADVANCE_ELEM4_OPS`].
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_element_at")]
#[inline(never)]
pub unsafe extern "C" fn deque_element_at(container: *const u8, index: i32) -> *mut u8 {
    let deque = container.add(4);
    if container_is_empty(deque) != 0 {
        return core::ptr::null_mut();
    }

    let mut copied = [0u32; 4];
    deque_iter_assign_alias_9fd4(copied.as_mut_ptr(), deque as *const u32);
    let words = copied.as_ptr();
    let source = DequeIter {
        cur: words.read() as usize as *mut u8,
        seg_base: words.add(1).read() as usize as *mut u8,
        seg_end: words.add(2).read() as usize as *mut u8,
        seg_slot: words.add(3).read() as usize as *mut *mut u8,
    };
    let mut advanced = DequeIter::NULL;
    deque_iter_advance_copy_elem4(&mut advanced, &source, index);
    advanced.cur
}


/// A pair of target words ordered by [`less_u32_pair`].
///
/// `first` and `second` occupy the two successive 32-bit words that the ARM
/// comparator loads. `repr(C)` preserves that layout on the target and keeps
/// both host fields disjoint.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct U32Pair {
    pub first: u32,
    pub second: u32,
}

/// less_u32_pair — original: `FUN_083d7388` @ 0x083d7388 (52 bytes; 5 direct
/// unconditional `bl` call sites, binary-verified).
///
/// Orders two referenced [`U32Pair`] values lexicographically with unsigned
/// comparisons: `first` decides unless equal, then `second` decides. The raw
/// ARM body loads `first` from each pair, takes the `bcs` false path when the
/// left word is greater, and compares the second words only on equality. The
/// unused `this` argument remains in the ABI; neither pair pointer is
/// NULL-checked.
///
/// Decoding every aligned ARM `B`/`BL` word in `osos.dec` finds exactly five
/// inbound calls, all plain unconditional `bl` at 0x083b7ac8, 0x083b7b04,
/// 0x083b7be0, 0x083b7d04, and 0x083b7dd8; there are no predicated calls or
/// direct tail branches. The callers are red-black-tree navigation and
/// insertion helpers, establishing this as their key-order predicate.
///
/// # Deliberate deviations
///
/// None.
///
/// # Safety
///
/// `left` and `right` must each point to a readable, aligned [`U32Pair`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn less_u32_pair(
    _this: *const u8,
    left: *const U32Pair,
    right: *const U32Pair,
) -> u32 {
    let left = left.read();
    let right = right.read();
    u32::from(
        left.first < right.first
            || (left.first == right.first && left.second < right.second),
    )
}

/// less_signed — original: `FUN_083d7580` @ 0x083d7580
/// (24 bytes, 45 `bl` call sites; the only copy of this body).
///
/// `std::less<int>::operator()(const int &a, const int &b)` — the
/// operands arrive by reference, so both are dereferenced. `this`
/// arrives in r0 and is immediately overwritten; it is kept in the
/// signature so call sites transcribe one-to-one.
///
/// # Safety
/// `a` and `b` must be valid, aligned `i32` pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn less_signed(_this: *const u8, a: *const i32, b: *const i32) -> u32 {
    u32::from(a.read() < b.read())
}

/// less_unsigned — original: `FUN_083d7598` @ 0x083d7598
/// (24 bytes; 20 `bl` call sites there, 73 across all 12 byte-identical
/// copies — see `names.yaml` for the list).
///
/// [`less_signed`] with an unsigned compare (`movcs`/`movcc` where the
/// signed form uses `movge`/`movlt`): `std::less<unsigned>` over
/// references. That the unsigned form has twelve instantiations and the
/// signed form one is the only thing that tells them apart in the
/// image.
///
/// # Safety
/// `a` and `b` must be valid, aligned `u32` pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn less_unsigned(_this: *const u8, a: *const u32, b: *const u32) -> u32 {
    u32::from(a.read() < b.read())
}
/// less_unsigned_alias_7404 — original: `FUN_083d7404` @ 0x083d7404
/// (24 bytes; 7 `bl` call sites, all unconditional: 0x08109ce0,
/// 0x08109d30, 0x083bb090, 0x083bb0cc, 0x083bb1a8, 0x083bb2cc, and
/// 0x083bb398; verified by decoding every `bl` word in `osos.dec`).
///
/// Byte-identical `std::less<unsigned>::operator()(const unsigned &a,
/// const unsigned &b)` instantiation: load both aligned referenced words,
/// unsigned-compare them, and return 1 when `*a < *b`, otherwise 0. The
/// raw body is `ldr r0,[r1]; ldr r1,[r2]; cmp r0,r1; movcs r0,#0; movcc
/// r0,#1; bx lr`; it neither reads `this` nor guards either operand.
///
/// Deliberately exported in its own text section rather than sharing
/// [`less_unsigned`], so the distinct retailOS branch target remains
/// hookable and LLVM cannot fold the byte-identical bodies.
///
/// # Safety
/// `a` and `b` must be valid, aligned `u32` pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.less_unsigned_alias_7404")]
#[inline(never)]
pub unsafe extern "C" fn less_unsigned_alias_7404(
    _this: *const u8,
    a: *const u32,
    b: *const u32,
) -> u32 {
    u32::from(a.read() < b.read())
}
/// less_unsigned_alias_741c — original: `FUN_083d741c` @ 0x083d741c
/// (24 bytes; 3 plain `bl` call sites, no predicated forms).
///
/// A byte-identical `std::less<unsigned>::operator()(const unsigned &a,
/// const unsigned &b)` instantiation. Raw `osos.dec` establishes the six-word
/// extent through `bx lr` at 0x083d7430; the next independently linked sibling
/// starts at 0x083d7434. It loads both aligned operands, unsigned-compares
/// them, and returns 1 exactly when `*a < *b`; `this` is ignored and neither
/// operand is NULL-checked. Its three unconditional callers are 0x083bbbe4,
/// 0x083bbd08, and 0x083bbdd4 in unsigned-key red-black-tree search and
/// insertion paths.
///
/// # Deliberate deviations
///
/// None. The dedicated text section prevents LLVM from folding this
/// independently hookable target into another identical comparator.
///
/// # Safety
///
/// `a` and `b` must be valid, aligned `u32` pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.less_unsigned_alias_741c")]
#[inline(never)]
pub unsafe extern "C" fn less_unsigned_alias_741c(
    _this: *const u8,
    a: *const u32,
    b: *const u32,
) -> u32 {
    u32::from(a.read() < b.read())
}

/// less_unsigned_alias_7434 — original: `FUN_083d7434` @ 0x083d7434
/// (24 bytes; 5 `bl` call sites, all unconditional: 0x08124e24,
/// 0x08124e74, 0x083bc620, 0x083bc744, and 0x083bc818; verified by
/// decoding every ARM B/BL-immediate word in `osos.dec`).
///
/// Byte-identical `std::less<unsigned>::operator()(const unsigned &a,
/// const unsigned &b)` instantiation: it loads both aligned referenced words,
/// unsigned-compares them, and returns 1 exactly when `*a < *b`. Raw ARM is
/// `ldr r0,[r1]; ldr r1,[r2]; cmp r0,r1; movcs r0,#0; movcc r0,#1; bx lr`;
/// it ignores `this` and has no NULL guards. The separately linked next
/// sibling starts at 0x083d744c, confirming the 24-byte extent.
///
/// Its own text section preserves this independently hookable retail branch
/// target against LLVM identical-function folding. No deliberate deviations.
///
/// # Safety
/// `a` and `b` must be valid, aligned `u32` pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.less_unsigned_alias_7434")]
#[inline(never)]
pub unsafe extern "C" fn less_unsigned_alias_7434(
    _this: *const u8,
    a: *const u32,
    b: *const u32,
) -> u32 {
    u32::from(a.read() < b.read())
}

/// less_unsigned_alias_744c — original: `FUN_083d744c` @ 0x083d744c
/// (24 bytes; 5 `bl` call sites, all unconditional: 0x083bd064,
/// 0x083bd188, 0x083bd25c, 0x083db1cc, and 0x083db21c; verified by
/// decoding every ARM B/BL-immediate word in `osos.dec`).
///
/// Byte-identical `std::less<unsigned>::operator()(const unsigned &a,
/// const unsigned &b)` instantiation: loads both aligned referenced words,
/// unsigned-compares them, and returns 1 when `*a < *b`, otherwise 0. Raw
/// ARM is `ldr r0,[r1]; ldr r1,[r2]; cmp r0,r1; movcs r0,#0; movcc r0,#1;
/// bx lr`; it neither reads `this` nor guards either operand. The next
/// independently linked sibling begins at 0x083d7464, confirming the
/// 24-byte extent.
///
/// This predicate drives red-black-tree lookup and insertion over node keys
/// at `+0x10`. Its own text section preserves this independently hookable
/// retail branch target against LLVM identical-function folding. No deliberate
/// deviations.
///
/// # Safety
/// `a` and `b` must be valid, aligned `u32` pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.less_unsigned_alias_744c")]
#[inline(never)]
pub unsafe extern "C" fn less_unsigned_alias_744c(
    _this: *const u8,
    a: *const u32,
    b: *const u32,
) -> u32 {
    u32::from(a.read() < b.read())
}

/// less_unsigned_alias_7464 — original: `FUN_083d7464` @ 0x083d7464
/// (24 bytes; 5 `bl` call sites, all unconditional: 0x083bd4ac,
/// 0x083bd4e8, 0x083bdb48, 0x083bdc6c, and 0x083bdd38; verified by
/// decoding every ARM B/BL-immediate word in `osos.dec`).
///
/// A byte-identical `std::less<unsigned>::operator()(const unsigned &a,
/// const unsigned &b)` instantiation: it loads both aligned referenced words,
/// unsigned-compares them, and returns 1 exactly when `*a < *b`. The raw ARM
/// is `ldr r0,[r1]; ldr r1,[r2]; cmp r0,r1; movcs r0,#0; movcc r0,#1;
/// bx lr`; it ignores `this` and has no NULL guards. The next independently
/// linked sibling starts at 0x083d747c, confirming the 24-byte extent.
///
/// This predicate drives red-black-tree lookup and insertion over node keys
/// at `+0x10`. Exported in its own text section so LLVM cannot fold this
/// independently hookable retail branch target into another comparator. No
/// deliberate deviations.
///
/// # Safety
/// `a` and `b` must be valid, aligned `u32` pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.less_unsigned_alias_7464")]
#[inline(never)]
pub unsafe extern "C" fn less_unsigned_alias_7464(
    _this: *const u8,
    a: *const u32,
    b: *const u32,
) -> u32 {
    u32::from(a.read() < b.read())
}

/// less_unsigned_alias_747c — original: `FUN_083d747c` @ 0x083d747c
/// (24 bytes; 5 `bl` call sites, all unconditional: 0x083be578,
/// 0x083be5b4, 0x083be690, 0x083be7b4, and 0x083be880; verified by
/// decoding every ARM B/BL-immediate word in `osos.dec`).
///
/// A byte-identical `std::less<unsigned>::operator()(const unsigned &a,
/// const unsigned &b)` instantiation: it loads both aligned referenced words,
/// unsigned-compares them, and returns 1 exactly when `*a < *b`. The raw ARM
/// is `ldr r0,[r1]; ldr r1,[r2]; cmp r0,r1; movcs r0,#0; movcc r0,#1;
/// bx lr`; it ignores `this` and has no NULL guards. The next independently
/// linked sibling starts at 0x083d7494, confirming the 24-byte extent.
///
/// Exported in its own text section so LLVM cannot fold this independently
/// hookable retail branch target into another byte-identical comparator. No
/// deliberate deviations.
///
/// # Safety
/// `a` and `b` must be valid, aligned `u32` pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.less_unsigned_alias_747c")]
#[inline(never)]
pub unsafe extern "C" fn less_unsigned_alias_747c(
    _this: *const u8,
    a: *const u32,
    b: *const u32,
) -> u32 {
    u32::from(a.read() < b.read())
}
///
/// less_unsigned_alias_7494 — original: `FUN_083d7494` @ 0x083d7494
/// (24 bytes; 3 plain `bl` call sites, no predicated forms).
///
/// A byte-identical `std::less<unsigned>::operator()(const unsigned &a,
/// const unsigned &b)` instantiation. Raw `osos.dec` establishes the exact
/// six-instruction extent through `bx lr` at 0x083d74a8; the next separately
/// linked sibling starts at 0x083d74ac. It loads both aligned operands,
/// unsigned-compares them, and returns 1 exactly when `*a < *b`; `this` is
/// ignored and neither operand is NULL-checked. The three unconditional calls
/// are 0x083bf0cc, 0x083bf1f0, and 0x083bf2bc in unsigned-key red-black-tree
/// lookup and insertion paths.
///
/// # Deliberate deviations
///
/// None. The dedicated text section prevents LLVM from folding this
/// independently hookable target into another identical comparator.
///
/// # Safety
///
/// `a` and `b` must be valid, aligned `u32` pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.less_unsigned_alias_7494")]
#[inline(never)]
pub unsafe extern "C" fn less_unsigned_alias_7494(
    _this: *const u8,
    a: *const u32,
    b: *const u32,
) -> u32 {
    u32::from(a.read() < b.read())
}


/// less_unsigned_alias_7568 — original: `FUN_083d7568` @ 0x083d7568
/// (24 bytes; 5 `bl` call sites, all unconditional: 0x083c6b0c,
/// 0x083c6c30, 0x083c6d08, 0x083d65b0, and 0x083d65ec; verified by
/// decoding every ARM B/BL-immediate word in `osos.dec`).
///
/// Byte-identical `std::less<unsigned>::operator()(const unsigned &a,
/// const unsigned &b)` instantiation: loads both aligned referenced words,
/// unsigned-compares them, and returns 1 when `*a < *b`, otherwise 0. Raw
/// ARM is `ldr r0,[r1]; ldr r1,[r2]; cmp r0,r1; movcs r0,#0; movcc r0,#1;
/// bx lr`; it neither reads `this` nor guards either operand. The next
/// independently linked sibling begins at 0x083d7580, confirming the
/// 24-byte extent.
///
/// Deliberately exported in its own text section rather than sharing
/// [`less_unsigned`], so the distinct retailOS branch target remains
/// hookable and LLVM cannot fold the byte-identical bodies. No deviations.
///
/// # Safety
/// `a` and `b` must be valid, aligned `u32` pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.less_unsigned_alias_7568")]
#[inline(never)]
pub unsafe extern "C" fn less_unsigned_alias_7568(
    _this: *const u8,
    a: *const u32,
    b: *const u32,
) -> u32 {
    u32::from(a.read() < b.read())
}
/// less_unsigned_alias_74c4 — original: `FUN_083d74c4` @ 0x083d74c4
/// (24 bytes; 5 `bl` call sites, all unconditional: 0x083c026c,
/// 0x083c02b0, 0x083c085c, 0x083c0974, and 0x083c0a40; verified by
/// decoding every ARM B/BL-immediate word in `osos.dec`).
///
/// Byte-identical `std::less<unsigned>::operator()(const unsigned &a,
/// const unsigned &b)` instantiation: loads both aligned referenced words,
/// unsigned-compares them, and returns 1 when `*a < *b`, otherwise 0. Raw
/// ARM is `ldr r0,[r1]; ldr r1,[r2]; cmp r0,r1; movcs r0,#0; movcc r0,#1;
/// bx lr`; it neither reads `this` nor guards either operand. The next
/// independently linked sibling begins at 0x083d74dc, confirming the
/// 24-byte extent.
///
/// Deliberately exported in its own text section rather than sharing
/// [`less_unsigned`], so the distinct retailOS branch target remains
/// hookable and LLVM cannot fold the byte-identical bodies. No deviations.
///
/// # Safety
/// `a` and `b` must be valid, aligned `u32` pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.less_unsigned_alias_74c4")]
#[inline(never)]
pub unsafe extern "C" fn less_unsigned_alias_74c4(
    _this: *const u8,
    a: *const u32,
    b: *const u32,
) -> u32 {
    u32::from(a.read() < b.read())
}
/// less_unsigned_alias_74ac — original: `FUN_083d74ac` @ 0x083d74ac
/// (24 bytes; 5 `bl` call sites, all unconditional: 0x083bfb58,
/// 0x083bfb94, 0x083bfc70, 0x083bfd94, and 0x083bfecc; verified by
/// decoding every ARM B/BL-immediate word in `osos.dec`).
///
/// Byte-identical `std::less<unsigned>::operator()(const unsigned &a,
/// const unsigned &b)` instantiation: loads both aligned referenced words,
/// unsigned-compares them, and returns 1 when `*a < *b`, otherwise 0. Raw
/// ARM is `ldr r0,[r1]; ldr r1,[r2]; cmp r0,r1; movcs r0,#0; movcc r0,#1;
/// bx lr`; it neither reads `this` nor guards either operand. The next
/// independently linked sibling begins at 0x083d74c4, confirming the
/// 24-byte extent.
///
/// No predicated calls, direct tail branches, or aligned raw data-word
/// references target this entry. The callers use it to navigate and insert
/// nodes whose u32 keys lie at +0x10 in a red-black tree.
///
/// Deliberately exported in its own text section rather than sharing
/// [`less_unsigned`], so the distinct retailOS branch target remains
/// hookable and LLVM cannot fold the byte-identical bodies. No deviations.
///
/// # Safety
/// `a` and `b` must be valid, aligned `u32` pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.less_unsigned_alias_74ac")]
#[inline(never)]
pub unsafe extern "C" fn less_unsigned_alias_74ac(
    _this: *const u8,
    a: *const u32,
    b: *const u32,
) -> u32 {
    u32::from(a.read() < b.read())
}

/// less_unsigned_alias_74dc — original: `FUN_083d74dc` @ 0x083d74dc
/// (24 bytes; 5 `bl` call sites, all unconditional: 0x0825ba0c,
/// 0x0825ba5c, 0x083c11ac, 0x083c12d0, and 0x083c1360; verified by
/// decoding every ARM B/BL-immediate word in `osos.dec`).
///
/// Byte-identical `std::less<unsigned>::operator()(const unsigned &a,
/// const unsigned &b)` instantiation: loads both aligned referenced words,
/// unsigned-compares them, and returns 1 when `*a < *b`, otherwise 0. Raw
/// ARM is `ldr r0,[r1]; ldr r1,[r2]; cmp r0,r1; movcs r0,#0; movcc r0,#1;
/// bx lr`; it neither reads `this` nor guards either operand. The next
/// independently linked sibling begins at 0x083d74f4, confirming the
/// 24-byte extent.
///
/// Deliberately exported in its own text section rather than sharing
/// [`less_unsigned`], so the distinct retailOS branch target remains
/// hookable and LLVM cannot fold the byte-identical bodies. No deviations.
///
/// # Safety
/// `a` and `b` must be valid, aligned `u32` pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.less_unsigned_alias_74dc")]
#[inline(never)]
pub unsafe extern "C" fn less_unsigned_alias_74dc(
    _this: *const u8,
    a: *const u32,
    b: *const u32,
) -> u32 {
    u32::from(a.read() < b.read())
}




/// less_unsigned_byte — original: `FUN_083d73bc` @ 0x083d73bc
/// (24 bytes; 10 `bl` call sites at this copy; the byte-identical
/// twin @ 0x083d73d4 has 3 more and is ported below as
/// [`less_unsigned_byte_alias_73d4`]).
///
/// `std::less<unsigned char>::operator()(const u8 &a, const u8 &b)`
/// — the byte-width member of the [`less_signed`] / [`less_unsigned`]
/// comparator family: loads one byte from each operand reference
/// (`ldrb`), unsigned-compares, and returns 1/0 (`movcs #0` /
/// `movcc #1`). `this` arrives in r0 and is immediately overwritten,
/// exactly as the word-sized functors take it. Callers in the byte
/// key tree (`byte_key_tree_insert_node`, `names.yaml` @ 0x083b8844)
/// use it as the key-ordering predicate deciding left vs right
/// insertion.
///
/// # Safety
/// `a` and `b` must be valid readable `u8` pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn less_unsigned_byte(_this: *const u8, a: *const u8, b: *const u8) -> u32 {
    u32::from(a.read() < b.read())
}

/// less_unsigned_byte_alias_73d4 — original: `FUN_083d73d4` @ 0x083d73d4
/// (24 bytes; 3 `bl` call sites — 0x083b9bec and 0x083b9d10 in
/// `FUN_083b9bac`, 0x083b9de4 in `FUN_083b9d38`;
/// `ipod-decomp/decomp/c/037/083d73d4_FUN_083d73d4.c`).
///
/// A second, byte-identical instantiation of [`less_unsigned_byte`] @
/// 0x083d73bc — all 24 bytes: `ldrb r0,[r1]; ldrb r1,[r2]; cmp r0,r1;
/// movcs r0,#0; movcc r0,#1; bx lr`. Same
/// `std::less<unsigned char>::operator()(const u8 &, const u8 &)`
/// functor, same by-reference operands, same r0 `this` overwrite. Its
/// callers sit in the byte-key-tree cluster beside
/// `byte_key_tree_insert_node` @ 0x083b8844 and use it the same way —
/// the key-ordering predicate: `FUN_083b9bac` walks `cmp r0,#0` /
/// `ldreq r4,[r4,#0xc]` (right) / `ldrne r4,[r4,#0x8]` (left) and
/// re-tests at the insertion point, `FUN_083b9d38` picks the child
/// slot with `streq`/`strne`. Ported as its own exported symbol (the
/// [`vector_size_elem4_alias_76c8`] precedent: identical body under a
/// distinct `link_section` so LLVM's identical-function folding keeps
/// both labels hookable), NOT folded into the primary the way the
/// ledger-only `not_equal_deref` aliases are.
///
/// # Safety
/// `a` and `b` must be valid readable `u8` pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.less_unsigned_byte_alias_73d4")]
#[inline(never)]
pub unsafe extern "C" fn less_unsigned_byte_alias_73d4(
    _this: *const u8,
    a: *const u8,
    b: *const u8,
) -> u32 {
    u32::from(a.read() < b.read())
}
/// less_unsigned_byte_alias_73ec — original: `FUN_083d73ec` @ 0x083d73ec
/// (24 bytes; 5 unconditional `bl` call sites: 0x083ba654, 0x083ba778,
/// 0x083ba850, 0x083d727c, and 0x083d72cc; verified by decoding every ARM
/// B/BL-immediate word in `osos.dec`).
///
/// A third, byte-identical `std::less<unsigned char>::operator()(const u8
/// &, const u8 &)` instantiation. It loads the two referenced bytes, compares
/// them unsigned, and returns 1 precisely when `*a < *b`; `this` is ignored
/// and neither operand is NULL-guarded. The raw sequence is `ldrb r0,[r1];
/// ldrb r1,[r2]; cmp r0,r1; movcs r0,#0; movcc r0,#1; bx lr`. The next
/// independently linked sibling begins at 0x083d7404, confirming the
/// 24-byte extent.
///
/// The five calls occur in byte-key red-black-tree search/insert helpers:
/// `FUN_083ba614` uses two search directions, `FUN_083ba7e0` selects an
/// insert child, and `FUN_083d7248` performs two lookup directions.
///
/// Exported in a distinct text section so LLVM cannot fold this independently
/// hookable retail branch target with either byte-identical predecessor. No
/// deliberate deviations.
///
/// # Safety
/// `a` and `b` must be valid readable `u8` pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.less_unsigned_byte_alias_73ec")]
#[inline(never)]
pub unsafe extern "C" fn less_unsigned_byte_alias_73ec(
    _this: *const u8,
    a: *const u8,
    b: *const u8,
) -> u32 {
    u32::from(a.read() < b.read())
}


/// not_equal_deref — original: `FUN_083d6f78` @ 0x083d6f78
/// (28 bytes; 14 `bl` call sites there, 35 across all 5 byte-identical
/// copies — 0x083d6f78 14, 0x083cf9e0 7, 0x083d6f94 6, 0x083d6f40 4,
/// 0x083d6f5c 4).
///
/// `*a != *b` as 0/1 over word-sized operands taken by reference — the
/// matching inequality functor of [`less_signed`] / [`less_unsigned`].
/// The original computes the EQUALITY first (`movne r0, #0` / `moveq
/// r0, #1`) and then XORs with 1 — a redundant final `eor` the compiler
/// never folded. Kept in the port's doc, though LLVM folds it back.
///
/// The scouting note guessed a `(this, a, b)` functor shape like the
/// comparators; the assembly says otherwise — r2 is never read and r0
/// is dereferenced on the first instruction, so this is a plain binary
/// predicate.
///
/// # Safety
/// `a` and `b` must be valid, aligned `u32` pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn not_equal_deref(a: *const u32, b: *const u32) -> u32 {
    u32::from(a.read() != b.read())
}

/// equal_deref — originals: `FUN_083cf650` @ 0x083cf650,
/// `FUN_083cf668` @ 0x083cf668, `FUN_083cf680` @ 0x083cf680,
/// `FUN_083cf698` @ 0x083cf698, `FUN_083cf6b0` @ 0x083cf6b0,
/// `FUN_083cf6c8` @ 0x083cf6c8, `FUN_083cf6e0` @ 0x083cf6e0,
/// `FUN_083cf758` @ 0x083cf758,
/// `FUN_083cf7b8` @ 0x083cf7b8, `FUN_083cf7e8` @ 0x083cf7e8,
/// `FUN_083cf800` @ 0x083cf800, `FUN_083cf860` @ 0x083cf860, `FUN_083cf878` @ 0x083cf878,
/// `FUN_083cf8c0` @ 0x083cf8c0, `FUN_083cf890` @ 0x083cf890,
/// `FUN_083cf908` @ 0x083cf908, `FUN_083cf920` @ 0x083cf920,
/// `FUN_083cf938` @ 0x083cf938, `FUN_083cf950` @ 0x083cf950,
/// `FUN_083cf968` @ 0x083cf968,
/// `FUN_083cf980` @ 0x083cf980, `FUN_083cf998` @ 0x083cf998,
/// `FUN_083cf9b0` @ 0x083cf9b0, and `FUN_083cf9c8` @ 0x083cf9c8
/// (24 bytes each). Raw bytes show all are the same six-word leaf. At
/// 0x083cf650, the next separately linked copy begins at 0x083cf668,
/// confirming the extent. Decoding every ARM B/BL word
/// in `osos.dec` finds exactly 7 plain `bl` callers there: 0x08109d10,
/// 0x083bab40, 0x083bafac, 0x083bafc8, 0x083bb04c, 0x083bb12c, and
/// 0x083bb21c; there are no predicated calls, tail branches, or aligned
/// raw-word references. It intentionally shares this established export
/// rather than adding a duplicate dispatch seam.
///
/// `FUN_083cf668` runs from `ldr r0,[r0]` at 0x083cf668 through `bx lr` at
/// 0x083cf67c; the next separately linked equal_deref copy begins at
/// 0x083cf680, confirming the 24-byte extent. It performs two unguarded
/// aligned `u32` loads, compares them, and returns normalized 1 or 0 for
/// equality. Decoding every ARM B/BL word in `osos.dec` finds exactly five
/// direct callers, all unconditional plain `bl`: 0x083bb688, 0x083bbaf4,
/// 0x083bbb10, 0x083bbb94, and 0x083bbc58. There are no predicated calls,
/// direct tail branches, or aligned raw-word references. Its byte-identical
/// body deliberately reuses [`equal_deref`] at 0x083cf968 instead of adding a
/// duplicate dispatch seam; hook 0x083cf668 to `equal_deref`. The shared host
/// test covers equal values at distinct addresses, unequal values in both
/// orders, zero, all-bits-set, and iterator-shaped records whose trailing word
/// is not read. Deliberate deviations: none.
/// `FUN_083cf680` runs from `ldr r0,[r0]` at 0x083cf680 through `bx lr` at
/// 0x083cf694; the next separately linked equal_deref copy begins at
/// 0x083cf698, confirming the 24-byte extent. It aligned-loads both u32
/// operands, compares them, and returns normalized 1 or 0 for equality.
/// Decoding every ARM B/BL word in `osos.dec` finds exactly six direct
/// callers, all unconditional `bl`: 0x08134eec, 0x083bd5ec, 0x083bda58,
/// 0x083bda74, 0x083bdaf8, and 0x083bdbbc; there are no predicated calls or
/// tail branches. The body is byte-identical to the established
/// [`equal_deref`] port at 0x083cf968, so this ledger-only alias deliberately
/// adds no duplicate dispatch seam; hook 0x083cf680 to equal_deref.
/// `FUN_083cf6c8` runs from `ldr r0,[r0]` at 0x083cf6c8 through `bx lr` at
/// 0x083cf6dc; the next separately linked equal_deref copy begins at
/// 0x083cf6e0, confirming the 24-byte extent. It aligned-loads both u32
/// operands, compares them, and returns normalized 1 or 0 for equality.
/// Decoding every ARM B/BL word in osos.dec finds exactly six direct callers,
/// all unconditional `bl`: 0x083bf60c, 0x083bfa74, 0x083bfa90, 0x083bfb14,
/// 0x083bfbf4, and 0x083bfce4; there are no predicated calls or tail
/// branches. Aligned raw words at 0x089b3668 and 0x089b36e8 also reference
/// this entry, so its stock hook covers direct and indirect dispatch. This
/// byte-identical copy deliberately reuses [`equal_deref`] rather than adding
/// a redundant dispatch seam.
/// `FUN_083cf6e0` runs from `ldr r0,[r0]` at 0x083cf6e0 through `bx lr` at
/// 0x083cf6f4; the next separately linked equal_deref copy begins at
/// 0x083cf6f8, confirming the 24-byte extent. It aligned-loads both `u32`
/// operands, compares them, and returns normalized 1 or 0 for equality.
/// Decoding every ARM B/BL word in `osos.dec` finds exactly four direct
/// callers, all unconditional plain `bl`: 0x083c0300, 0x083c076c,
/// 0x083c0788, and 0x083c080c; there are no predicated calls, direct tail
/// branches, or aligned raw-word references. Its byte-identical body
/// deliberately reuses the established [`equal_deref`] export rather than
/// introducing a redundant dispatch seam; hook 0x083cf6e0 to equal_deref.
/// The shared host test covers equal values at distinct addresses, unequal
/// values in both orders, zero, all-bits-set, and iterator-shaped records
/// whose trailing word is not read. Deliberate deviations: none.
/// `FUN_083cf6f8` runs from `ldr r0,[r0]` through `bx lr` at 0x083cf70c; the
/// next separately linked equal_deref copy begins at 0x083cf710, confirming
/// the 24-byte extent. It aligned-loads both `u32` operands, compares them,
/// and returns normalized 1 or 0 for equality. Decoding every ARM B/BL word in
/// `osos.dec` finds exactly three direct callers, all unconditional plain
/// `bl`: 0x0825ba3c, 0x083c0d30, and 0x083c1220. There are no predicated
/// calls, tail branches, or aligned raw-word references. Its byte-identical
/// body deliberately reuses the established [`equal_deref`] export rather
/// than introducing a redundant dispatch seam; hook 0x083cf6f8 to
/// `equal_deref`. The shared host test covers equal values at distinct
/// addresses, unequal values in both orders, zero, all-bits-set, and
/// iterator-shaped records whose trailing word is not read. Deliberate
/// deviations: none.
/// `FUN_083cf698` runs from `ldr r0,[r0]` at 0x083cf698 through `bx lr` at
/// 0x083cf6ac; the next separately linked equal_deref copy begins at
/// 0x083cf6b0, confirming the 24-byte extent. It aligned-loads both u32
/// operands, compares them, and returns normalized 1 or 0 for equality.
/// Decoding every ARM B/BL word in osos.dec finds exactly six direct callers,
/// all unconditional `bl`: 0x083be028, 0x083be494, 0x083be4b0, 0x083be534,
/// 0x083be614, and 0x083be704; there are no predicated calls or tail
/// branches. The body is byte-identical to the established equal_deref port
/// at 0x083cf968, so this ledger-only alias deliberately adds no duplicate
/// dispatch seam; hook 0x083cf698 to equal_deref.
/// `FUN_083cf6b0` runs from `ldr r0,[r0]` at 0x083cf6b0 through `bx lr` at
/// 0x083cf6c4; the next separately linked equal_deref copy begins at
/// 0x083cf6c8, confirming the 24-byte extent. It aligned-loads both `u32`
/// operands, compares them, and returns normalized 1 or 0 for equality.
/// Decoding every ARM B/BL word in `osos.dec` finds exactly five direct callers,
/// all unconditional plain `bl`: 0x083beb70, 0x083befdc, 0x083beff8,
/// 0x083bf07c, and 0x083bf140. There are no predicated calls, direct tail
/// branches, or aligned raw-word references. Its byte-identical body deliberately
/// reuses the established [`equal_deref`] export rather than introducing a
/// redundant dispatch seam; hook 0x083cf6b0 to equal_deref. The shared host test
/// covers equal values at distinct addresses, unequal values in both orders,
/// zero, all-bits-set, and iterator-shaped records whose trailing word is not
/// read. Deliberate deviations: none.
/// `FUN_083cf758` comprises the six words through `bx lr` at 0x083cf76c;
/// the next separately linked copy begins at 0x083cf770, fixing its 24-byte
/// extent. Decoding every ARM B/BL word in `osos.dec` finds exactly six
/// inbound unconditional `bl` calls: 0x08259ba4, 0x083b8c4c, 0x083b90b8,
/// 0x083b90d4, 0x083b9158, and 0x083b921c. There are no predicated calls or
/// tail branches; this byte-identical copy deliberately reuses
/// [`equal_deref`] rather than adding a redundant dispatch seam.
/// It finds 7 plain `bl` callers at 0x083cf7a0 (0x08124e54, 0x08124ea8,
/// 0x083bc0c4, 0x083bc530, 0x083bc54c, 0x083bc5d0, and 0x083bc694), with no
/// predicated calls, tail branches, or aligned raw-word references.
/// `FUN_083cf788` is 24 bytes through `bx lr` at 0x083cf79c; the next
/// separately linked copy starts at 0x083cf7a0. It loads each aligned operand
/// word and returns the normalized 0/1 result of `*a == *b`. Decoding every
/// ARM B/BL word in `osos.dec` finds six unconditional plain `bl` callers:
/// 0x083ba0f4, 0x083ba564, 0x083ba580, 0x083ba604, 0x083ba6c8, and
/// 0x083d72ac; there are no predicated calls or tail branches. This
/// byte-identical copy deliberately hooks the established export instead of
/// adding a redundant dispatch seam.
/// Decoding every ARM B/BL word in `osos.dec` finds 8
/// plain `bl` callers at 0x083cf7b8 (0x0809dcf4, 0x0809e074, 0x083bcb08,
/// 0x083bcf74, 0x083bcf90, 0x083bd014, 0x083bd0d8, and 0x083db1fc), with no
/// predicated calls, tail branches, or aligned raw-word references.
/// `FUN_083cf7e8` spans six instructions through `bx lr` at 0x083cf7fc; the
/// separately linked copy at 0x083cf800 fixes its 24-byte extent. It performs
/// two unguarded aligned `u32` loads and returns normalized 1 exactly when the
/// values are equal. Decoding every ARM B/BL-immediate word in `osos.dec`
/// finds exactly five inbound direct calls, all unconditional plain `bl`:
/// 0x083c2384, 0x083c27f8, 0x083c2814, 0x083c2898, and 0x083c295c. There are
/// no predicated calls, direct tail branches, or aligned raw-word references.
/// Its byte-identical body deliberately reuses this established export rather
/// than introducing a redundant dispatch seam; hook 0x083cf7e8 to
/// [`equal_deref`]. The shared host test covers equal values at distinct
/// addresses, unequal values in both orders, zero, all-bits-set, and
/// iterator-shaped records whose trailing word is not read. Deliberate
/// deviations: none.
///
/// `FUN_083cf800` runs from `ldr r0,[r0]` at 0x083cf800 through `bx lr` at
/// 0x083cf814; the next separately linked equal_deref copy begins at
/// 0x083cf818, confirming the 24-byte extent. It aligned-loads both u32
/// operands, compares them, and returns normalized 1 or 0 for equality.
/// Decoding every ARM B/BL-immediate word in osos.dec finds exactly four
/// inbound direct calls, all unconditional plain `bl`: 0x081df9f0,
/// 0x081dfb5c, 0x083c2e68, and 0x083db47c; there are no predicated calls,
/// direct tail branches, or aligned raw-word references. Its byte-identical
/// body deliberately reuses [`equal_deref`] rather than adding a redundant
/// dispatch seam; hook 0x083cf800 to equal_deref. The shared host test
/// covers equal values at distinct addresses, unequal values in both
/// orders, zero, all-bits-set, and iterator-shaped records whose trailing
/// word is not read. Deliberate deviations: none.
///
/// Decoding every ARM B/BL word in `osos.dec` finds 8 plain `bl` callers at
/// 0x083cf8a8 (0x081bf838, 0x0839bc00, 0x083c6ff8, 0x083c7464,
/// 0x083c7480, 0x083c7504, 0x083c75c8, and 0x083db8ac), with no predicated
/// calls, tail branches, or aligned raw-word references.
/// The 0x083cf8c0 copy is 24 bytes through `bx lr` at 0x083cf8d4; the
/// separately linked 0x083cf8d8 copy follows immediately. Its six direct
/// callers are all unconditional `bl`: 0x083c7a3c, 0x083c7ea8, 0x083c7ec4,
/// 0x083c7f48, 0x083c8028, and 0x083c8118. Decoding every ARM B/BL word finds
/// no predicated call or tail branch. It has no NULL guard; routing this
/// byte-identical copy to the established export is the deliberate deviation,
/// avoiding a redundant dispatch seam.
/// `FUN_083cf830` @ 0x083cf830 is a separately linked 24-byte copy through
/// `bx lr` at 0x083cf844; the next function, `FUN_083cf848`, begins
/// immediately afterward. It performs two unguarded aligned `u32` loads and
/// returns normalized 1 exactly when their values are equal. Decoding every
/// ARM B/BL-immediate word in `osos.dec` finds exactly five inbound direct
/// calls, all unconditional plain `bl`: 0x083c3794, 0x083c3c08, 0x083c3c24,
/// 0x083c3ca8, and 0x083c3d6c. There are no predicated calls, direct tail
/// branches, or aligned raw-word references. Its byte-identical body
/// deliberately reuses this established export rather than introducing a
/// redundant dispatch seam; hook 0x083cf830 to [`equal_deref`]. The shared
/// host test covers equal values at distinct addresses, unequal values in both
/// orders, zero, all-bits-set, and iterator-shaped records whose trailing word
/// is not read. Deliberate deviations: none.
///
/// `FUN_083cf860` is a separately linked 24-byte copy through `bx lr` at
/// 0x083cf874; the next equal_deref copy begins at 0x083cf878. It performs two
/// unguarded aligned u32 loads and returns normalized 1 exactly when the values
/// are equal. Decoding every ARM B/BL word in `osos.dec` finds exactly five
/// direct callers, all unconditional plain `bl`: 0x083c4f1c, 0x083c4f8c,
/// 0x083c53f8, 0x083c5414, and 0x083c5498. There are no predicated forms,
/// direct tail branches, or aligned raw-word references. Its byte-identical body
/// deliberately reuses this established export rather than introducing a
/// redundant dispatch seam; hook 0x083cf860 to [`equal_deref`]. The shared host
/// test covers equal values at distinct addresses, unequal values in both
/// orders, zero, all-bits-set, and iterator-shaped records whose trailing word
/// is not read. Deliberate deviations: none.
/// `FUN_083cf878` is a separately linked 24-byte copy through `bx lr` at
/// 0x083cf88c; the next equal_deref copy begins at 0x083cf890. It performs
/// two unguarded aligned u32 loads and returns normalized 1 exactly when the
/// loaded words are equal. Decoding every ARM B/BL word in `osos.dec` finds
/// five direct callers, all unconditional plain `bl`: 0x083c5b2c, 0x083c5fa0,
/// 0x083c5fbc, 0x083c6040, and 0x083c6104. There are no predicated forms,
/// direct tail branches, or aligned raw-word references. Its byte-identical
/// body deliberately reuses this established export rather than introducing a
/// redundant dispatch seam; hook 0x083cf878 to [`equal_deref`]. The shared
/// host test covers equal values at distinct addresses, unequal values in both
/// orders, zero, all-bits-set, and iterator-shaped records whose trailing word
/// is not read. Deliberate deviations: none.
/// `FUN_083cf890` is a separately linked 24-byte copy through `bx lr` at
/// 0x083cf8a4; the next equal_deref copy begins at 0x083cf8a8. It performs
/// two unguarded aligned word loads and returns normalized 1 only when the
/// values are equal. Decoding every ARM B/BL word in `osos.dec` finds exactly
/// five direct callers, all unconditional plain `bl`: 0x083c65ac, 0x083c6a1c,
/// 0x083c6a38, 0x083c6abc, and 0x083c6b80. There are no predicated calls,
/// direct tail branches, or aligned raw-word references. Its byte-identical
/// body deliberately reuses this established export rather than adding a
/// redundant dispatch seam; hook 0x083cf890 to [`equal_deref`]. The shared
/// host test covers equal values at distinct addresses, unequal values in both
/// orders, zero, all-bits-set, and iterator-shaped records whose trailing word
/// is not read. Deliberate deviations: none.
/// It finds 8 plain `bl` callers at 0x083cf8f0 (0x081bd33c, 0x0839bc54, 0x083c8fd0,
/// 0x083c943c, 0x083c9458, 0x083c94dc, 0x083c95a0, 0x083db9c4), with no
/// predicated calls, tail branches, or aligned raw-word references. It finds
/// 8 plain `bl` callers at 0x083cf908 (0x081bea64, 0x0839bca8, 0x083c9a14,
/// 0x083c9e80, 0x083c9e9c, 0x083c9f20, 0x083c9fe4, 0x083dba6c), with no
/// 7 plain `bl` callers at 0x083cf920 (0x0819f668, 0x0819f6bc, 0x083ca458,
/// 0x083ca8c4, 0x083ca8e0, 0x083ca964, and 0x083caa28), with no predicated
/// calls, tail branches, or aligned raw-word references. It finds 8 plain `bl`
/// callers at 0x083cf950 (0x081bdd38, 0x0839bcfc, 0x083cb914, 0x083cbd80,
/// 0x083cbd9c, 0x083cbe20, 0x083cbee4, and 0x083dbb14), also with no
/// predicated calls or tail branches.
/// The 0x083cf938 copy is the same six instructions through `bx lr` at
/// 0x083cf94c; 0x083cf950 begins the next copy, confirming its 24-byte
/// extent. It has exactly six direct callers, all unconditional `bl`:
/// 0x0829f30c, 0x083caec8, 0x083cb338, 0x083cb354, 0x083cb3d8, and
/// 0x083cb49c. There are no predicated calls, tail branches, or aligned
/// raw-word references, so its hook deliberately uses this existing
/// byte-identical export rather than adding a redundant dispatch seam.
/// The canonical copy has 12 plain `bl`
/// callers; the 0x083cf980 copy has 9 plain `bl` callers — 0x081e1518,
/// 0x081e1568, 0x083cd808, 0x083cdc74, 0x083cdc90, 0x083cdd14, 0x083cddf4,
/// 0x083cdee4 and 0x083dbcc4 — likewise with no predicated forms. The
/// 0x083cf9b0 copy has exactly six direct callers, all unconditional `bl`:
/// 0x083cc358, 0x083cc7c4, 0x083cc7e0, 0x083cc864, 0x083cc928, and
/// 0x083dbf64. Decoding every ARM B/BL word finds no predicated calls or
/// direct tail branches.
///
/// `FUN_083cf998` @ 0x083cf998 is a separately linked 24-byte copy through
/// `bx lr` at 0x083cf9ac; `FUN_083cf9b0` starts immediately after it. It
/// performs two unguarded aligned word loads and returns normalized 1 or 0
/// for equality. Decoding every ARM B/BL word in `osos.dec` finds exactly
/// five direct callers, all unconditional plain `bl`: 0x083ce358,
/// 0x083ce7c4, 0x083ce7e0, 0x083ce864, and 0x083ce928. There are no
/// predicated calls, direct tail branches, or aligned raw-word references.
/// Its byte-identical body deliberately reuses this established export rather
/// than adding a redundant dispatch seam; hook 0x083cf998 to `equal_deref`.
/// The shared host test covers equal values at distinct addresses, unequal
/// values in both orders, zero, all-bits-set, and iterator-shaped records
/// whose trailing word is not read. Deliberate deviation: none.
/// direct tail branches. The 0x083cf9c8 copy has six direct callers: five
/// plain `bl` at 0x083ced9c,
/// 0x083cf208, 0x083cf224, 0x083cf2a8, and 0x083cf36c, plus predicated
/// `blhi` at 0x088a976c; there are no direct tail branches.
///
/// The 0x083cf9c8 alias has no NULL guard: its first two instructions load
/// both operands. No behavioral deviation is introduced by routing its hook
/// to this byte-identical export rather than creating a redundant symbol.
///
/// `*a == *b` as 0/1 over word-sized operands taken by reference:
/// `ldr r0,[r0]; ldr r1,[r1]; cmp r0,r1; movne r0,#0; moveq r0,#1`
/// — the matching EQUALITY functor of [`not_equal_deref`], without that
/// family's redundant final `eor`.
/// `FUN_083cf740` @ 0x083cf740 is a separately linked 24-byte copy with
/// exactly six direct `bl` callers (0x083b8160, 0x083b85cc, 0x083b85e8,
/// 0x083b866c, 0x083b8730, and 0x083daffc), all unconditional in the
/// binary scan. It performs the same two aligned word loads, comparison, and
/// normalized 0/1 result as this export. Its byte-identical body reuses this
/// established implementation rather than introducing a redundant dispatch
/// seam; hook 0x083cf740 to [`equal_deref`].
///
///
/// The 0x083cf968 callers are container-iteration loops: they
/// stack-materialize a cursor iterator and the list/deque end iterator and
/// compare their FIRST words (the current-node pointer) through this helper,
/// i.e. the ADS checked-iterator `operator==`. The 0x083cf650, 0x083cf770,
/// 0x083cf788, 0x083cf7d0, 0x083cf7b8, 0x083cf908, 0x083cf920, 0x083cf938,
/// 0x083cf950, 0x083cf980, 0x083cf9b0, and 0x083cf9c8 copies have the same
/// raw body and ABI, so their ledger entries deliberately hook this established
/// export instead of introducing redundant dispatch seams.
///
/// `FUN_083cf710` @ 0x083cf710 is a separately linked 24-byte copy with five
/// direct, unconditional `bl` callers (0x08211b64, 0x083b6e88, 0x083b72fc,
/// 0x083b7318, and 0x083b739c). Its two aligned loads compare dereferenced
/// words and return normalized equality, with no NULL guard. It deliberately
/// reuses this byte-identical export: no behavioral deviation or duplicate
/// dispatch seam is introduced.
///
/// `FUN_083cf7d0` @ 0x083cf7d0 is a separately linked 24-byte copy with five
/// direct, unconditional `bl` callers (0x083c1790, 0x083c1800, 0x083c1c6c,
/// 0x083c1c88, and 0x083c1d0c); its two aligned loads compare the dereferenced
/// words and return normalized equality, with no NULL guard. It deliberately
/// reuses this byte-identical export: no behavioral deviation or duplicate
/// dispatch seam is introduced.
///
/// `FUN_083cf770` @ 0x083cf770 is a separately linked 24-byte copy with five
/// direct, unconditional `bl` callers (0x083b9690, 0x083b9afc, 0x083b9b18,
/// 0x083b9b9c, and 0x083b9c60). Its two aligned loads compare dereferenced
/// words and return normalized equality, with no NULL guard. It deliberately
/// reuses this byte-identical export: no behavioral deviation or duplicate
/// dispatch seam is introduced.
///
/// The body is byte-identical to `fixed16_eq_indirect` @ 0x082a1834
/// ([`crate::fp::fp_misc`]) — a Q16.16 comparator that merely shares
/// the load-cmp-select shape. The distinct `link_section` below keeps
/// LLVM's identical-function folding from merging the two exports so
/// both stay hookable (the `vector_size_elem4_alias_76c8` precedent).
///
/// # Safety
/// `a` and `b` must be valid, aligned `u32` pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.equal_deref")]
#[inline(never)]
pub unsafe extern "C" fn equal_deref(a: *const u32, b: *const u32) -> u32 {
    u32::from(a.read() == b.read())
}
/// iterator_equal — original: `FUN_083cf848` @ 0x083cf848 (24 bytes;
/// 11 `bl` call sites, all unconditional, binary-verified: 0x08101c60,
/// 0x08101e54, 0x08101f1c, 0x08101f60, 0x083c4258, 0x083c46c8,
/// 0x083c46e4, 0x083c4768, 0x083c4848, 0x083c4938, 0x083db5bc).
///
/// Returns 1 when the current-node words in two checked iterators are
/// equal, otherwise 0. The raw body performs exactly two aligned loads,
/// compares them, and materializes the equality result:
/// `ldr r0,[r0]; ldr r1,[r1]; cmp r0,r1; movne r0,#0; moveq r0,#1`.
/// The string-table callers use this as the header-node miss test.
///
/// This is byte-identical to [`equal_deref`] @ 0x083cf968, but remains a
/// distinct export because 0x083cf848 is independently hookable. Its
/// dedicated section prevents LLVM from folding their bodies together.
///
/// # Safety
/// `a` and `b` must be valid, aligned `u32` pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.iterator_equal")]
#[inline(never)]
pub unsafe extern "C" fn iterator_equal(a: *const u32, b: *const u32) -> u32 {
    u32::from(a.read() == b.read())
}

/// container_is_empty — original: `FUN_083d75e0` @ 0x083d75e0
/// (16 bytes; 15 `bl` call sites there, 92 across all 9 byte-identical
/// copies — 0x083d75e0 15, 0x083d7610 13, 0x083d75c0 13, 0x083d7630 12,
/// 0x083d75f0 10, 0x083d7620 9, 0x083d7600 8, 0x083d75d0 6,
/// 0x083d75b0 6).
///
/// Returns 1 when the word at `this + 0x20` is zero, 0 otherwise — the
/// ADS idiom for `return !x` (`rsbs r0, r0, #1` / `movcc r0, #0`).
/// Callers use it as an emptiness predicate (`if (!empty()) front()`,
/// `if (empty()) construct`), but whether the +0x20 word is a count or
/// a head pointer is NOT pinned down and the owning class is not
/// identified, so the name is provisional — it says what callers use
/// the answer for, which is all the firmware tells us.
///
/// The word is addressed by WORD INDEX (8), so the port is byte-exact
/// +0x20 on the 32-bit target and keeps the field disjoint on a 64-bit
/// host. It is read as a full `u32` — zero is zero in either width.
///
/// # Safety
/// `container` must have at least nine readable words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn container_is_empty(container: *const u8) -> u32 {
    u32::from((container as *const u32).add(8).read() == 0)
}

/// Signature of the container's virtual element-slot method: given an
/// index it returns the *address of the slot* holding the element
/// pointer, which [`container_element_at`] then loads.
pub type ElementSlotFn = unsafe extern "C" fn(this: *mut u8, index: usize) -> *mut *mut u8;

/// Vtable **slot index** of that method — the original's `ldr r2,
/// [r2, #0x40]`, i.e. slot 16 on the 32-bit target. Indexed by slot,
/// not by byte offset, so the port is correct on a 64-bit test host too.
pub const ELEMENT_SLOT_VTABLE_INDEX: usize = 0x40 / 4;
/// ARMv5TE vtable word indices for the two container methods this wrapper
/// dispatches: lookup at `+0x4c`, then removal at `+0x2c`.
const CONTAINER_ELEMENT_LOOKUP_SLOT: usize = 0x4c / 4;
const CONTAINER_REMOVE_AT_SLOT: usize = 0x2c / 4;

/// ABI of the unrecovered element-lookup virtual method at vtable `+0x4c`.
pub type ContainerElementLookupFn = unsafe extern "C" fn(*mut u8, *mut u8) -> i32;

/// ABI of the unrecovered remove-at-index virtual method at vtable `+0x2c`.
pub type ContainerRemoveAtFn = unsafe extern "C" fn(*mut u8, i32);

/// container_remove_element — original: `FUN_083d125c` @ **0x083d125c**
/// (64 bytes). Raw ARM establishes the complete extent from `push {r0,r1,r4,
/// r5,r6,lr}` at `0x083d125c` through `pop {r2,r3,r4,r5,r6,pc}` at
/// `0x083d1298`; the next separately linked function begins at `0x083d129c`.
///
/// Decoding every aligned immediate ARM `B`/`BL` word in `osos.dec` finds
/// exactly five inbound direct calls, all unconditional plain `bl` at
/// `0x0816dff4`, `0x0816e114`, `0x0816e18c`, `0x0816e1ec`, and `0x0816e214`.
/// There are no predicated calls or direct tail branches.
///
/// # Algorithm
///
/// Calls the container's unrecovered vtable `+0x4c` lookup with `element`.
/// A `-1` result is returned without removing anything; every other signed
/// result is passed to vtable `+0x2c` to remove that index, then returned.
/// The container's vtable is re-read between the calls exactly as retailOS
/// does. No pointer or callback is NULL-checked.
///
/// # Deliberate deviation
///
/// Target vtable entries are 32-bit words, whereas host function pointers are
/// wider. The port selects the same word indices in a host-sized vtable and
/// performs equivalent typed virtual calls. The concrete method identities
/// remain unrecovered and are deliberately not invented.
///
/// # Safety
///
/// `container` must contain a readable vtable pointer whose lookup and, on a
/// nonnegative result, remove-at entries are valid for their documented ABIs.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_remove_element")]
#[inline(never)]
pub unsafe extern "C" fn container_remove_element(
    container: *mut u8,
    element: *mut u8,
) -> i32 {
    let vtable = (container as *const *const usize).read();
    let lookup_entry = vtable.add(CONTAINER_ELEMENT_LOOKUP_SLOT).read();
    let lookup: ContainerElementLookupFn = core::mem::transmute(lookup_entry);
    let index = lookup(container, element);
    if index != -1 {
        let vtable = (container as *const *const usize).read();
        let remove_entry = vtable.add(CONTAINER_REMOVE_AT_SLOT).read();
        let remove: ContainerRemoveAtFn = core::mem::transmute(remove_entry);
        remove(container, index);
    }
    index
}


/// container_element_at — original: `FUN_083d5efc` @ 0x083d5efc
/// (24 bytes; 13 `bl` call sites there, 154 across all 30
/// byte-identical copies — see `names.yaml` for the list; the copies @
/// 0x083d689c, 0x083d68dc, and @ 0x083d6908 are ported below as
/// [`container_element_at_alias_689c`],
/// [`container_element_at_alias_68dc`], and
/// [`container_element_at_alias_6908`]).
///
/// `T *operator[](size_t index)`: dispatches through the container's
/// own vtable (slot 0x40) to get the address of the element slot, then
/// loads the element pointer out of it. The `push {r4, lr}` in the
/// original saves nothing — r4 is never touched — it is there for
/// stack alignment.
///
/// The vtable pointer is read from the object, so subclass and test
/// vtables are honored; this is the same shape `heap/block_deque` uses
/// for the element destructor.
///
/// A NULL return from the virtual method faults on the load, exactly as
/// the original does — there is no guard to port.
///
/// # Safety
/// `this` must point at an object whose first word is a vtable with at
/// least [`ELEMENT_SLOT_VTABLE_INDEX`] + 1 slots.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn container_element_at(this: *mut u8, index: usize) -> *mut u8 {
    let vtable = (this as *const *const ElementSlotFn).read();
    let element_slot = vtable.add(ELEMENT_SLOT_VTABLE_INDEX).read();
    element_slot(this, index).read()
}
/// container_element_at_alias_9bac0 — original: `FUN_0829bac0` @ 0x0829bac0
/// (24 bytes; 7 plain `bl` call sites — 0x080fe88c, 0x0810b34c,
/// 0x0813ef14, 0x08155f10, 0x08156048, 0x0827df04, and 0x0827df68;
/// no predicated calls).
///
/// A byte-identical instantiation of [`container_element_at`] @
/// 0x083d5efc: `T *operator[](size_t index)`. It dispatches through the
/// container's own vtable slot 0x40 for an element-slot address, then loads
/// the element pointer from that slot. The ARM `push {r4,lr}` only aligns the
/// stack; r4 is never touched. The raw body has no NULL guard for either the
/// virtual result or its element slot.
///
/// Ghidra omits the r1 index argument from its one-argument signature, but
/// the `blx r2` preserves it for the virtual method. The decoded callers pass
/// loop indexes and consume the returned element as a signed value, pointer,
/// or byte. This distinct link section deliberately keeps the independently
/// hookable export from being folded into a byte-identical sibling; otherwise
/// there are no deliberate deviations from the ARM algorithm.
///
/// # Safety
/// Same contract as [`container_element_at`]: `this` must point at an object
/// whose first word is a vtable with at least [`ELEMENT_SLOT_VTABLE_INDEX`] +
/// 1 slots.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_element_at_alias_9bac0")]
#[inline(never)]
pub unsafe extern "C" fn container_element_at_alias_9bac0(this: *mut u8, index: usize) -> *mut u8 {
    let vtable = (this as *const *const ElementSlotFn).read();
    let element_slot = vtable.add(ELEMENT_SLOT_VTABLE_INDEX).read();
    element_slot(this, index).read()
}

/// container_element_at_alias_5f14 — original: `FUN_083d5f14` @ 0x083d5f14
/// (24 bytes; 11 plain `bl` call sites — 0x081002e4, 0x08100408,
/// 0x08100624, 0x0810070c, 0x081008f4, 0x08100930, 0x081010a4,
/// 0x08101538, 0x08101550, 0x0839c004 and 0x0839c048; no predicated
/// calls).
///
/// A byte-identical instantiation of [`container_element_at`] @
/// 0x083d5efc: `T *operator[](size_t index)`. It dispatches through the
/// container's own vtable slot 0x40 for an element-slot address, then
/// loads that slot's element pointer. `push {r4, lr}` is pure stack
/// alignment: r4 is never touched. The raw body has no NULL guard for
/// either the virtual result or its element slot.
///
/// Its callers pass an index in r1 and use the result as an element pointer:
/// the 0x0839bffc caller advances an index until a non-NULL element appears,
/// while the UI callers test and consume returned records. The dedicated
/// link section deliberately keeps this independently hookable export from
/// being folded into a byte-identical body; otherwise the implementation
/// has no deliberate deviations from the ARM algorithm.
///
/// # Safety
/// Same contract as [`container_element_at`]: `this` must point at an
/// object whose first word is a vtable with at least
/// [`ELEMENT_SLOT_VTABLE_INDEX`] + 1 slots.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_element_at_alias_5f14")]
#[inline(never)]
pub unsafe extern "C" fn container_element_at_alias_5f14(this: *mut u8, index: usize) -> *mut u8 {
    let vtable = (this as *const *const ElementSlotFn).read();
    let element_slot = vtable.add(ELEMENT_SLOT_VTABLE_INDEX).read();
    element_slot(this, index).read()
}
/// container_element_at_alias_5f2c — original: `FUN_083d5f2c` @ 0x083d5f2c
/// (24 bytes; five plain `bl` call sites — 0x082845e0, 0x082846f4,
/// 0x08284780, 0x08284828, and 0x0839c164; no predicated calls — plus the
/// non-call `b` tail branch at 0x082a6788).
///
/// A byte-identical instantiation of [`container_element_at`] @
/// 0x083d5efc: `T *operator[](size_t index)`. It dispatches through the
/// container's own vtable slot 0x40 for an element-slot address, then loads
/// that slot's element pointer. Raw ARM covers exactly `push {r4,lr}; ldr
/// r2,[r0]; ldr r2,[r2,#0x40]; blx r2; ldr r0,[r0]; pop {r4,pc}`; the next
/// independently linked sibling begins at 0x083d5f44.
///
/// Ghidra omits the r1 index parameter, but the indirect `blx` preserves it
/// for the virtual method. The body has no NULL guard for the virtual result
/// or element slot. Its dedicated link section keeps this independently
/// hookable export from folding into a byte-identical body; otherwise there
/// are no deliberate deviations from the ARM algorithm.
///
/// # Safety
/// Same contract as [`container_element_at`]: `this` must point at an object
/// whose first word is a vtable with at least [`ELEMENT_SLOT_VTABLE_INDEX`] +
/// 1 slots.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_element_at_alias_5f2c")]
#[inline(never)]
pub unsafe extern "C" fn container_element_at_alias_5f2c(this: *mut u8, index: usize) -> *mut u8 {
    let vtable = (this as *const *const ElementSlotFn).read();
    let element_slot = vtable.add(ELEMENT_SLOT_VTABLE_INDEX).read();
    element_slot(this, index).read()
}


/// container_element_at_alias_5f44 — original: `FUN_083d5f44` @ 0x083d5f44
/// (24 bytes; 8 plain `bl` call sites — 0x08126ef0, 0x081272f4,
/// 0x081273ac, 0x08127de0, 0x08127e04, 0x08127e30, 0x0839c1f0, and
/// 0x0839c234; no predicated calls).
///
/// A byte-identical instantiation of [`container_element_at`] @
/// 0x083d5efc — all 24 bytes are `push {r4,lr}; ldr r2,[r0]; ldr
/// r2,[r2,#0x40]; blx r2; ldr r0,[r0]; pop {r4,pc}`. It implements
/// `T *operator[](size_t index)`: dispatch through the container's vtable
/// slot 0x40 for an element-slot address, then load the element pointer
/// from that slot. The `push {r4,lr}` only aligns the stack; r4 is never
/// touched. The raw body has no NULL guard for either the virtual result
/// or its element slot.
///
/// Ghidra omits the r1 index parameter from its signature, but the `blx`
/// leaves r1 intact for the virtual method; the decoded callers pass loop
/// or event indexes and NULL-test the returned element. This distinct link
/// section deliberately keeps this independently hookable export from
/// being folded into a byte-identical body. There are no other deliberate
/// deviations from the ARM algorithm.
///
/// # Safety
/// Same contract as [`container_element_at`]: `this` must point at an
/// object whose first word is a vtable with at least
/// [`ELEMENT_SLOT_VTABLE_INDEX`] + 1 slots.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_element_at_alias_5f44")]
#[inline(never)]
pub unsafe extern "C" fn container_element_at_alias_5f44(this: *mut u8, index: usize) -> *mut u8 {
    let vtable = (this as *const *const ElementSlotFn).read();
    let element_slot = vtable.add(ELEMENT_SLOT_VTABLE_INDEX).read();
    element_slot(this, index).read()
}

/// container_element_at_alias_5f74 — original: `FUN_083d5f74` @ 0x083d5f74
/// (24 bytes; 6 plain `bl` call sites, no predicated calls).
///
/// Raw `osos.dec` fixes the full six-instruction extent through `pop
/// {r4,pc}` at 0x083d5f88; the next separately linked sibling begins at
/// 0x083d5f8c. This is a byte-identical [`container_element_at`]
/// instantiation: it calls the container vtable's +0x40 slot with `this` and
/// `index`, then loads and returns the resulting element-slot word.
///
/// Ghidra drops the live r1 index and mistakes the virtual method's slot
/// address for the result. Raw `blx r2` preserves r1 and the following
/// `ldr r0,[r0]` establishes the element-pointer result. No NULL guards exist
/// for either the virtual result or element slot.
///
/// # Deliberate deviations
///
/// This distinct text section prevents LLVM identical-function folding from
/// removing the independently hookable retailOS address. Otherwise none.
///
/// # Safety
///
/// Same contract as [`container_element_at`]: `this` must point at an object
/// whose first word is a vtable with at least [`ELEMENT_SLOT_VTABLE_INDEX`] +
/// 1 slots.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_element_at_alias_5f74")]
#[inline(never)]
pub unsafe extern "C" fn container_element_at_alias_5f74(this: *mut u8, index: usize) -> *mut u8 {
    let vtable = (this as *const *const ElementSlotFn).read();
    let element_slot = vtable.add(ELEMENT_SLOT_VTABLE_INDEX).read();
    element_slot(this, index).read()
}
/// container_element_at_veneer_9cef0 — original: `FUN_0829cef0` @ 0x0829cef0
/// (8 bytes; four plain `bl` call sites, no predicated calls).
///
/// Raw `osos.dec` establishes the complete two-word body: `add r0,r0,#0x24;
/// b 0x083d5f74`. The following `ldr r0,[r0,#0x7c]; bx lr` at 0x0829cef8 is
/// the next unrelated function. The branch target is the already ported
/// [`container_element_at_alias_5f74`], the `T *operator[](size_t)`
/// instantiation that dispatches through vtable +0x40 and loads the returned
/// element-slot word.
///
/// The four direct callers at 0x081177dc, 0x0828bb38, 0x0828bbec, and
/// 0x082a69d4 are unconditional plain `bl`; no predicated BL reaches the
/// veneer. It adjusts an owning object's address to its embedded container at
/// +0x24, preserving the original `index` and result. Deliberate deviation:
/// Rust expresses the ARM tail branch as a call; LLVM may lower it back to a
/// tail branch.
///
/// # Safety
///
/// `owner + 0x24` must satisfy [`container_element_at_alias_5f74`]'s contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_element_at_veneer_9cef0")]
#[inline(never)]
pub unsafe extern "C" fn container_element_at_veneer_9cef0(
    owner: *mut u8,
    index: usize,
) -> *mut u8 {
    container_element_at_alias_5f74(owner.add(0x24), index)
}





/// container_element_at_alias_6908 — original: `FUN_083d6908` @ 0x083d6908
/// (24 bytes; 5 `bl` call sites — 0x08123ff8, 0x08298b84, 0x08298cb4,
/// 0x083d02b4 and 0x083d02f8; `ipod-decomp/decomp/c/037/083d6908_FUN_083d6908.c`).
///
/// A third, byte-identical instantiation of [`container_element_at`] @
/// 0x083d5efc — all 24 bytes verified against osos.dec: `push {r4,lr};
/// ldr r2,[r0]; ldr r2,[r2,#0x40]; blx r2; ldr r0,[r0]; pop {r4,pc}`.
/// Same `T *operator[](size_t)`: dispatch through the container's own
/// vtable slot 0x40 for the element-slot address, then load the element
/// pointer out of it; the `push {r4, lr}` is again pure stack alignment
/// (r4 is never touched). Three of its callers (0x08123ff8, 0x08298b84,
/// 0x08298cb4) all reach a sub-container at `this+0x6c` (`add r0,r?,#0x6c`
/// immediately before the `bl`), and the two sites in `FUN_083d02ac`
/// loop `r4`/`r5` as the index and NULL-test each returned element
/// (`cmp r0,#0; beq`) before use — the same usage shape the primary's
/// call sites established. Ported as its own exported symbol (the
/// [`vector_size_elem4_alias_76c8`] precedent: identical body under a
/// distinct `link_section` so LLVM's identical-function folding keeps
/// both labels hookable), NOT folded into the primary the way the
/// ledger-only `not_equal_deref` aliases are.
///
/// # Safety
/// Same contract as [`container_element_at`]: `this` must point at an
/// object whose first word is a vtable with at least
/// [`ELEMENT_SLOT_VTABLE_INDEX`] + 1 slots.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_element_at_alias_6908")]
#[inline(never)]
pub unsafe extern "C" fn container_element_at_alias_6908(this: *mut u8, index: usize) -> *mut u8 {
    let vtable = (this as *const *const ElementSlotFn).read();
    let element_slot = vtable.add(ELEMENT_SLOT_VTABLE_INDEX).read();
    element_slot(this, index).read()
}
/// container_element_at_alias_6a68 — original: `FUN_083d6a68` @ 0x083d6a68
/// (24 bytes; 5 plain `bl` call sites — 0x0812f63c, 0x0812fc00,
/// 0x0812fdc0, 0x083d10e0, and 0x083d1124; no predicated calls or direct
/// tail branches).
///
/// A byte-identical instantiation of [`container_element_at`] @
/// 0x083d5efc — `push {r4,lr}; ldr r2,[r0]; ldr r2,[r2,#0x40]; blx r2;
/// ldr r0,[r0]; pop {r4,pc}`. It implements `T *operator[](size_t)`:
/// dispatch through the container's own vtable slot 0x40 for the
/// element-slot address, then load the element pointer from that slot. Raw
/// osos.dec establishes the complete body through `pop {r4,pc}` at
/// 0x083d6a7c; the next separately linked sibling begins at 0x083d6a80.
///
/// Ghidra drops the r1 index argument from its one-argument signature, but
/// raw `blx r2` preserves it for the virtual method. Decoding every ARM
/// B/BL-immediate word in osos.dec finds the five inbound calls above, all
/// unconditional plain `bl`. The ARM routine has no NULL guard for the
/// virtual result or the element slot. This distinct link section keeps this
/// independently hookable export separate from byte-identical siblings.
/// Deliberate deviations: none.
///
/// # Safety
///
/// Same contract as [`container_element_at`]: `this` must point at an object
/// whose first word is a vtable with at least [`ELEMENT_SLOT_VTABLE_INDEX`] +
/// 1 slots.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_element_at_alias_6a68")]
#[inline(never)]
pub unsafe extern "C" fn container_element_at_alias_6a68(this: *mut u8, index: usize) -> *mut u8 {
    let vtable = (this as *const *const ElementSlotFn).read();
    let element_slot = vtable.add(ELEMENT_SLOT_VTABLE_INDEX).read();
    element_slot(this, index).read()
}

/// container_element_at_alias_6b14 — original: `FUN_083d6b14` @ 0x083d6b14
/// (24 bytes; 5 plain `bl` call sites — 0x08235c54, 0x08235cb0,
/// 0x08235e48, 0x083d1604, and 0x083d1648; no predicated calls).
///
/// A byte-identical instantiation of [`container_element_at`] @
/// 0x083d5efc: `T *operator[](size_t index)`. It reads the container's
/// vtable, calls slot 0x40 to find the indexed element slot, and loads the
/// element pointer from that slot. Raw osos.dec establishes the complete
/// body through `pop {r4,pc}` at 0x083d6b28; the next sibling starts at
/// 0x083d6b2c.
///
/// Ghidra omits r1 from its signature, but the indirect `blx r2` retains the
/// index for the virtual method. The ARM routine has no NULL guard for the
/// virtual result or the element slot. A distinct link section keeps this
/// independently hookable alias separate from identical siblings. Deliberate
/// deviations: none.
///
/// # Safety
/// Same contract as [`container_element_at`]: `this` must point at an object
/// whose first word is a vtable with at least [`ELEMENT_SLOT_VTABLE_INDEX`] +
/// 1 slots.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_element_at_alias_6b14")]
#[inline(never)]
pub unsafe extern "C" fn container_element_at_alias_6b14(this: *mut u8, index: usize) -> *mut u8 {
    let vtable = (this as *const *const ElementSlotFn).read();
    let element_slot = vtable.add(ELEMENT_SLOT_VTABLE_INDEX).read();
    element_slot(this, index).read()
}
/// container_element_at_alias_6b40 — original: `FUN_083d6b40` @
/// 0x083d6b40 (24 bytes; 4 direct call sites, all unconditional plain `bl`;
/// no predicated forms).
///
/// Raw `osos.dec` fixes the complete six-instruction body through `pop
/// {r4,pc}` at 0x083d6b54; the independently linked next sibling begins at
/// 0x083d6b58. This is a byte-identical [`container_element_at`]
/// instantiation: it dispatches the container's vtable slot 0x40 with `this`
/// and `index`, then loads and returns the resulting element-slot word.
///
/// Ghidra omits the live r1 index argument and misidentifies the return as
/// the virtual method's return value. The raw `blx r2` preserves r1, and
/// `ldr r0,[r0]` after the call establishes the actual result. The routine
/// has no NULL guard for either virtual result or element slot. Its distinct
/// link section prevents LLVM from folding this independently hookable copy
/// into an identical sibling; otherwise there are no deliberate deviations.
///
/// # Safety
///
/// Same contract as [`container_element_at`]: `this` must point at an object
/// whose first word is a vtable with at least [`ELEMENT_SLOT_VTABLE_INDEX`] +
/// 1 slots.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_element_at_alias_6b40")]
#[inline(never)]
pub unsafe extern "C" fn container_element_at_alias_6b40(
    this: *mut u8,
    index: usize,
) -> *mut u8 {
    let vtable = (this as *const *const ElementSlotFn).read();
    let element_slot = vtable.add(ELEMENT_SLOT_VTABLE_INDEX).read();
    element_slot(this, index).read()
}


/// container_element_at_alias_6b6c — original: `FUN_083d6b6c` @ 0x083d6b6c
/// (24 bytes; 5 plain `bl` call sites — 0x0815bba0, 0x0815bbec,
/// 0x0815bc44, 0x083d17b4, and 0x083d17f8; no predicated calls).
///
/// A byte-identical instantiation of [`container_element_at`] @
/// 0x083d5efc: `T *operator[](size_t index)`. It reads the vtable from the
/// container, dispatches its slot 0x40 method for the element-slot address,
/// then loads the element pointer from that slot. The raw extent ends with
/// `pop {r4,pc}` at 0x083d6b80; the next sibling begins at 0x083d6b84.
///
/// Ghidra omits r1 from its signature, but the indirect `blx r2` preserves
/// the index for the virtual method. The raw body has no NULL guard for the
/// virtual result or the element slot. Its own link section retains this
/// separately hookable export despite the byte-identical body; no other
/// deliberate deviations from the ARM algorithm.
///
/// # Safety
/// Same contract as [`container_element_at`]: `this` must point at an object
/// whose first word is a vtable with at least [`ELEMENT_SLOT_VTABLE_INDEX`] +
/// 1 slots.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_element_at_alias_6b6c")]
#[inline(never)]
pub unsafe extern "C" fn container_element_at_alias_6b6c(this: *mut u8, index: usize) -> *mut u8 {
    let vtable = (this as *const *const ElementSlotFn).read();
    let element_slot = vtable.add(ELEMENT_SLOT_VTABLE_INDEX).read();
    element_slot(this, index).read()
}

/// container_element_at_alias_6bc0 — original: `FUN_083d6bc0` @ 0x083d6bc0
/// (24 bytes; 9 plain `bl` call sites — 0x08214878, 0x08214930,
/// 0x08214a0c, 0x08214e20, 0x08214e38, 0x08214e48, 0x08214e5c,
/// 0x083d1a68, and 0x083d1aa0; no predicated calls).
///
/// A byte-identical instantiation of [`container_element_at`] @
/// 0x083d5efc: `T *operator[](size_t index)`. It dispatches through the
/// container's own vtable slot 0x40 for an element-slot address, then loads
/// the element pointer from that slot. The ARM `push {r4,lr}` only aligns
/// the stack: r4 is never touched. The raw body has no NULL guard for the
/// virtual result or its element slot.
///
/// Ghidra drops the r1 index argument from its one-argument signature; the
/// `blx r2` preserves it for the virtual method. This distinct link section
/// keeps the independently hookable alias from being folded into its
/// byte-identical siblings; otherwise there are no deliberate deviations.
///
/// # Safety
/// Same contract as [`container_element_at`]: `this` must point at an object
/// whose first word is a vtable with at least [`ELEMENT_SLOT_VTABLE_INDEX`] +
/// 1 slots.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_element_at_alias_6bc0")]
#[inline(never)]
pub unsafe extern "C" fn container_element_at_alias_6bc0(this: *mut u8, index: usize) -> *mut u8 {
    let vtable = (this as *const *const ElementSlotFn).read();
    let element_slot = vtable.add(ELEMENT_SLOT_VTABLE_INDEX).read();
    element_slot(this, index).read()
}
/// container_element_at_alias_6bec — original: `FUN_083d6bec` @ 0x083d6bec
/// (24 bytes; 6 plain `bl` call sites — 0x0820152c, 0x082016a0,
/// 0x08201ad4, 0x0829ef7c, 0x083d1b34, and 0x083d1b78; no predicated
/// calls).
///
/// A byte-identical instantiation of [`container_element_at`] @
/// 0x083d5efc: `T *operator[](size_t index)`. It dispatches through the
/// container's own vtable slot 0x40 for an element-slot address, then loads
/// that slot's element pointer. Raw osos.dec ends with `pop {r4,pc}` at
/// 0x083d6c00; the next separately linked helper starts at 0x083d6c04.
///
/// Ghidra drops the r1 index argument from its signature, but the `blx r2`
/// preserves it for the virtual method. The raw body guards neither the
/// virtual result nor its element slot. This distinct link section keeps the
/// independently hookable export from folding into its byte-identical
/// siblings; otherwise there are no deliberate deviations.
///
/// # Safety
/// Same contract as [`container_element_at`]: `this` must point at an object
/// whose first word is a vtable with at least [`ELEMENT_SLOT_VTABLE_INDEX`] +
/// 1 slots.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_element_at_alias_6bec")]
#[inline(never)]
pub unsafe extern "C" fn container_element_at_alias_6bec(this: *mut u8, index: usize) -> *mut u8 {
    let vtable = (this as *const *const ElementSlotFn).read();
    let element_slot = vtable.add(ELEMENT_SLOT_VTABLE_INDEX).read();
    element_slot(this, index).read()
}
/// container_element_at_alias_6c6c — original: `FUN_083d6c6c` @ 0x083d6c6c
/// (24 bytes; 4 direct call sites: 0x081b9318, 0x081b93a4, 0x083d1f68, and
/// 0x083d1fa0; all are unconditional plain `bl`, with no predicated forms).
///
/// Raw `osos.dec` fixes the complete six-instruction body through `pop
/// {r4,pc}` at 0x083d6c80; the next separately linked helper begins at
/// 0x083d6c84. It is a byte-identical [`container_element_at`] instantiation:
/// dispatch vtable slot 0x40 with `this` and `index` to obtain an element-slot
/// address, then load and return that slot's element pointer.
///
/// Ghidra omits the r1 index argument, but the raw `blx r2` preserves it for
/// the virtual call. The ARM routine does not guard either the virtual result
/// or element slot. This distinct link section prevents LLVM from folding this
/// independently hookable address into an identical sibling. Deliberate
/// deviations: none.
///
/// # Safety
/// Same contract as [`container_element_at`]: `this` must point at an object
/// whose first word is a vtable with at least [`ELEMENT_SLOT_VTABLE_INDEX`] +
/// 1 slots.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_element_at_alias_6c6c")]
#[inline(never)]
pub unsafe extern "C" fn container_element_at_alias_6c6c(this: *mut u8, index: usize) -> *mut u8 {
    let vtable = (this as *const *const ElementSlotFn).read();
    let element_slot = vtable.add(ELEMENT_SLOT_VTABLE_INDEX).read();
    element_slot(this, index).read()
}




/// container_element_at_alias_68dc — original: `FUN_083d68dc` @ 0x083d68dc
/// (24 bytes; 2 `bl` call sites — 0x082848a0 in `FUN_08284878`,
/// 0x083d0214 in `FUN_083d01f4` — plus one `b` tail-call at 0x082a6770;
/// `ipod-decomp/decomp/c/037/083d68dc_FUN_083d68dc.c`).
///
/// A second, byte-identical instantiation of [`container_element_at`] @
/// 0x083d5efc — all 24 bytes: `push {r4,lr}; ldr r2,[r0]; ldr
/// r2,[r2,#0x40]; blx r2; ldr r0,[r0]; pop {r4,pc}`. Same
/// `T *operator[](size_t)`: dispatch through the container's own vtable
/// slot 0x40 for the element-slot address, then load the element pointer
/// out of it; the `push {r4, lr}` is again pure stack alignment (r4 is
/// never touched). Its callers all reach a sub-container at `this+0x34`:
/// `FUN_08284878` loops `r4` as the index over `this+0x34` and feeds each
/// element on, the `b` site tail-wraps `this+0x34` as a plain accessor,
/// and `FUN_083d01f4` NULL-tests the result before an indirect call
/// through the element's own vtable — the same usage shape the primary's
/// call sites established. Ported as its own exported symbol (the
/// [`vector_size_elem4_alias_76c8`] precedent: identical body under a
/// distinct `link_section` so LLVM's identical-function folding keeps
/// both labels hookable), NOT folded into the primary the way the
/// ledger-only `not_equal_deref` aliases are.
///
/// # Safety
/// Same contract as [`container_element_at`]: `this` must point at an
/// object whose first word is a vtable with at least
/// [`ELEMENT_SLOT_VTABLE_INDEX`] + 1 slots.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_element_at_alias_68dc")]
#[inline(never)]
pub unsafe extern "C" fn container_element_at_alias_68dc(this: *mut u8, index: usize) -> *mut u8 {
    let vtable = (this as *const *const ElementSlotFn).read();
    let element_slot = vtable.add(ELEMENT_SLOT_VTABLE_INDEX).read();
    element_slot(this, index).read()
}

/// container_element_at_alias_6870 — original: `FUN_083d6870` @ 0x083d6870
/// (24 bytes; 6 plain `bl` call sites — 0x0828527c, 0x08285320,
/// 0x082853f8, 0x082854fc, 0x083cff18, and 0x083cff50; no predicated
/// calls; plus one plain `b` tail-call at 0x082854e4).
///
/// A byte-identical instantiation of [`container_element_at`] @
/// 0x083d5efc — `push {r4,lr}; ldr r2,[r0]; ldr r2,[r2,#0x40]; blx r2;
/// ldr r0,[r0]; pop {r4,pc}`. It implements `T *operator[](size_t)`:
/// dispatch through this container's vtable slot 0x40 to obtain an
/// element-slot address, then load the element pointer from that slot.
/// Ghidra omits r1, but the indirect call preserves the index. The raw
/// body guards neither the virtual result nor its element slot. This
/// independently hookable copy has a dedicated link section to prevent
/// identical-function folding; otherwise there are no deliberate deviations.
///
/// # Safety
/// Same contract as [`container_element_at`]: `this` must point at an object
/// whose first word is a vtable with at least [`ELEMENT_SLOT_VTABLE_INDEX`] +
/// 1 slots.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_element_at_alias_6870")]
#[inline(never)]
pub unsafe extern "C" fn container_element_at_alias_6870(this: *mut u8, index: usize) -> *mut u8 {
    let vtable = (this as *const *const ElementSlotFn).read();
    let element_slot = vtable.add(ELEMENT_SLOT_VTABLE_INDEX).read();
    element_slot(this, index).read()
}


/// container_element_at_alias_689c — original: `FUN_083d689c` @ 0x083d689c
/// (24 bytes; 6 plain `bl` call sites — 0x08123f60, 0x08298cf4,
/// 0x08298d44, 0x08298da4, 0x083cffe4, and 0x083d0028; no predicated
/// calls).
///
/// A byte-identical instantiation of [`container_element_at`] @
/// 0x083d5efc — `push {r4,lr}; ldr r2,[r0]; ldr r2,[r2,#0x40]; blx r2;
/// ldr r0,[r0]; pop {r4,pc}`. It implements `T *operator[](size_t)`:
/// dispatch through this container's vtable slot 0x40 to obtain an
/// element-slot address, then load the element pointer from that slot.
/// Ghidra omits r1, but the indirect call preserves the index. The raw
/// body guards neither the virtual result nor its element slot. This
/// independently hookable copy has a dedicated link section to prevent
/// identical-function folding; otherwise there are no deliberate deviations.
///
/// # Safety
/// Same contract as [`container_element_at`]: `this` must point at an object
/// whose first word is a vtable with at least [`ELEMENT_SLOT_VTABLE_INDEX`] +
/// 1 slots.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_element_at_alias_689c")]
#[inline(never)]
pub unsafe extern "C" fn container_element_at_alias_689c(this: *mut u8, index: usize) -> *mut u8 {
    let vtable = (this as *const *const ElementSlotFn).read();
    let element_slot = vtable.add(ELEMENT_SLOT_VTABLE_INDEX).read();
    element_slot(this, index).read()
}

/// The `{begin, end}` head of a vector — the two words the
/// `vector_size_elem*` family loads with one `ldm r0, {r0, r1}`.
/// Addressed by field, so `end` lands one word after `begin` on both
/// the 32-bit target and a 64-bit host.
#[repr(C)]
pub struct VectorBounds {
    /// First element.
    pub begin: *mut u8,
    /// One past the last element.
    pub end: *mut u8,
}
/// An owner whose embedded `vector<T>` begins after three target words.
/// `#[repr(C)]` makes the vector start at +0x0c on ARM while preserving
/// pointer-field separation on 64-bit host tests.
#[repr(C)]
pub struct EmbeddedVectorSizeElem8 {
    _prefix: [u32; 3],
    pub vector: VectorBounds,
}

/// vector_is_empty — original: `FUN_083d7810` @ 0x083d7810
/// (24 bytes; `ipod-decomp/decomp/c/037/083d7810_FUN_083d7810.c`).
///
/// `std::vector<T>::empty()`: loads the vector head's `begin` and `end`
/// pointers and returns whether they compare equal. The raw ARM body is
/// `ldr r1,[r0]; ldr r0,[r0,#4]; cmp r1,r0; movne r0,#0; moveq r0,#1;
/// bx lr`, establishing both the `r0` vector argument and its 0/1
/// word-sized bool result ABI.
///
/// # Safety
/// `vector` must point at a readable, target-word-aligned
/// [`VectorBounds`]. The pointed-to elements are never accessed, so
/// either bound may be NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_is_empty(vector: *const VectorBounds) -> u32 {
    if (*vector).begin == (*vector).end { 1 } else { 0 }
}


/// `(end - begin) >> shift`, the shared body of the `vector_size_elem*`
/// family. The shift is **arithmetic**: the original's `asr` keeps a
/// reversed vector's negative span negative instead of turning it into
/// a huge unsigned count.
#[inline(always)]
unsafe fn vector_size(vector: *const VectorBounds, shift: u32) -> i32 {
    // `read_unaligned`: on target the two words are a plain `ldm`; on a
    // 64-bit host a firmware vector head can sit at a 4-aligned address
    // that is not 8-aligned (e.g. +0x14 of an owner object).
    let begin = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).begin));
    let end = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).end));
    let span = end as isize - begin as isize;
    (span >> shift) as i32
}

/// vector_size_elem4_alias_76c8 — original: `FUN_083d76c8` @ 0x083d76c8
/// (16 bytes; `ipod-decomp/decomp/c/037/083d76c8_FUN_083d76c8.c`).
///
/// A byte-identical `std::vector<T>::size()` instantiation for a 4-byte
/// element: loads the `{begin, end}` head, subtracts `begin` from `end`,
/// then applies the original ARM `asr #2`. Its 4 direct call sites use this
/// same vector head. Reusing [`vector_size`] preserves that signed
/// arithmetic-shift result for reversed spans.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_size_elem4_alias_76c8")]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem4_alias_76c8(vector: *const VectorBounds) -> i32 {
    vector_size(vector, 2)
}

/// vector_size_elem4 — original: `FUN_083d76d8` @ 0x083d76d8
/// (16 bytes; 20 `bl` call sites there, 140 across all 17
/// byte-identical copies — see `names.yaml` for the list).
///
/// `vector<T>::size()` for a 4-byte element: `(end - begin) >> 2`.
///
/// The size family has one member per element size. The four powers of
/// two are ported here, as are the 12-, 20-, 24-, 28- and 40-byte
/// divide members ([`vector_size_elem12`], [`vector_size_elem20`],
/// [`vector_size_elem24`], [`vector_size_elem28`],
/// [`vector_size_elem40`]), each tail-branching into the ADS signed
/// divide @ 0x08031568.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem4(vector: *const VectorBounds) -> i32 {
    vector_size(vector, 2)
}

/// vector_size_elem4_alias_76e8 — original: `FUN_083d76e8` @ 0x083d76e8
/// (16 bytes; `ipod-decomp/decomp/c/037/083d76e8_FUN_083d76e8.c`).
///
/// A byte-identical `std::vector<T>::size()` instantiation for a 4-byte
/// element: loads the `{begin, end}` head, subtracts `begin` from `end`,
/// then applies the original ARM `asr #2`. Its 9 direct call sites use this
/// same vector head. Reusing [`vector_size`] preserves that signed
/// arithmetic-shift result for reversed spans.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_size_elem4_alias_76e8")]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem4_alias_76e8(vector: *const VectorBounds) -> i32 {
    vector_size(vector, 2)
}

/// vector_size_elem4_alias_77cc — original: `FUN_083d77cc` @ 0x083d77cc
/// (16 bytes; `ipod-decomp/decomp/c/037/083d77cc_FUN_083d77cc.c`).
///
/// A byte-identical `std::vector<T>::size()` instantiation for a 4-byte
/// element: loads the `{begin, end}` head, subtracts `begin` from `end`,
/// then applies the original ARM `asr #2`. Reusing [`vector_size`] preserves
/// that signed arithmetic-shift result for reversed spans.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_size_elem4_alias_77cc")]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem4_alias_77cc(vector: *const VectorBounds) -> i32 {
    vector_size(vector, 2)
}

/// vector_size_elem4_alias_78c4 — original: `FUN_083d78c4` @ 0x083d78c4
/// (16 bytes; `ipod-decomp/decomp/c/037/083d78c4_FUN_083d78c4.c`).
///
/// A byte-identical `std::vector<T>::size()` instantiation for a 4-byte
/// element: loads the `{begin, end}` head, subtracts `begin` from `end`,
/// then applies the original ARM `asr #2`. Its 11 direct call sites use this
/// same vector head. Reusing [`vector_size`] preserves that signed
/// arithmetic-shift result for reversed spans.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_size_elem4_alias_78c4")]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem4_alias_78c4(vector: *const VectorBounds) -> i32 {
    vector_size(vector, 2)
}

/// vector_size_elem4_alias_78d4 — original: `FUN_083d78d4` @ 0x083d78d4
/// (16 bytes; `ipod-decomp/decomp/c/037/083d78d4_FUN_083d78d4.c`).
///
/// A byte-identical `std::vector<T>::size()` instantiation for a 4-byte
/// element: loads the `{begin, end}` head, subtracts `begin` from `end`,
/// then applies the original ARM `asr #2`. Reusing [`vector_size`] preserves
/// that signed arithmetic-shift result for reversed spans.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_size_elem4_alias_78d4")]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem4_alias_78d4(vector: *const VectorBounds) -> i32 {
    vector_size(vector, 2)
}

/// vector_size_elem4_alias_78e4 — original: `FUN_083d78e4` @ 0x083d78e4
/// (16 bytes; `ipod-decomp/decomp/c/037/083d78e4_FUN_083d78e4.c`).
///
/// A byte-identical `std::vector<T>::size()` instantiation for a 4-byte
/// element: loads the `{begin, end}` head, subtracts `begin` from `end`,
/// then applies the original ARM `asr #2`. Its 6 direct call sites use this
/// same vector head. Reusing [`vector_size`] preserves that signed
/// arithmetic-shift result for reversed spans.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_size_elem4_alias_78e4")]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem4_alias_78e4(vector: *const VectorBounds) -> i32 {
    vector_size(vector, 2)
}

/// vector_size_elem4_alias_78f4 — original: `FUN_083d78f4` @ 0x083d78f4
/// (16 bytes; `ipod-decomp/decomp/c/037/083d78f4_FUN_083d78f4.c`).
///
/// A byte-identical `std::vector<T>::size()` instantiation for a 4-byte
/// element: loads the `{begin, end}` head, subtracts `begin` from `end`,
/// then applies the original ARM `asr #2`. Its 5 direct call sites use this
/// same vector head. Reusing [`vector_size`] preserves that signed
/// arithmetic-shift result for reversed spans.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_size_elem4_alias_78f4")]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem4_alias_78f4(vector: *const VectorBounds) -> i32 {
    vector_size(vector, 2)
}

/// vector_size_elem4_alias_7904 — original: `FUN_083d7904` @ 0x083d7904
/// (16 bytes; `ipod-decomp/decomp/c/037/083d7904_FUN_083d7904.c`).
///
/// A byte-identical `std::vector<T>::size()` instantiation for a 4-byte
/// element: loads the `{begin, end}` head, subtracts `begin` from `end`,
/// then applies the original ARM `asr #2`. Its 7 direct call sites use this
/// same vector head. Reusing [`vector_size`] preserves that signed
/// arithmetic-shift result for reversed spans.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_size_elem4_alias_7904")]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem4_alias_7904(vector: *const VectorBounds) -> i32 {
    vector_size(vector, 2)
}

/// vector_size_elem4_alias_7914 — original: `FUN_083d7914` @ 0x083d7914
/// (16 bytes; `ipod-decomp/decomp/c/037/083d7914_FUN_083d7914.c`).
///
/// A byte-identical `std::vector<T>::size()` instantiation for a 4-byte
/// element: loads the `{begin, end}` head, subtracts `begin` from `end`,
/// then applies the original ARM `asr #2`. Reusing [`vector_size`] preserves
/// that signed arithmetic-shift result for reversed spans.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_size_elem4_alias_7914")]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem4_alias_7914(vector: *const VectorBounds) -> i32 {
    vector_size(vector, 2)
}

/// vector_size_elem4_alias_7924 — original: `FUN_083d7924` @ 0x083d7924
/// (16 bytes; `ipod-decomp/decomp/c/037/083d7924_FUN_083d7924.c`).
///
/// A byte-identical `std::vector<T>::size()` instantiation for a 4-byte
/// element: loads the `{begin, end}` head, subtracts `begin` from `end`,
/// then applies the original ARM `asr #2`. Reusing [`vector_size`] preserves
/// that signed arithmetic-shift result for reversed spans.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_size_elem4_alias_7924")]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem4_alias_7924(vector: *const VectorBounds) -> i32 {
    vector_size(vector, 2)
}

/// vector_size_elem4_alias_7934 — original: `FUN_083d7934` @ 0x083d7934
/// (16 bytes; `ipod-decomp/decomp/c/037/083d7934_FUN_083d7934.c`).
///
/// A byte-identical `std::vector<T>::size()` instantiation for a 4-byte
/// element: loads the `{begin, end}` head, subtracts `begin` from `end`,
/// then applies the original ARM `asr #2`. Its 4 direct call sites use this
/// same vector head. Reusing [`vector_size`] preserves that signed
/// arithmetic-shift result for reversed spans.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_size_elem4_alias_7934")]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem4_alias_7934(vector: *const VectorBounds) -> i32 {
    vector_size(vector, 2)
}

/// vector_size_elem4_alias_7944 — original: `FUN_083d7944` @ 0x083d7944
/// (16 bytes; `ipod-decomp/decomp/c/037/083d7944_FUN_083d7944.c`).
///
/// A byte-identical `std::vector<T>::size()` instantiation for a 4-byte
/// element: loads the `{begin, end}` head, subtracts `begin` from `end`,
/// then applies the original ARM `asr #2`. Reusing [`vector_size`] preserves
/// that signed arithmetic-shift result for reversed spans.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_size_elem4_alias_7944")]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem4_alias_7944(vector: *const VectorBounds) -> i32 {
    vector_size(vector, 2)
}

/// vector_size_elem4_alias_7a38 — original: `FUN_083d7a38` @ 0x083d7a38
/// (16 bytes; `ipod-decomp/decomp/c/037/083d7a38_FUN_083d7a38.c`).
///
/// A byte-identical `std::vector<T>::size()` instantiation for a 4-byte
/// element: loads the `{begin, end}` head, subtracts `begin` from `end`,
/// then applies the original ARM `asr #2`. Its 4 direct call sites use this
/// same vector head. Reusing [`vector_size`] preserves that signed
/// arithmetic-shift result for reversed spans.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_size_elem4_alias_7a38")]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem4_alias_7a38(vector: *const VectorBounds) -> i32 {
    vector_size(vector, 2)
}

/// vector_size_elem4_alias_7a48 — original: `FUN_083d7a48` @ 0x083d7a48
/// (16 bytes; `ipod-decomp/decomp/c/037/083d7a48_FUN_083d7a48.c`).
///
/// A byte-identical `std::vector<T>::size()` instantiation for a 4-byte
/// element: loads the `{begin, end}` head, subtracts `begin` from `end`,
/// then applies the original ARM `asr #2`. Reusing [`vector_size`] preserves
/// that signed arithmetic-shift result for reversed spans.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_size_elem4_alias_7a48")]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem4_alias_7a48(vector: *const VectorBounds) -> i32 {
    vector_size(vector, 2)
}

/// vector_size_elem4_alias_7a58 — original: `FUN_083d7a58` @ 0x083d7a58
/// (16 bytes; `ipod-decomp/decomp/c/037/083d7a58_FUN_083d7a58.c`).
///
/// A byte-identical `std::vector<T>::size()` instantiation for a 4-byte
/// element: loads the `{begin, end}` head, subtracts `begin` from `end`,
/// then applies the original ARM `asr #2`. Its 4 direct call sites use this
/// same vector head. Reusing [`vector_size`] preserves that signed
/// arithmetic-shift result for reversed spans.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_size_elem4_alias_7a58")]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem4_alias_7a58(vector: *const VectorBounds) -> i32 {
    vector_size(vector, 2)
}

/// vector_size_elem4_alias_7a68 — original: `FUN_083d7a68` @ 0x083d7a68
/// (16 bytes; `ipod-decomp/decomp/c/037/083d7a68_FUN_083d7a68.c`).
///
/// A byte-identical `std::vector<T>::size()` instantiation for a 4-byte
/// element: loads the `{begin, end}` head, subtracts `begin` from `end`,
/// then applies the original ARM `asr #2`. Reusing [`vector_size`] preserves
/// that signed arithmetic-shift result for reversed spans.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_size_elem4_alias_7a68")]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem4_alias_7a68(vector: *const VectorBounds) -> i32 {
    vector_size(vector, 2)
}

/// vector_size_elem2 — original: `FUN_083d7a78` @ 0x083d7a78
/// (16 bytes, 16 `bl` call sites; the only copy of this shift).
/// [`vector_size_elem4`] with `>> 1`.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem2(vector: *const VectorBounds) -> i32 {
    vector_size(vector, 1)
}

/// vector_size_elem2_clamped — original: `FUN_0829db9c` @ 0x0829db9c
/// (24 bytes; 23 `bl` call sites, binary-scanned from osos.dec — all
/// plain, zero predicated; the only copy of this guarded body in the
/// image, byte-pattern verified).
///
/// The unsigned-clamped `std::vector<u16>::size()` out-of-line body:
/// `ldm r0,{r0,r1}; cmp r1,r0; subhi r0,r1,r0; asrhi r0,r0,#1;
/// movls r0,#0; bx lr`. Unlike the [`vector_size_elem2`] family's bare
/// `sub`/`asr`, the compare is UNSIGNED and both the subtract and the
/// shift are predicated on it: an empty or inverted head
/// (`end <= begin`) yields 0, never a negative count. The guard makes
/// the span positive, so the original's `asr #1` and an `lsr #1`
/// agree; the port keeps the arithmetic shift anyway.
///
/// Caller shape: the wide-string verb matcher [`wstr_case_eq`]
/// (`util/wstr_casecmp`) takes its element count through this body,
/// and the `FUN_081ba9ac` family parses signed `HH:MM:SS`-style fields
/// out of `vector<u16>` heads, testing this result for nonzero before
/// dividing each field.
///
/// [`wstr_case_eq`]: crate::util::wstr_casecmp::wstr_case_eq
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem2_clamped(vector: *const VectorBounds) -> i32 {
    // `read_unaligned`: on target the two words are one `ldm`; on a
    // 64-bit host a firmware vector head can sit at a 4-aligned address
    // that is not 8-aligned (the vector_size precedent).
    let begin = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).begin)) as usize;
    let end = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).end)) as usize;
    if end > begin {
        ((end - begin) as isize >> 1) as i32
    } else {
        0
    }
}


/// vector_size_elem8 — original: `FUN_083d7860` @ 0x083d7860
/// (16 bytes; 14 `bl` call sites there, 50 across 4 byte-identical
/// copies). [`vector_size_elem4`] with `>> 3`.
///
/// The copy at 0x083d7664 (`FUN_083d7664`, 9 `bl` call sites;
/// `ipod-decomp/decomp/c/037/083d7664_FUN_083d7664.c`) is byte-identical
/// — verified against osos.asm and Ghidra's `return param_1[1] - *param_1
/// >> 3` — so it is served by this port: any hook at that address points
/// here (the `vector_size_elem16` copy-at-0x083d78b4 ledger precedent).
/// The copy at 0x083d76a4 (13 `bl` call sites plus one `b` tail-branch
/// at 0x0829c02c; `ipod-decomp/decomp/c/037/083d76a4_FUN_083d76a4.c`) is
/// likewise byte-identical — verified against osos.asm per address — and
/// hooks this same symbol. The copy at 0x083d7a88 (12 `bl` call sites
/// plus one `bne` tail-branch at 0x08269c50;
/// `ipod-decomp/decomp/c/037/083d7a88_FUN_083d7a88.c`) is likewise
/// byte-identical — verified against osos.asm per address — and hooks
/// this same symbol.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem8(vector: *const VectorBounds) -> i32 {
    vector_size(vector, 3)
}
/// embedded_vector_size_elem8 — original: `FUN_0829c028` @ 0x0829c028
/// (8 bytes; 6 direct, unconditional `bl` call sites: 0x08131ea4,
/// 0x08131ebc, 0x08132084, 0x08132094, 0x081320e0, and 0x081321b8).
///
/// Advances past the owner's three-word prefix, then tail-branches to the
/// existing byte-identical `vector_size_elem8` body at 0x083d76a4. Thus it
/// returns `(vector.end - vector.begin) >> 3`, using ARM's arithmetic shift.
/// Raw aligned ARM B/BL decoding found no predicated inbound calls.
///
/// Deliberate deviation: LLVM adds a frame prologue and epilogue around its
/// tail transfer; the vector selection and return value are unchanged.
///
/// # Safety
/// `owner.vector` must contain readable `{begin, end}` bounds.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.embedded_vector_size_elem8_0829c028")]
#[inline(never)]
pub unsafe extern "C" fn embedded_vector_size_elem8(
    owner: *const EmbeddedVectorSizeElem8,
) -> i32 {
    vector_size_elem8(core::ptr::addr_of!((*owner).vector))
}


/// vector_size_elem16 — original: `FUN_083d7884` @ 0x083d7884
/// (16 bytes; 19 `bl` call sites there, 78 across 6 byte-identical
/// copies). [`vector_size_elem4`] with `>> 4`.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem16(vector: *const VectorBounds) -> i32 {
    vector_size(vector, 4)
}

/// vector_size_elem32 — original: `FUN_083d78a4` @ 0x083d78a4
/// (16 bytes, 8 `bl` call sites; the only copy).
/// [`vector_size_elem4`] with `>> 5`.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem32(vector: *const VectorBounds) -> i32 {
    vector_size(vector, 5)
}

/// vector_size_elem12 — original: `FUN_083d76f8` @ 0x083d76f8
/// (16 bytes; 18 `bl` call sites there — the hottest instantiation of
/// the whole `vector_size` divide half — 62 across all 5 byte-identical
/// copies; the byte-identical copies `FUN_083d772c` @ 0x083d772c,
/// `FUN_083d7774` @ 0x083d7774 and `FUN_083d77bc` @ 0x083d77bc are
/// ported as ledger-only aliases of this symbol, the last copy
/// (`FUN_083d7800` @ 0x083d7800) stays identified in `names.yaml`).
///
/// `vector<T>::size()` for a 12-byte element, a non-power-of-two member
/// of the `vector_size_elem*` family: the same `ldm r0,{r0,r1}; sub
/// r0,r1,r0` head as the shifts, then `mov r1,#0xc` and a **tail
/// branch** into the ADS signed divide @ 0x08031568 (ported as
/// [`__rt_sdiv`]). The divide is signed and truncating, so a reversed
/// vector's negative span truncates toward zero like any C `/`, and a
/// partial element is dropped.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem12(vector: *const VectorBounds) -> i32 {
    // `read_unaligned`: same 4-but-not-8-aligned firmware head hazard
    // as `vector_size` on a 64-bit host.
    let begin = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).begin));
    let end = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).end));
    let span = (end as isize - begin as isize) as i32;
    __rt_sdiv(span, 12)
}

/// vector_size_elem24 — original: `FUN_083d7750` @ 0x083d7750
/// (16 bytes; 31 `bl` call sites there, 45 across the 2 byte-identical
/// copies — the second instantiation, `FUN_083d77dc` @ 0x083d77dc with
/// 14 `bl` sites, is byte-identical and hooks this same symbol).
///
/// `vector<T>::size()` for a 24-byte element, the non-power-of-two
/// member of the `vector_size_elem*` family: the same `ldm r0,{r0,r1};
/// sub r0,r1,r0` head as the shifts, then `mov r1,#0x18` and a
/// **tail branch** into the ADS signed divide @ 0x08031568 (ported as
/// [`__rt_sdiv`]). The divide is signed and truncating, so a reversed
/// vector's negative span truncates toward zero like any C `/`, and a
/// partial element is dropped.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem24(vector: *const VectorBounds) -> i32 {
    // `read_unaligned`: same 4-but-not-8-aligned firmware head hazard
    // as `vector_size` on a 64-bit host.
    let begin = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).begin));
    let end = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).end));
    let span = (end as isize - begin as isize) as i32;
    __rt_sdiv(span, 24)
}

/// vector_size_elem20 — original: `FUN_083d7640` @ 0x083d7640
/// (16 bytes; 14 `bl` call sites there, 21 across the 2 byte-identical
/// copies — the second instantiation, `FUN_083d771c` @ 0x083d771c with
/// 7 `bl` sites, is byte-identical and can hook this same symbol).
///
/// `vector<T>::size()` for a 20-byte element, a non-power-of-two member
/// of the `vector_size_elem*` family: the same `ldm r0,{r0,r1}; sub
/// r0,r1,r0` head as the shifts, then `mov r1,#0x14` and a **tail
/// branch** into the ADS signed divide @ 0x08031568 (ported as
/// [`__rt_sdiv`]). The divide is signed and truncating, so a reversed
/// vector's negative span truncates toward zero like any C `/`, and a
/// partial element is dropped.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem20(vector: *const VectorBounds) -> i32 {
    // `read_unaligned`: same 4-but-not-8-aligned firmware head hazard
    // as `vector_size` on a 64-bit host.
    let begin = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).begin));
    let end = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).end));
    let span = (end as isize - begin as isize) as i32;
    __rt_sdiv(span, 20)
}

/// vector_size_elem28 — original: `FUN_083d7894` @ 0x083d7894
/// (16 bytes, 8 `bl` call sites; the only copy).
///
/// `vector<T>::size()` for a 28-byte element, a non-power-of-two member
/// of the `vector_size_elem*` family: the same `ldm r0,{r0,r1}; sub
/// r0,r1,r0` head as the shifts, then `mov r1,#0x1c` and a **tail
/// branch** into the ADS signed divide @ 0x08031568 (ported as
/// [`__rt_sdiv`]). The divide is signed and truncating, so a reversed
/// vector's negative span truncates toward zero like any C `/`, and a
/// partial element is dropped.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem28(vector: *const VectorBounds) -> i32 {
    // `read_unaligned`: same 4-but-not-8-aligned firmware head hazard
    // as `vector_size` on a 64-bit host.
    let begin = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).begin));
    let end = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).end));
    let span = (end as isize - begin as isize) as i32;
    __rt_sdiv(span, 28)
}

/// vector_size_elem40 — original: `FUN_083d783c` @ 0x083d783c
/// (16 bytes, 14 `bl` call sites; the only copy).
///
/// `vector<T>::size()` for a 40-byte element, a non-power-of-two member
/// of the `vector_size_elem*` family: the same `ldm r0,{r0,r1}; sub
/// r0,r1,r0` head as the shifts, then `mov r1,#0x28` and a **tail
/// branch** into the ADS signed divide @ 0x08031568 (ported as
/// [`__rt_sdiv`]). The divide is signed and truncating, so a reversed
/// vector's negative span truncates toward zero like any C `/`, and a
/// partial element is dropped.
///
/// # Safety
/// `vector` must point at a readable `{begin, end}` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_size_elem40(vector: *const VectorBounds) -> i32 {
    // `read_unaligned`: same 4-but-not-8-aligned firmware head hazard
    // as `vector_size` on a 64-bit host.
    let begin = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).begin));
    let end = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).end));
    let span = (end as isize - begin as isize) as i32;
    __rt_sdiv(span, 40)
}

/// A `vector<bool>` bit iterator — the `{word, bit}` pair that
/// [`vector_bool_iter_not_equal`] compares. Addressed by field, so the
/// port is layout-correct on both the 32-bit target and a 64-bit host.
#[repr(C)]
pub struct VectorBoolIter {
    /// Word containing the referenced bit.
    pub word: *mut u32,
    /// Bit offset within `word` (0..32).
    pub bit: u32,
}

/// A `vector<bool>` mask reference — the `{word, mask}` pair
/// [`vector_bool_reference_init`] writes, `std::vector<bool>`'s
/// `_Vb_reference`-shaped proxy for a single bit: `word` addresses the
/// storage word and `mask` is the single-bit selector `1 << bit`
/// within it. Addressed by field, so the port is layout-correct on
/// both the 32-bit target and a 64-bit host.
#[repr(C)]
pub struct VectorBoolReference {
    /// Word containing the referenced bit.
    pub word: *mut u32,
    /// Single-bit mask selecting the bit within `word`.
    pub mask: u32,
}

/// The `{begin_word, begin_bit, end_word, end_bit}` head of a
/// `vector<bool>` — two bit iterators, each a word pointer plus a bit
/// offset within that word. Addressed by field, so the port is
/// layout-correct on both the 32-bit target and a 64-bit host.
#[repr(C)]
pub struct VectorBoolBounds {
    /// Word containing the first bit.
    pub begin_word: *mut u32,
    /// Bit offset of the first bit within `begin_word` (0..32).
    pub begin_bit: u32,
    /// Word containing the end position.
    pub end_word: *mut u32,
    /// Bit offset of the end position within `end_word` (0..32).
    pub end_bit: u32,
}

/// vector_size_bool — original: `FUN_083d7968` @ 0x083d7968
/// (76 bytes; 2 `bl` call sites, both in the storage-grow path at
/// 0x083e5dfc / 0x083e5e10; the only copy —
/// `ipod-decomp/decomp/c/037/083d7968_FUN_083d7968.c`).
///
/// `std::vector<bool>::size()`, the bit-vector member of the
/// `vector_size_elem*` family: the bit-iterator difference
/// `(end_word - begin_word) / 4` whole words of 32 bits each, plus
/// `end_bit`, minus `begin_bit`. The original applies an **arithmetic**
/// `asr #2` to the word span, so a reversed head's negative word count
/// floors like the shift members of the size family, then `lsl #5`
/// scales words to bits. Its spill of all four head words to the stack
/// and immediate reload is ADS noise around an inlined iterator
/// difference; the port keeps only the computation.
///
/// Identification: the immediate neighbors are the bit-iterator
/// members — `operator!=` @ 0x083d79b4 (compare word pointer, then bit
/// offset), [`vector_bool_reference_init`] @ 0x083d79dc (the `{word, 1 << bit}`
/// mask-reference ctor) and
/// the `*word & mask` bit test @ 0x083d7a20 — and both call sites feed
/// the result into `words = (max(0x20, 2*size) + 0x1f) >> 5; alloc
/// words * 4`, the `vector<bool>` storage grow.
///
/// # Safety
/// `bits` must point at a readable [`VectorBoolBounds`]. The word
/// storage itself is never accessed, so either word pointer may be
/// NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_size_bool(bits: *const VectorBoolBounds) -> i32 {
    // `read_unaligned`: same 4-but-not-8-aligned firmware head hazard
    // as `vector_size` on a 64-bit host.
    let begin_word = core::ptr::read_unaligned(core::ptr::addr_of!((*bits).begin_word));
    let begin_bit = core::ptr::read_unaligned(core::ptr::addr_of!((*bits).begin_bit));
    let end_word = core::ptr::read_unaligned(core::ptr::addr_of!((*bits).end_word));
    let end_bit = core::ptr::read_unaligned(core::ptr::addr_of!((*bits).end_bit));
    // `asr #2`: arithmetic, so a reversed head's negative word span
    // floors instead of truncating toward zero.
    let words = ((end_word as isize - begin_word as isize) >> 2) as i32;
    // `lsl #5` + wrapping add/sub: 32 bits per word, 32-bit register
    // arithmetic exactly as the ARM body.
    (end_bit as i32).wrapping_add(words << 5).wrapping_sub(begin_bit as i32)
}

/// vector_bool_iter_not_equal — original: `FUN_083d79b4` @ 0x083d79b4
/// (40 bytes; 2 `bl` call sites, both in the `vector<bool>`
/// storage-grow path at 0x083e5dc4 / 0x083e5f40; the only copy —
/// `ipod-decomp/decomp/c/037/083d79b4_FUN_083d79b4.c`).
///
/// `std::vector<bool>` bit-iterator `operator!=`: two iterators
/// compare unequal when their word pointers differ or, the pointers
/// being equal, their bit offsets do. The original is a single
/// branchless predicated run — `ldreq` reloads the bit offsets only
/// when the word compare came out equal, then the shared `cmpeq`
/// finishes either comparison — and computes the EQUALITY first
/// (`movne r0, #0` / `moveq r0, #1`) before inverting it with a final
/// `eor r0, r0, #1`, the same never-folded ADS idiom as
/// [`not_equal_deref`].
///
/// Identification: it sits between [`vector_size_bool`] @ 0x083d7968
/// and [`vector_bool_reference_init`] @ 0x083d79dc (the `{word, 1 << bit}`
/// mask-reference ctor) in the
/// bit-iterator cluster (see that entry for the neighborhood).
///
/// # Safety
/// `a` and `b` must point at readable [`VectorBoolIter`]s. The word
/// storage itself is never accessed, so either word pointer may be
/// NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_bool_iter_not_equal(
    a: *const VectorBoolIter,
    b: *const VectorBoolIter,
) -> u32 {
    // `read_unaligned`: same 4-but-not-8-aligned firmware head hazard
    // as `vector_size_bool` on a 64-bit host.
    let a_word = core::ptr::read_unaligned(core::ptr::addr_of!((*a).word));
    let a_bit = core::ptr::read_unaligned(core::ptr::addr_of!((*a).bit));
    let b_word = core::ptr::read_unaligned(core::ptr::addr_of!((*b).word));
    let b_bit = core::ptr::read_unaligned(core::ptr::addr_of!((*b).bit));
    u32::from(a_word != b_word || a_bit != b_bit)
}

/// vector_bool_reference_init — original: `FUN_083d79dc` @ 0x083d79dc
/// (28 bytes; 8 `bl` call sites — 0x0826a3f4 plus 0x083e5d90,
/// 0x083e5da4, 0x083e5dd8, 0x083e5e78, 0x083e5f04, 0x083e5f20 and
/// 0x083e603c, seven of them in the `vector<bool>` storage-grow path;
/// the only copy — `ipod-decomp/decomp/c/037/083d79dc_FUN_083d79dc.c`).
///
/// `std::vector<bool>` mask-reference constructor: initializes a
/// `{word, mask}` reference proxy ([`VectorBoolReference`]) from a bit
/// iterator `{word, bit}` ([`VectorBoolIter`]) — copies the word
/// pointer and computes the single-bit mask `1 << bit`. The original
/// is a straight `ldr`/`lsl`/`str` run — `ldr r2,[r1]; ldr r1,[r1,#4];
/// mov r3,#1; mov r1,r3, lsl r1; str r1,[r0,#4]; str r2,[r0]` — and
/// leaves `mask_ref` in r0 untouched, so like [`deque_iter_assign`]
/// the port returns it.
///
/// The mask shift is an ARM register `lsl`: only the low byte of the
/// bit offset is used and a shift of 32 or more yields zero, which the
/// port reproduces with `checked_shl`; an in-range iterator (bit 0..32)
/// never reaches either edge.
///
/// Identification: it sits between the bit-iterator `operator!=` @
/// 0x083d79b4 and the `*word & mask` bit test @ 0x083d7a20 in the
/// bit-iterator cluster (see [`vector_size_bool`] @ 0x083d7968 for the
/// neighborhood), and every call site pairs it with that cluster's
/// iterator.
///
/// # Safety
/// `mask_ref` must point at a writable [`VectorBoolReference`] and
/// `iter` at a readable [`VectorBoolIter`]. The word storage itself is
/// never accessed, so the iterator's word pointer may be NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_bool_reference_init(
    mask_ref: *mut VectorBoolReference,
    iter: *const VectorBoolIter,
) -> *mut VectorBoolReference {
    // `read_unaligned`/`write_unaligned`: same 4-but-not-8-aligned
    // firmware head hazard as `vector_size_bool` on a 64-bit host.
    let word = core::ptr::read_unaligned(core::ptr::addr_of!((*iter).word));
    let bit = core::ptr::read_unaligned(core::ptr::addr_of!((*iter).bit));
    // ARM register `lsl`: the shift amount is the low byte of `bit`,
    // and a shift of 32 or more produces zero (not a wrap).
    let mask = 1u32.checked_shl(bit & 0xff).unwrap_or(0);
    core::ptr::write_unaligned(core::ptr::addr_of_mut!((*mask_ref).mask), mask);
    core::ptr::write_unaligned(core::ptr::addr_of_mut!((*mask_ref).word), word);
    mask_ref
}

/// vector_bool_iter_advance — original: `FUN_083e5f84` @ 0x083e5f84
/// (60 bytes; the only copy —
/// `ipod-decomp/decomp/c/038/083e5f84_FUN_083e5f84.c`).
///
/// `std::vector<bool>` bit-iterator `operator+=`: adds a signed bit
/// distance to the iterator's bit offset, then folds the wrapped 32-bit
/// sum into a whole-word pointer displacement and a bit offset in
/// `0..32`. The ARM sequence uses a sign-derived bias before `asr #5`,
/// then repairs a negative remainder with `+0x20` and one preceding word;
/// together those operations implement floor division rather than Rust/C
/// truncation toward zero.
///
/// The function returns `void`: r0 still happens to hold `iter` at `bx lr`,
/// but the recovered C signature and caller ABI consume no result. It
/// reads and writes only the iterator head, never its storage word.
///
/// # Safety
/// `iter` must point at a writable [`VectorBoolIter`]. Its `word` member
/// may be NULL because it is advanced as an address and never dereferenced.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_bool_iter_advance(iter: *mut VectorBoolIter, distance: i32) {
    // `read_unaligned`/`write_unaligned`: firmware heads are only
    // 4-byte aligned, while a 64-bit host gives the pointer field
    // stricter natural alignment.
    let word = core::ptr::read_unaligned(core::ptr::addr_of!((*iter).word));
    let bit = core::ptr::read_unaligned(core::ptr::addr_of!((*iter).bit));
    // `add r1, r2, r1`: wrapping 32-bit register arithmetic.
    let total = (bit as i32).wrapping_add(distance);
    // `asr #0x1f` + `lsr #0x1b`: add 31 to negative values before the
    // arithmetic word shift, exactly as the ARM body does.
    let bias = (((total >> 31) as u32) >> 27) as i32;
    let biased = total.wrapping_add(bias);
    let words = biased >> 5;
    let mut rem = total.wrapping_sub(biased & !0x1f);
    let mut new_word = word.wrapping_offset(words as isize);
    // `subs` leaves the sign flag for the conditional remainder/word
    // repair, producing Euclidean (floor) quotient and remainder.
    if rem < 0 {
        rem += 32;
        new_word = new_word.wrapping_sub(1);
    }
    core::ptr::write_unaligned(core::ptr::addr_of_mut!((*iter).word), new_word);
    core::ptr::write_unaligned(core::ptr::addr_of_mut!((*iter).bit), rem as u32);
}
/// vector_bool_iter_index — original: `FUN_083e6008` @ 0x083e6008
/// (60 bytes; 3 unconditional `bl` call sites — 0x08269ed4, 0x08269f44,
/// and 0x08269f6c; two direct calls, to `vector_bool_iter_advance` @
/// 0x083e5f84 and `vector_bool_reference_init` @ 0x083d79dc; the only copy).
///
/// `std::vector<bool>` bit-iterator `operator[]`: copies `iter` into a
/// stack temporary, advances that copy by `distance`, then initializes
/// `result` as the temporary's `{word, 1 << bit}` reference proxy. The
/// source iterator is never modified. The raw body saves `result` in r4,
/// uses the pushed r0/r3 slots for the first temporary, then converts the
/// advanced pair through the existing reference constructor.
///
/// The original returns with r0 holding `result`, because its final direct
/// callee leaves that argument intact. The port preserves that incidental
/// result even though all three callers use the hidden output object.
///
/// Deliberate host-only deviation: named-field `read_unaligned` and
/// `write_unaligned` accesses accept firmware heads that are 4-byte aligned
/// but not 8-byte aligned for host pointers; target field accesses remain
/// aligned word loads and stores.
///
/// # Safety
///
/// `result` must point at writable [`VectorBoolReference`] storage and
/// `iter` at readable [`VectorBoolIter`] storage. They may alias because
/// the original completes both source loads before writing `result`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_bool_iter_index(
    result: *mut VectorBoolReference,
    iter: *const VectorBoolIter,
    distance: i32,
) -> *mut VectorBoolReference {
    let mut local = VectorBoolIter {
        word: core::ptr::read_unaligned(core::ptr::addr_of!((*iter).word)),
        bit: core::ptr::read_unaligned(core::ptr::addr_of!((*iter).bit)),
    };
    vector_bool_iter_advance(&mut local, distance);
    vector_bool_reference_init(result, core::ptr::addr_of!(local))
}

/// vector_bool_iter_increment — original: `FUN_083e5fc0` @ 0x083e5fc0
/// (36 bytes in raw osos.dec, despite Ghidra's 40-byte report; 5
/// unconditional `bl` call sites at 0x0826a3d8, 0x083e5dec,
/// 0x083e5e68, 0x083e5ef4, and 0x083e5f10; the only copy).
///
/// `std::vector<bool>` bit-iterator `operator++`: increments `iter.bit`
/// with 32-bit register wrapping. When the incremented offset is exactly
/// 32, it resets the offset to zero and advances `iter.word` by one
/// 4-byte storage word. It reads and writes only the iterator head, never
/// the storage word. There is deliberately no NULL guard: every decoded
/// caller is an unconditional call and the original dereferences the head.
///
/// Deliberate host-only deviation: unaligned field access accepts firmware
/// heads that are 4-byte aligned but not aligned for 64-bit host pointers;
/// target named-field accesses remain aligned word loads and stores.
///
/// # Safety
///
/// `iter` must point at a writable [`VectorBoolIter`]. Its `word` member
/// may be NULL because it is advanced as an address and never dereferenced.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_bool_iter_increment(iter: *mut VectorBoolIter) {
    #[cfg(target_os = "none")]
    let bit = (*iter).bit;
    #[cfg(not(target_os = "none"))]
    let bit = core::ptr::read_unaligned(core::ptr::addr_of!((*iter).bit));
    let next_bit = bit.wrapping_add(1);
    #[cfg(target_os = "none")]
    {
        (*iter).bit = next_bit;
    }
    #[cfg(not(target_os = "none"))]
    core::ptr::write_unaligned(core::ptr::addr_of_mut!((*iter).bit), next_bit);
    if next_bit == 32 {
        #[cfg(target_os = "none")]
        {
            (*iter).bit = 0;
            (*iter).word = (*iter).word.wrapping_add(1);
        }
        #[cfg(not(target_os = "none"))]
        {
            core::ptr::write_unaligned(core::ptr::addr_of_mut!((*iter).bit), 0);
            let word = core::ptr::read_unaligned(core::ptr::addr_of!((*iter).word));
            core::ptr::write_unaligned(
                core::ptr::addr_of_mut!((*iter).word),
                word.wrapping_add(1),
            );
        }
    }
}


/// vector_bool_reference_assign — original: `FUN_083e5fe8` @ 0x083e5fe8
/// (32 bytes; 7 unconditional `bl` call sites — 0x08269f50, 0x08269f78,
/// 0x0826a400, 0x083e5db8, 0x083e5de4, 0x083e5e84, and 0x083e5f34; the
/// only copy).
///
/// `std::vector<bool>` mask-reference assignment: reads the proxy's
/// `{word, mask}` fields and replaces the masked storage bit(s), clearing
/// them when `value` is zero and setting them for every nonzero raw C++ bool
/// value. The raw ARM sequence is `ldr r3,[r0]; movs ip,r1; ldr r1,[r0,#4];
/// ldr r2,[r3]; biceq r1,r2,r1; orrne r1,r2,r1; str r1,[r3]; bx lr`.
///
/// Although the raw leaf body leaves r0 as `mask_ref`, all seven verified
/// call sites discard it; the recovered ABI is therefore `void`, matching
/// the original signature. There is deliberately no NULL guard: every call
/// is unconditional and the original dereferences both the reference head
/// and its storage word.
///
/// On target, named-field loads compile as aligned word accesses, matching
/// the firmware's 4-byte-aligned proxy layout. The host-only branch uses
/// `read_unaligned` so the same function can test a firmware-aligned head
/// that is not 8-byte-aligned for host pointers.
///
/// # Safety
///
/// `mask_ref` must point at a readable [`VectorBoolReference`] whose `word`
/// points at a writable, aligned `u32` storage word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_bool_reference_assign(
    mask_ref: *mut VectorBoolReference,
    value: u32,
) {
    #[cfg(target_os = "none")]
    let word = (*mask_ref).word;
    #[cfg(not(target_os = "none"))]
    let word = core::ptr::read_unaligned(core::ptr::addr_of!((*mask_ref).word));
    #[cfg(target_os = "none")]
    let mask = (*mask_ref).mask;
    #[cfg(not(target_os = "none"))]
    let mask = core::ptr::read_unaligned(core::ptr::addr_of!((*mask_ref).mask));
    let previous = word.read();
    let updated = if value == 0 {
        previous & !mask
    } else {
        previous | mask
    };
    word.write(updated);
}


/// vector_bool_iter_minus — original: `FUN_083d79f8` @ 0x083d79f8
/// (40 bytes; 2 `bl` call sites — 0x0826a3e8 and 0x083e5d6c, the
/// latter in the `vector<bool>` storage-grow path; the only copy —
/// `ipod-decomp/decomp/c/037/083d79f8_FUN_083d79f8.c`).
///
/// `std::vector<bool>` bit-iterator `operator-(iter, n)`: copies the
/// `{word, bit}` iterator to a stack temp (`ldmia r1,{r0,r1}` /
/// `stmia sp,{r0,r1}` — the temp reuses the pushed r2/r3 slots),
/// advances the temp by the NEGATED distance (`rsb r1, r2, #0`, a
/// wrapping 32-bit negate) through the in-place advance @ 0x083e5f84,
/// and stores the result through the hidden sret pointer saved in r4
/// (`ldmia sp,{r0,r1}` / `stmia r4,{r0,r1}`). The reload leaves r0
/// holding the result's **word pointer**, not the sret pointer, so
/// the port returns that; both call sites recompute every pointer
/// they need and never consume r0.
///
/// Its callee is the direct port [`vector_bool_iter_advance`] of
/// 0x083e5f84, preserving the original `bl` relationship without an
/// indirection seam.
///
/// Identification: sits between [`vector_bool_reference_init`] @
/// 0x083d79dc and [`vector_bool_reference_test`] @ 0x083d7a20 in the
/// bit-iterator cluster (see [`vector_size_bool`] @ 0x083d7968 for the
/// neighborhood). The 0x0826a3e8 call site follows an `operator++` @
/// 0x083e5fc0 with `operator-(iter, 1)` plus the mask-reference ctor
/// and the set/clear-bit store @ 0x083e5fe8 — write-back of the bit
/// just stepped past.
///
/// # Safety
/// `result` must point at a writable [`VectorBoolIter`] and `iter` at
/// a readable one; they may alias (the original round-trips through a
/// stack temp, so an in-place `it = it - n` works). The word storage
/// itself is never accessed, so either word pointer may be NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_bool_iter_minus(
    result: *mut VectorBoolIter,
    iter: *const VectorBoolIter,
    distance: i32,
) -> *mut u32 {
    // `read_unaligned`: same 4-but-not-8-aligned firmware head hazard
    // as `vector_bool_reference_init` on a 64-bit host.
    let mut local = VectorBoolIter {
        word: core::ptr::read_unaligned(core::ptr::addr_of!((*iter).word)),
        bit: core::ptr::read_unaligned(core::ptr::addr_of!((*iter).bit)),
    };
    // `rsb r1, r2, #0`: the advance runs on the NEGATED distance, as
    // wrapping 32-bit register arithmetic.
    vector_bool_iter_advance(&mut local, distance.wrapping_neg());
    core::ptr::write_unaligned(core::ptr::addr_of_mut!((*result).word), local.word);
    core::ptr::write_unaligned(core::ptr::addr_of_mut!((*result).bit), local.bit);
    // The original returns with r0 holding the result's word pointer
    // (reloaded from the stack temp), not the sret pointer.
    local.word
}

/// vector_bool_reference_test — original: `FUN_083d7a20` @ 0x083d7a20
/// (24 bytes; 3 `bl` call sites — 0x08269edc plus 0x083e5dac and
/// 0x083e5f28 in the `vector<bool>` storage-grow path; the only copy —
/// `ipod-decomp/decomp/c/037/083d7a20_FUN_083d7a20.c`).
///
/// `std::vector<bool>` mask-reference dereference — the
/// `_Vb_reference`-shaped proxy's `operator bool`: loads the
/// reference's word pointer and single-bit mask, reads the storage
/// word, and returns whether the masked bit is set. The original is a
/// straight `ldr`/`and` run — `ldr r1,[r0]; ldr r0,[r0,#4]; ldr
/// r1,[r1]; ands r0,r1,r0; movne r0,#1; bx lr` — the `ands` setting
/// the flags and `movne r0, #1` normalizing the result to the ADS 0/1
/// word-sized bool.
///
/// Identification: it sits immediately after [`vector_bool_reference_init`]
/// @ 0x083d79dc in the bit-iterator cluster (see [`vector_size_bool`]
/// @ 0x083d7968 for the neighborhood), the read half of the
/// `{word, mask}` proxy that constructor writes.
///
/// # Safety
/// `mask_ref` must point at a readable [`VectorBoolReference`] whose
/// `word` field addresses a readable storage word — unlike the other
/// cluster members, this one dereferences the storage, so `word` must
/// not be NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_bool_reference_test(mask_ref: *const VectorBoolReference) -> u32 {
    // `read_unaligned`: same 4-but-not-8-aligned firmware head hazard
    // as `vector_bool_reference_init` on a 64-bit host.
    let word = core::ptr::read_unaligned(core::ptr::addr_of!((*mask_ref).word));
    let mask = core::ptr::read_unaligned(core::ptr::addr_of!((*mask_ref).mask));
    u32::from(word.read() & mask != 0)
}

/// The `{begin, end, end_of_storage}` head of a vector — the three
/// words [`vector_capacity`] reads the first and last of (`ldr
/// r1,[r0,#0x8]` / `ldr r0,[r0,#0x0]`). Addressed by field, so
/// `end_of_storage` lands two words after `begin` on both the 32-bit
/// target and a 64-bit host.
#[repr(C)]
pub struct VectorStorage {
    /// First element.
    pub begin: *mut u8,
    /// One past the last element (unused by capacity, kept so the
    /// layout matches the firmware head).
    pub end: *mut u8,
    /// One past the allocated storage.
    pub end_of_storage: *mut u8,
}
/// vector_clear_elem4 — original: `FUN_083e6808` @ `0x083e6808`
/// (84 bytes, `0x083e6808..0x083e685c`; the next separately linked function
/// starts `ldr r2,[r0,#8]` at `0x083e685c`).
///
/// Clears a `std::vector<T>` whose four-byte elements have trivial
/// destruction. The ARM body loads `begin` and `end`; an empty head returns
/// immediately. For a non-empty head, its apparent range-copy loop is
/// unreachable because it compares `end` to a register that was just set to
/// `end`; its following walk has no side effects and it stores `begin` into
/// `end`. Thus no element is read, written, or destroyed, and the allocation
/// remains owned by the vector.
///
/// **Call count:** complete aligned ARM B/BL-immediate decoding of
/// `osos.dec` finds five direct, unconditional `bl` callers at
/// `0x0813d8e8`, `0x0813e1b8`, `0x0813e21c`, `0x08177614`, and `0x081778fc`;
/// there are no predicated forms. A sixth inbound branch is the unconditional
/// tail transfer at `0x0813d8f4`, not a call.
///
/// # Deliberate deviations
///
/// None.
///
/// # Safety
///
/// `vector` must point to a writable, aligned [`VectorStorage`].
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_clear_elem4")]
#[inline(never)]
pub unsafe extern "C" fn vector_clear_elem4(vector: *mut VectorStorage) {
    let begin = (*vector).begin;
    if begin != (*vector).end {
        (*vector).end = begin;
    }
}

/// vector_storage_init — original: `FUN_083e688c` @ `0x083e688c`
/// (20 bytes, 6 direct `bl` call sites — 0x08177630, 0x0817763c,
/// 0x08177648, 0x08177b94, 0x082ae80c, and 0x082ae824; all
/// unconditional).
///
/// Default-constructs a `std::vector<T>` storage head by writing zero to
/// its `{begin, end, end_of_storage}` words. Raw `osos.dec` confirms the
/// three `str r1,[r0,#offset]` stores at +0, +4, and +8, with `r1` set to
/// zero once. No deliberate deviations.
///
/// # Safety
/// `vector` must point at a writable, aligned [`VectorStorage`].
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_storage_init")]
#[inline(never)]
pub unsafe extern "C" fn vector_storage_init(vector: *mut VectorStorage) {
    (*vector).begin = core::ptr::null_mut();
    (*vector).end = core::ptr::null_mut();
    (*vector).end_of_storage = core::ptr::null_mut();
}


/// vector_capacity — original: `FUN_083d7760` @ 0x083d7760
/// (20 bytes, 6 `bl` call sites; names.yaml's size: 16 is stale,
/// functions.csv and the next function at 0x083d7774 both say 20).
///
/// `vector<T>::capacity()` for a 24-byte element: the capacity()
/// sibling of the `vector_size_elem*` family, reading the
/// end-of-storage word at +8 instead of the end word at +4 —
/// `(end_of_storage - begin) / 24`. The element size is not a power of
/// two, so instead of an `asr` the original loads `mov r1, #0x18` and
/// **tail-branches** into the ADS signed divide @ 0x08031568
/// (ported as [`__rt_sdiv`]); the divide is signed, so a reversed
/// vector's negative span truncates toward zero like any C `/`.
///
/// # Safety
/// `vector` must point at a readable `{begin, end, end_of_storage}`
/// triple.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_capacity(vector: *const VectorStorage) -> i32 {
    // `read_unaligned`: same 4-but-not-8-aligned firmware head hazard
    // as `vector_size` on a 64-bit host.
    let begin = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).begin));
    let end_of_storage =
        core::ptr::read_unaligned(core::ptr::addr_of!((*vector).end_of_storage));
    let span = (end_of_storage as isize - begin as isize) as i32;
    __rt_sdiv(span, 24)
}

/// vector_capacity_elem12 — original: `FUN_083d7708` @ 0x083d7708
/// (20 bytes, 4 `bl` call sites).
///
/// `vector<T>::capacity()` for a 12-byte element: the same
/// end-of-storage head as [`vector_capacity`] (`ldr r1,[r0,#0x8]` /
/// `ldr r0,[r0,#0x0]` / `sub r0,r1,r0`), then `mov r1, #0xc` and a
/// **tail branch** into the ADS signed divide @ 0x08031568 (ported as
/// [`__rt_sdiv`]). The ledger guessed this instantiation was
/// shift-based; osos.asm says otherwise — 12 is not a power of two, so
/// this is a divide member exactly like the 24-byte primary. The
/// divide is signed and truncating, so a reversed vector's negative
/// span truncates toward zero like any C `/`, and a partial element is
/// dropped.
///
/// # Safety
/// `vector` must point at a readable `{begin, end, end_of_storage}`
/// triple.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_capacity_elem12(vector: *const VectorStorage) -> i32 {
    // `read_unaligned`: same 4-but-not-8-aligned firmware head hazard
    // as `vector_size` on a 64-bit host.
    let begin = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).begin));
    let end_of_storage =
        core::ptr::read_unaligned(core::ptr::addr_of!((*vector).end_of_storage));
    let span = (end_of_storage as isize - begin as isize) as i32;
    __rt_sdiv(span, 12)
}

/// vector_capacity_elem16 — original: `FUN_083d77a8` @ 0x083d77a8
/// (20 bytes, 4 `bl` call sites).
///
/// `vector<T>::capacity()` for a 16-byte element: the same
/// end-of-storage head as [`vector_capacity`] (`ldr r1,[r0,#0x8]` /
/// `ldr r0,[r0,#0x0]` / `sub r0,r1,r0`), then `mov r0,r0, asr #0x4`
/// and `bx lr` — a **shift** member, not a divide: 16 is a power of
/// two, so there is no tail branch into the ADS signed divide. The
/// ledger's blanket "shift-based" guess for this instantiation happens
/// to be right, but that is luck — the sibling at 0x083d7708 with the
/// same guess turned out to be a divide; element sizes must be read
/// from osos.asm per address. The shift is **arithmetic**, so a
/// reversed vector's negative span stays negative instead of becoming
/// a huge unsigned count.
///
/// # Safety
/// `vector` must point at a readable `{begin, end, end_of_storage}`
/// triple.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_capacity_elem16(vector: *const VectorStorage) -> i32 {
    // `read_unaligned`: same 4-but-not-8-aligned firmware head hazard
    // as `vector_size` on a 64-bit host.
    let begin = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).begin));
    let end_of_storage =
        core::ptr::read_unaligned(core::ptr::addr_of!((*vector).end_of_storage));
    let span = end_of_storage as isize - begin as isize;
    (span >> 4) as i32
}

/// vector_capacity_elem24_copy_77ec — original: `FUN_083d77ec` @
/// 0x083d77ec (20 bytes; 3 `bl` call sites: 0x083e2c1c, 0x083e2d4c,
/// 0x083e2dd0 — the ledger's "4 bl sites" guess was stale).
///
/// A second, byte-identical instantiation of the 24-byte
/// [`vector_capacity`] @ 0x083d7760: the same end-of-storage head
/// (`ldr r1,[r0,#0x8]` / `ldr r0,[r0,#0x0]` / `sub r0,r1,r0`), then
/// `mov r1, #0x18` and a **tail branch** into the ADS signed divide @
/// 0x08031568 (ported as [`__rt_sdiv`]). Verified against osos.asm per
/// address — the ledger's blanket "shift-based" guess for the remaining
/// capacity instantiations is wrong for this one too (as it was for
/// 0x083d7708); only 0x083d77a8 is really a shift. The divide is
/// signed and truncating, so a reversed vector's negative span
/// truncates toward zero like any C `/`, and a partial element is
/// dropped.
///
/// # Safety
/// `vector` must point at a readable `{begin, end, end_of_storage}`
/// triple.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_capacity_elem24_copy_77ec(
    vector: *const VectorStorage,
) -> i32 {
    // `read_unaligned`: same 4-but-not-8-aligned firmware head hazard
    // as `vector_size` on a 64-bit host.
    let begin = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).begin));
    let end_of_storage =
        core::ptr::read_unaligned(core::ptr::addr_of!((*vector).end_of_storage));
    let span = (end_of_storage as isize - begin as isize) as i32;
    __rt_sdiv(span, 24)
}

/// vector_capacity_elem40 — original: `FUN_083d784c` @ 0x083d784c
/// (20 bytes; 4 `bl` call sites: 0x083e32bc, 0x083e33d8, 0x083e3434,
/// 0x083e34bc).
///
/// `vector<T>::capacity()` for a 40-byte element: the same
/// end-of-storage head as [`vector_capacity`] (`ldr r1,[r0,#0x8]` /
/// `ldr r0,[r0,#0x0]` / `sub r0,r1,r0`), then `mov r1, #0x28` and a
/// **tail branch** into the ADS signed divide @ 0x08031568 (ported as
/// [`__rt_sdiv`]). Verified against osos.asm per address — the ledger's
/// blanket "shift-based" guess for the remaining capacity
/// instantiations is wrong for this one too (as it was for 0x083d7708,
/// 0x083d77ec and 0x083d7828); only 0x083d77a8 is really a shift. The
/// divide is signed and truncating, so a reversed vector's negative
/// span truncates toward zero like any C `/`, and a partial element is
/// dropped.
///
/// # Safety
/// `vector` must point at a readable `{begin, end, end_of_storage}`
/// triple.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_capacity_elem40(vector: *const VectorStorage) -> i32 {
    // `read_unaligned`: same 4-but-not-8-aligned firmware head hazard
    // as `vector_size` on a 64-bit host.
    let begin = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).begin));
    let end_of_storage =
        core::ptr::read_unaligned(core::ptr::addr_of!((*vector).end_of_storage));
    let span = (end_of_storage as isize - begin as isize) as i32;
    __rt_sdiv(span, 40)
}

/// vector_capacity_elem8 — original: `FUN_083d7870` @ 0x083d7870
/// (20 bytes; 4 `bl` call sites: 0x083e35dc, 0x083e36f4, 0x083e3748,
/// 0x083e37cc).
///
/// `vector<T>::capacity()` for an 8-byte element: the same
/// end-of-storage head as [`vector_capacity`] (`ldr r1,[r0,#0x8]` /
/// `ldr r0,[r0,#0x0]` / `sub r0,r1,r0`), then `mov r0,r0, asr #0x3`
/// and `bx lr` — a **shift** member like [`vector_capacity_elem16`],
/// not a divide: 8 is a power of two, so there is no tail branch into
/// the ADS signed divide. Verified against osos.asm per address — the
/// ledger's blanket "shift-based" guess for this instantiation happens
/// to be right, but that is luck (the 0x083d7708, 0x083d77ec,
/// 0x083d7828 and 0x083d784c siblings with the same guess all turned
/// out to be divides); element sizes must be read from osos.asm per
/// address. The shift is **arithmetic**, so a reversed vector's
/// negative span stays negative (rounding toward -inf, unlike the
/// divide members' toward-zero truncation).
///
/// # Safety
/// `vector` must point at a readable `{begin, end, end_of_storage}`
/// triple.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_capacity_elem8(vector: *const VectorStorage) -> i32 {
    // `read_unaligned`: same 4-but-not-8-aligned firmware head hazard
    // as `vector_size` on a 64-bit host.
    let begin = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).begin));
    let end_of_storage =
        core::ptr::read_unaligned(core::ptr::addr_of!((*vector).end_of_storage));
    let span = end_of_storage as isize - begin as isize;
    (span >> 3) as i32
}

/// vector_capacity_elem4 — original: `FUN_083d7954` @ 0x083d7954
/// (20 bytes; 4 `bl` call sites: 0x083e5988, 0x083e5a90, 0x083e5bdc,
/// 0x083e5c60 — the last of the family's shift instantiations; the
/// divide member at 0x083d7650, [`vector_capacity_elem20`], was
/// identified later).
///
/// `vector<T>::capacity()` for a 4-byte element: the same
/// end-of-storage head as [`vector_capacity`] (`ldr r1,[r0,#0x8]` /
/// `ldr r0,[r0,#0x0]` / `sub r0,r1,r0`), then `mov r0,r0, asr #0x2`
/// and `bx lr` — a **shift** member like [`vector_capacity_elem16`]
/// and [`vector_capacity_elem8`], not a divide: 4 is a power of two,
/// so there is no tail branch into the ADS signed divide. Verified
/// against osos.asm per address — with 0x083d7708, 0x083d77ec,
/// 0x083d7828 and 0x083d784c all having turned out to be divides
/// under the ledger's blanket "shift-based" guess, this one had to be
/// read from the disassembly too; it sits immediately after the
/// `vector_size_elem4`-shaped shift at 0x083d7944 and shares its
/// `asr #0x2`. The shift is **arithmetic**, so a reversed vector's
/// negative span stays negative (rounding toward -inf, unlike the
/// divide members' toward-zero truncation).
///
/// # Safety
/// `vector` must point at a readable `{begin, end, end_of_storage}`
/// triple.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_capacity_elem4(vector: *const VectorStorage) -> i32 {
    // `read_unaligned`: same 4-but-not-8-aligned firmware head hazard
    // as `vector_size` on a 64-bit host.
    let begin = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).begin));
    let end_of_storage =
        core::ptr::read_unaligned(core::ptr::addr_of!((*vector).end_of_storage));
    let span = end_of_storage as isize - begin as isize;
    (span >> 2) as i32
}

/// vector_capacity_elem20 — original: `FUN_083d7650` @ 0x083d7650
/// (20 bytes; 2 `bl` call sites: 0x083e0130, 0x083e0260).
///
/// `vector<T>::capacity()` for a 20-byte element: the same
/// end-of-storage head as [`vector_capacity`] (`ldr r1,[r0,#0x8]` /
/// `ldr r0,[r0,#0x0]` / `sub r0,r1,r0`), then `mov r1, #0x14` and a
/// **tail branch** into the ADS signed divide @ 0x08031568 (ported as
/// [`__rt_sdiv`]). Verified against osos.asm per address — the
/// ledger's note on [`vector_capacity_elem4`] claimed the capacity
/// family was fully ported, but this instantiation had never been
/// identified at all; it sits immediately before the
/// `vector_size_elem8`-shaped shift at 0x083d7664. The divide is
/// signed and truncating, so a reversed vector's negative span
/// truncates toward zero like any C `/`, and a partial element is
/// dropped.
///
/// # Safety
/// `vector` must point at a readable `{begin, end, end_of_storage}`
/// triple.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_capacity_elem20(vector: *const VectorStorage) -> i32 {
    // `read_unaligned`: same 4-but-not-8-aligned firmware head hazard
    // as `vector_size` on a 64-bit host.
    let begin = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).begin));
    let end_of_storage =
        core::ptr::read_unaligned(core::ptr::addr_of!((*vector).end_of_storage));
    let span = (end_of_storage as isize - begin as isize) as i32;
    __rt_sdiv(span, 20)
}

/// Firmware load address of `FUN_083e12dc`, the grow-and-insert helper
/// [`vector_push_back_elem12`] calls when the storage is full. Unported
/// (its own size/capacity/allocate callees — [`vector_size_elem12`]
/// 0x083d76f8, [`vector_capacity_elem12`] 0x083d7708 and
/// `operator_new_checked` 0x08266c70 — are all ported); dispatched
/// through [`VECTOR_PUSH_BACK_ELEM12_OPS`].
pub const VECTOR_INSERT_AUX_ELEM12_ADDRESS: usize = 0x083e_12dc;

/// Indirect dispatch for the one unported callee of
/// [`vector_push_back_elem12`] (the `app/animation.rs` pattern): host
/// tests install a recording model; a later port of the helper replaces
/// the default without touching this caller.
#[derive(Clone, Copy)]
pub struct VectorPushBackElem12Ops {
    /// Insert-aux 0x083e12dc `(vector, position, element)`: inserts the
    /// 12-byte `element` at `position` (the vector's `end` here),
    /// growing the storage first (capacity + max(capacity/2 +
    /// capacity/8, 32) elements through `operator_new_checked`, then an
    /// elementwise move). No return value.
    pub insert_aux: unsafe extern "C" fn(
        vector: *mut VectorStorage,
        position: *mut u8,
        element: *const u32,
    ),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_insert_aux_elem12(
    vector: *mut VectorStorage,
    position: *mut u8,
    element: *const u32,
) {
    let f: unsafe extern "C" fn(*mut VectorStorage, *mut u8, *const u32) =
        core::mem::transmute(VECTOR_INSERT_AUX_ELEM12_ADDRESS);
    f(vector, position, element)
}

/// Host default: inert — every test installs its own model.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_insert_aux_elem12(
    _vector: *mut VectorStorage,
    _position: *mut u8,
    _element: *const u32,
) {
}

/// Wired default: the ROM address on target, a documented inert stub on
/// host.
pub const DEFAULT_VECTOR_PUSH_BACK_ELEM12_OPS: VectorPushBackElem12Ops =
    VectorPushBackElem12Ops {
        insert_aux: firmware_insert_aux_elem12,
    };

/// The active callee, read through `read_volatile` so LLVM cannot fold
/// the indirect call to the default.
pub static mut VECTOR_PUSH_BACK_ELEM12_OPS: VectorPushBackElem12Ops =
    DEFAULT_VECTOR_PUSH_BACK_ELEM12_OPS;

#[inline(always)]
fn vector_push_back_elem12_ops() -> VectorPushBackElem12Ops {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(VECTOR_PUSH_BACK_ELEM12_OPS)) }
}

/// vector_push_back_elem12 — original: `FUN_0816caa4` @ 0x0816caa4
/// (64 bytes; `ipod-decomp/decomp/c/015/0816caa4_FUN_0816caa4.c`).
///
/// `std::vector<T>::push_back` for a 12-byte trivially-copyable element
/// on the [`VectorStorage`] `{begin, end, end_of_storage}` head. The
/// element arrives by value in r1/r2/r3:
///
/// ```text
/// 0816caa4  push {r1, r2, r3, lr}   ; spill the 12-byte element
/// 0816caa8  stm sp, {r1, r2}        ; (already pushed; the strb below
/// 0816caac  strb r3, [sp, #8]       ;  is redundant — sp+8 holds FULL r3)
/// 0816cab0  ldmib r0, {r1, r2}      ; end = [+4], cap = [+8]
/// 0816cab4  cmp r1, r2
/// 0816cab8  beq slow                ; full: grow & insert
/// 0816cabc  add r1, r1, #12
/// 0816cac0  str r1, [r0, #4]        ; end += 12 (UNCONDITIONAL)
/// 0816cac4  subs r0, r1, #12        ; r0 = old end, Z iff end == NULL
/// 0816cac8  movne/ldmne/stmne       ; if end != NULL: *end = element
/// 0816cad4  pop {r2, r3, ip, pc}
/// slow:
/// 0816cad8  mov r2, sp
/// 0816cadc  bl  0x083e12dc          ; insert_aux(vector, end, &element)
/// 0816cae0  pop {r2, r3, ip, pc}
/// ```
///
/// **Extent**: exactly 64 bytes — the next function opens `push
/// {r4, r5, r6, lr}` at 0x0816cae4. **Call count**, verified by
/// decoding every B/BL word in osos.dec: 43 sites, 38 plain `bl` plus
/// 5 predicated forms (4 `bleq`, 1 `blne` @ 0x0821ec58, 0x0821ec80,
/// 0x08222f98, 0x08226c18, 0x08239524) — each sits immediately after a
/// `cmp r0, #0`, so the CALLER skips the push when its preceding lookup
/// failed; the callee itself carries no such guard. A byte-pattern scan
/// finds no second instantiation. The observed use binds button
/// handlers: callers push `{command_id, handler_name, flag}` records
/// (e.g. FUN_082342b4 pushes `{id, "HandleAddToOTG" + 1, 1}`) into a
/// stack vector handed to FUN_08134720; push_back interprets none of
/// the fields.
///
/// Two behaviours worth pinning: the end advance happens BEFORE and
/// independently of the NULL-slot guard (a NULL `end` distinct from
/// `end_of_storage` still advances to 12 with no store), and the third
/// element word is the FULL r3, not a byte — the `strb` rewrites the
/// low byte of the pushed word with the value it already held. Ghidra's
/// C matches this decode; its `puVar1 + 3` is the +12-byte advance in
/// 4-byte units.
///
/// # Deviations
///
/// The grow-and-insert helper `FUN_083e12dc` is unported and dispatches
/// through [`VECTOR_PUSH_BACK_ELEM12_OPS`]: target builds transmute
/// [`VECTOR_INSERT_AUX_ELEM12_ADDRESS`], the host default is inert and
/// every test installs a recording model.
///
/// # Safety
/// `vector` must point at a writable `{begin, end, end_of_storage}`
/// triple; on the fast path `end` must be NULL or point at 12 writable
/// bytes inside the storage.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_push_back_elem12")]
#[inline(never)]
pub unsafe extern "C" fn vector_push_back_elem12(
    vector: *mut VectorStorage,
    word0: u32,
    word1: u32,
    word2: u32,
) {
    // Plain aligned word accesses: the original's `ldmib r0, {r1, r2}`
    // / `str r1, [r0, #4]` — every call site heads a word-aligned
    // vector (stack spill slot or object member), so the family's
    // `read_unaligned` host-fixture idiom would only pessimize ARMv5TE
    // codegen into four `ldrb` per word here.
    let end = (*vector).end;
    let end_of_storage = (*vector).end_of_storage;
    if end == end_of_storage {
        // Full: the original's `push {r1, r2, r3}` spills the element
        // to the stack and `mov r2, sp` hands the helper its address.
        let element = [word0, word1, word2];
        (vector_push_back_elem12_ops().insert_aux)(vector, end, element.as_ptr());
        return;
    }
    // str r1, [r0, #4]: the advance is unconditional — a NULL end still
    // becomes 12 (`wrapping_add`: `add` on a null pointer is UB on host).
    (*vector).end = end.wrapping_add(12);
    if !end.is_null() {
        // stm r0, {r2, r3, ip}: the whole 12-byte element, word2 in full.
        let slot = end.cast::<u32>();
        slot.write(word0);
        slot.add(1).write(word1);
        slot.add(2).write(word2);
    }
}

/// Firmware load address of `FUN_083e6500`, the grow-and-insert helper
/// [`vector_push_back_elem4`] tail-branches to when the vector is full.
///
/// The helper is not yet ported. It receives `(vector, end, element)` and
/// reallocates the four-byte-element storage before inserting `*element`.
pub const VECTOR_INSERT_AUX_ELEM4_ADDRESS: usize = 0x083e_6500;

/// Indirect dispatch for [`vector_push_back_elem4`]'s unported full-storage
/// helper. Target builds retain the firmware boundary; host tests install a
/// concrete recorder.
#[derive(Clone, Copy)]
pub struct VectorPushBackElem4Ops {
    pub insert_aux:
        unsafe extern "C" fn(vector: *mut VectorStorage, position: *mut u8, element: *const u32),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_insert_aux_elem4(
    vector: *mut VectorStorage,
    position: *mut u8,
    element: *const u32,
) {
    let insert_aux: unsafe extern "C" fn(*mut VectorStorage, *mut u8, *const u32) =
        core::mem::transmute(VECTOR_INSERT_AUX_ELEM4_ADDRESS);
    insert_aux(vector, position, element)
}

/// Host default: inert. Tests replace it to observe the full-storage path.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_insert_aux_elem4(
    _vector: *mut VectorStorage,
    _position: *mut u8,
    _element: *const u32,
) {
}

pub const DEFAULT_VECTOR_PUSH_BACK_ELEM4_OPS: VectorPushBackElem4Ops =
    VectorPushBackElem4Ops {
        insert_aux: firmware_insert_aux_elem4,
    };

/// Active full-storage helper. A volatile load preserves the indirect firmware
/// boundary instead of allowing LLVM to fold in the default target address.
pub static mut VECTOR_PUSH_BACK_ELEM4_OPS: VectorPushBackElem4Ops =
    DEFAULT_VECTOR_PUSH_BACK_ELEM4_OPS;

#[inline(always)]
fn vector_push_back_elem4_ops() -> VectorPushBackElem4Ops {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(VECTOR_PUSH_BACK_ELEM4_OPS)) }
}

/// vector_push_back_elem4 — original: `FUN_083e685c` @ `0x083e685c`
/// (48 bytes, `0x083e685c..0x083e688c`; the next separately linked function
/// starts `mov r1, #0` at `0x083e688c`).
///
/// `std::vector<T>::push_back` for one trivially-copyable four-byte element.
/// Raw ARM loads `end` and `end_of_storage`; if they match it copies `end`
/// into r1, moves the source pointer to r2, and tail-branches to
/// `FUN_083e6500`. Otherwise it advances and stores `end` before using
/// `subs r0, r2, #4` as a NULL destination guard; a NULL `end` therefore
/// advances to address 4 without dereferencing `element`.
///
/// **Call count:** decoding every ARM B/BL word in `osos.dec` finds seven
/// direct `bl` callers: five plain (`0x08177768`, `0x081777e0`,
/// `0x08177808`, `0x08177838`, `0x08177868`) and two predicated `blne`
/// (`0x0813e208`, `0x0813e26c`). The latter callers compare their candidate
/// word with zero immediately before the call, so the push itself has no
/// source NULL guard. The full-vector transfer is a `beq`, not a call.
///
/// # Deliberate deviation
///
/// `FUN_083e6500` is unported, so its tail transfer crosses
/// [`VECTOR_PUSH_BACK_ELEM4_OPS`]. On target the default calls the verified
/// firmware address; host tests replace it. The fast path has no deviation.
///
/// # Safety
///
/// `vector` must be a writable, aligned [`VectorStorage`]. On the fast path,
/// `element` must be readable and `end` must be either NULL or a writable
/// aligned four-byte slot; on the full path the configured helper owns the
/// `element` contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_push_back_elem4")]
#[inline(never)]
pub unsafe extern "C" fn vector_push_back_elem4(
    vector: *mut VectorStorage,
    element: *const u32,
) {
    // `ldr r2,[r0,#8] ; ldr r3,[r0,#4]`: plain aligned word loads.
    let end_of_storage = (*vector).end_of_storage;
    let end = (*vector).end;
    if end == end_of_storage {
        // `moveq r2,r1 ; moveq r1,r3 ; beq 0x083e6500`.
        (vector_push_back_elem4_ops().insert_aux)(vector, end, element);
        return;
    }

    // `add r2,r3,#4 ; str r2,[r0,#4]`: update precedes the NULL-slot
    // guard, including for a null raw address.
    (*vector).end = end.wrapping_add(4);
    if !end.is_null() {
        // `ldrne r1,[r1] ; strne r1,[r0]`: no source NULL guard.
        end.cast::<u32>().write(element.read());
    }
}

/// A `{base, count}` pointer array — the two words [`array_at_checked`]
/// reads. Addressed by field, so the count lands one word after the
/// base on both the 32-bit target and a 64-bit host.
#[repr(C)]
pub struct PtrArray {
    /// Contiguous array of element pointers.
    pub base: *mut *mut u8,
    /// Number of live elements. Signed in the original's compare.
    pub count: i32,
}

/// array_at_checked — original: `FUN_083d48dc` @ 0x083d48dc
/// (28 bytes; 40 `bl` call sites there, plus 3 at the byte-identical
/// copy 0x083d5500).
///
/// `index >= 0 && index < count ? base[index] : NULL`. Both tests are
/// **signed** (`cmp r1, #0` / `cmpge r2, r1` with a `gt`/`le` split), so
/// a negative index is rejected rather than wrapping into a huge
/// unsigned one — worth keeping, since the count is a plain `int`.
///
/// The original folds the whole thing into one predicated run with no
/// branches; `base` is loaded only on the in-range path.
///
/// # Safety
/// `array` must be readable; `base[index]` must be readable when the
/// index is in range.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn array_at_checked(array: *const PtrArray, index: i32) -> *mut u8 {
    if index < 0 || (*array).count <= index {
        return core::ptr::null_mut();
    }
    (*array).base.offset(index as isize).read()
}

/// pair_assign_guarded — original: `FUN_083dc0e0` @ 0x083dc0e0
/// (24 bytes; 14 `bl` call sites, the only copy).
///
/// The copy-assign of a two-word (8-byte) value type: when `src != dst`
/// the two words at `src` are copied to `dst`, otherwise nothing
/// happens — the textbook `if (this != &other)` self-assignment guard.
/// Unlike [`deque_iter_assign`]'s unconditional four-word copy this one
/// is fully predicated: the original is a single branchless run of
/// `cmp` + `ldrne`/`strne` pairs, returning with `dst` in r0 untouched.
///
/// Codegen deviation: LLVM emits the guard as a real branch instead of
/// predicated word copies; the structure (compare, guarded two-word
/// copy, return) is the same.
///
/// # Safety
/// `dst` and `src` must be valid, 4-byte aligned and 8 bytes wide when
/// they differ. When they are equal (or both NULL) nothing is touched.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pair_assign_guarded(dst: *mut u32, src: *const u32) -> *mut u32 {
    if src as *mut u32 != dst {
        dst.write(src.read());
        dst.add(1).write(src.add(1).read());
    }
    dst
}
/// vector_pair_copy_into — original: `FUN_083d7d10` @ 0x083d7d10
/// (16 bytes; 3 `bl` call sites).
///
/// Copies the opaque two-word pair stored as an 8-byte vector element into
/// `dst`. The caller at 0x080d1e38 passes the vector header in `r0`, an
/// insertion-slot iterator in `r1`, and a stack pair in `r2`; the vector
/// reallocation member @ 0x083e02a8 uses the same `(vector, slot, pair)`
/// shape at 0x083e02f0 and 0x083e0370. The pair fields are not identified,
/// but both source words are loaded before either destination word is stored,
/// matching `ldmne r2,{r1,r2}; stmne r0,{r1,r2}`.
///
/// The vector argument is ABI-required but ignored. A NULL destination is a
/// no-op and leaves the source unread. Although Ghidra declares `void`, the
/// opening `movs r0,r1` leaves `dst` in the return register on both paths.
///
/// # Safety
/// When `dst` is non-NULL, `dst` must be writable and `src` readable for two
/// aligned `u32` words. The original has no overlap guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_pair_copy_into(
    _vector: *const u8,
    dst: *mut u32,
    src: *const u32,
) -> *mut u32 {
    if !dst.is_null() {
        let first = src.read();
        let second = src.add(1).read();
        dst.write(first);
        dst.add(1).write(second);
    }
    dst
}

/// string_object_word_range_copy — original: `FUN_083e9b28` @ 0x083e9b28
/// (64 bytes; raw extent 0x083e9b28..0x083e9b68, with the next separately
/// linked function opening at 0x083e9b68). Seven direct `bl` call sites are
/// all unconditional: 0x083e8570, 0x083e85a8, 0x083e8688, 0x083e86ac,
/// 0x083e86c4, 0x083e86d8, and 0x083ea80c. One additional unconditional
/// tail `b` enters at 0x083ea820; no predicated calls target this body.
///
/// Copies the half-open `[first, last)` range of 12-byte
/// [`StringObjectWord`] records into initialized `output` storage. For each
/// record it calls the existing [`string_object_assign`] port on the leading
/// StringObject, copies the trailing word, advances both cursors one record,
/// and returns the final output cursor. The raw ARM has no NULL guard and
/// terminates solely on cursor equality.
///
/// The third word's semantic identity is not recovered; naming it
/// `trailing_word` records only the verified layout. There are no deliberate
/// deviations: the direct call remains a direct Rust call to the already
/// ported assignment operator, and typed iteration preserves the 12-byte ARM
/// stride without overlapping host pointer fields.
///
/// # Safety
///
/// `first` and `last` must delimit contiguous readable
/// [`StringObjectWord`] records. `output` must designate equally many valid,
/// initialized writable records. The StringObject assignment's payload and
/// virtual-method preconditions apply to every element; this routine has no
/// overlap guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_word_range_copy(
    mut first: *const StringObjectWord,
    last: *const StringObjectWord,
    mut output: *mut StringObjectWord,
) -> *mut StringObjectWord {
    while first != last {
        string_object_assign(
            core::ptr::addr_of_mut!((*output).string),
            core::ptr::addr_of!((*first).string),
        );
        (*output).trailing_word = (*first).trailing_word;
        first = first.add(1);
        output = output.add(1);
    }
    output
}
/// advance_string_object_word_cursor — original: `FUN_083ea988` @ 0x083ea988
/// (32 bytes; raw extent 0x083ea988..0x083ea9a8, with the separately linked
/// next function opening at 0x083ea9a8). Six direct `bl` call sites are all
/// unconditional: 0x083e85f0, 0x083e862c, 0x083e8704, 0x083e9854,
/// 0x083e9894, and 0x083e98dc; no predicated direct calls target this body.
///
/// Advances the target 32-bit cursor stored at `cursor` by
/// `element_count * 12` bytes, wrapping exactly as the ARM `add` and
/// shift-add sequence does. The callers use that stride for
/// [`StringObjectWord`] records.
///
/// The host-safe `u32` cursor deliberately represents the retailOS pointer
/// word rather than a native host pointer: this preserves the 32-bit ARM
/// arithmetic despite host pointer width. No firmware behavior is changed.
///
/// # Safety
///
/// `cursor` must be valid and aligned for one writable target pointer word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn advance_string_object_word_cursor(cursor: *mut u32, element_count: i32) {
    *cursor = (*cursor).wrapping_add((element_count as u32).wrapping_mul(12));
}

/// vector_copy_range_elem24 — original: `FUN_083e8ba0` @ 0x083e8ba0
/// (60 bytes, raw extent 0x083e8ba0..0x083e8bdc; 8 direct `bl` call
/// sites, all unconditional and none predicated).
///
/// Copies the half-open `[first, last)` range of aligned 24-byte vector
/// records into `output`, advancing both cursors by 24 bytes per record and
/// returning the resulting output cursor. The ARM loop predicates each
/// `memcpy` call on `output != NULL`; an initially NULL output skips the
/// first record only, then advances to the non-NULL address `0x18`.
///
/// Deliberate deviation: the raw `bl 0x08037df8` reaches the IRAM memcpy
/// veneer. This port calls its already-ported [`memcpy_forward_words`] body
/// through a volatile function pointer so LLVM retains that call rather than
/// replacing it with an inlined copy; its forward-copy semantics and 24-byte
/// alignment precondition are identical at this call site.
///
/// # Safety
///
/// `first` and `last` must delimit a range whose length is a multiple of 24.
/// When `output` is non-NULL, `first` must be readable and `output` writable
/// for that many bytes; both must be word-aligned. The original has no
/// overlap guard and performs forward copies. For exactly one record, a NULL
/// `output` is supported and leaves `first` unread.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_copy_range_elem24(
    mut first: *const u8,
    last: *const u8,
    mut output: *mut u8,
) -> *mut u8 {
    while first != last {
        if !output.is_null() {
            let copy = core::ptr::read_volatile(
                &(memcpy_forward_words as unsafe extern "C" fn(*mut u8, *const u8, usize) -> *mut u8),
            );
            copy(output, first, 24);
        }
        first = first.wrapping_add(24);
        output = output.wrapping_add(24);
    }
    output
}
/// An 8-byte vector record whose +5 byte is padding left untouched by the
/// retailOS copy assignment.
///
/// The raw transfer uses `ldr/str` at +0, `ldrb/strb` at +4, and
/// `ldrh/strh` at +6. Named fields retain those 32-bit-target offsets and
/// prevent host pointer width from creating an overlapping representation.
#[repr(C)]
pub struct VectorRecord8 {
    pub word: u32,
    pub byte: u8,
    pub padding: u8,
    pub halfword: u16,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 8] = [0; core::mem::size_of::<VectorRecord8>()];
#[cfg(target_pointer_width = "32")]
const _: [u8; 4] = [0; core::mem::offset_of!(VectorRecord8, byte)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 6] = [0; core::mem::offset_of!(VectorRecord8, halfword)];

/// vector_copy_range_record8 — original: `thunk_FUN_083e89fc` @ 0x083e89d0
/// (60 bytes; Ghidra reports 4).
///
/// Copies the non-padding fields of every 8-byte [`VectorRecord8`] in the
/// half-open `[first, last)` range into `output`, then returns the advanced
/// output cursor. The original's scheduled loop stores the word at +0, byte
/// at +4, and halfword at +6, deliberately leaving byte +5 unchanged. Its
/// five inbound direct calls are all unconditional plain `bl` at 0x083e0834,
/// 0x083e0884, 0x083e08f4, 0x083e0934, and 0x083e0a4c; decoding every aligned
/// ARM B/BL word in `osos.dec` finds no predicated calls or tail branches.
///
/// Ghidra splits the scheduled loop at 0x083e89fc and calls the four-byte
/// entry a thunk. Raw bytes show `b 0x083e89fc` at 0x083e89d0 enters this
/// function's compare header, whose backward `bne` reaches the body at
/// 0x083e89d4; `bx lr` at 0x083e8a08 and the next independent `push` at
/// 0x083e8a0c fix the complete 60-byte extent. There are no deliberate
/// deviations: `wrapping_add` preserves ARM cursor arithmetic, including the
/// one-record NULL-output path, where neither source nor output is read.
///
/// # Safety
///
/// `first` and `last` must delimit contiguous, aligned [`VectorRecord8`]
/// records. When `output` is non-NULL, it must designate writable records for
/// the same range. The original is a forward field copy with no overlap guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_copy_range_record8")]
#[inline(never)]
pub unsafe extern "C" fn vector_copy_range_record8(
    mut first: *const VectorRecord8,
    last: *const VectorRecord8,
    mut output: *mut VectorRecord8,
) -> *mut VectorRecord8 {
    while first != last {
        if !output.is_null() {
            (*output).word = (*first).word;
            (*output).byte = (*first).byte;
            (*output).halfword = (*first).halfword;
        }
        first = first.wrapping_add(1);
        output = output.wrapping_add(1);
    }
    output
}


/// vector_copy_range_u32 — original: `thunk_FUN_083e9430` @ 0x083e9418
/// (40 bytes; raw extent 0x083e9418..0x083e9440, with the separately linked
/// next function opening at 0x083e9440). Six direct `bl` call sites are all
/// unconditional: 0x083e65a4, 0x083e65e0, 0x083e6698, 0x083e66ec,
/// 0x083e676c, and 0x083e67ac; no predicated calls target this entry.
///
/// Copies the half-open `[first, last)` range of aligned 4-byte vector
/// elements into `output`, advancing both cursors by one word per element and
/// returning the resulting output cursor. The ARM loop predicates its load and
/// store on `output != NULL`; an initially NULL output skips only the first
/// source word, then advances to address 4.
///
/// Ghidra splits the scheduled ARM loop header at 0x083e9430 and calls the
/// four-byte entry at 0x083e9418 a thunk. Raw bytes show that entry branches
/// into its own compare/loop header, whose backward branch enters the loop
/// body at 0x083e941c; the 40-byte extent is one function. The unused r3
/// vector argument is omitted from the Rust ABI, as Ghidra also reports.
///
/// There are no deliberate behavior deviations: raw pointer wrapping preserves
/// the target's cursor arithmetic even for the supported one-word NULL-output
/// path.
///
/// # Safety
///
/// `first` and `last` must delimit contiguous, aligned readable `u32` words.
/// When `output` is non-NULL, it must be writable for the same number of
/// words. The original has no overlap guard and therefore copies forward.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_copy_range_u32(
    mut first: *const u32,
    last: *const u32,
    mut output: *mut u32,
) -> *mut u32 {
    while first != last {
        if !output.is_null() {
            output.write(first.read());
        }
        first = first.wrapping_add(1);
        output = output.wrapping_add(1);
    }
    output
}

/// vector_copy_range_u8 — original: `thunk_FUN_083e8ecc` @ 0x083e8eb4
/// (4-byte branch veneer; target body `FUN_083e8ecc` is 24 bytes at
/// 0x083e8ecc..0x083e8ee4). The next independently linked function starts
/// with `push {r4-r8,lr}` at 0x083e8ee4. Whole-image A32 decoding finds three
/// inbound direct plain `bl` calls and no predicated `bl` calls.
///
/// The veneer branches to a byte-wise forward copy of `[first,last)`, guarded
/// by the current output cursor: a NULL output skips both the source load and
/// destination store, but still advances both cursors and returns the advanced
/// output. Deliberate deviation: this export replaces the veneer with its
/// verified target body, and omits Ghidra's unused fourth argument.
///
/// # Safety
///
/// `first` and `last` must delimit a contiguous readable byte range. When
/// `output` is non-NULL, it must be writable for that range. The target copies
/// forward without overlap protection.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_copy_range_u8(
    mut first: *const u8,
    last: *const u8,
    mut output: *mut u8,
) -> *mut u8 {
    while first != last {
        if !output.is_null() {
            output.write(first.read());
        }
        first = first.wrapping_add(1);
        output = output.wrapping_add(1);
    }
    output
}


/// vector_copy_range_pair_u32 — original: `FUN_083e94b8` @ `0x083e94b8`
/// (44 bytes; raw extent `0x083e94b8..0x083e94e4`, with the separately linked
/// next function opening at `0x083e94e4`). Three inbound direct calls are
/// unconditional plain `bl`; there are no predicated `bl` calls.
///
/// Copies the half-open `[first, last)` range of eight-byte two-word vector
/// elements into `output`, advancing both cursors by one pair and returning
/// the resulting output cursor. The ARM loop predicates both source loads and
/// destination stores on `output != NULL`; a NULL output therefore advances
/// without reading `first`.
///
/// Raw words show a `push {lr}`, compare-header branch, two `ldrne`/`strne`
/// pairs, and `pop {pc}`. Ghidra's three-pointer signature is accurate; its
/// apparent function body begins at the true entry. There are no deliberate
/// deviations: wrapping cursor arithmetic preserves the target's NULL-output
/// cursor behavior and the copy remains forward-only.
///
/// # Safety
///
/// `first` and `last` must delimit contiguous, aligned readable two-word
/// elements. When `output` is non-NULL, it must be writable for the same
/// number of elements. The original has no overlap guard and copies forward.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_copy_range_pair_u32(
    mut first: *const [u32; 2],
    last: *const [u32; 2],
    mut output: *mut [u32; 2],
) -> *mut [u32; 2] {
    while first != last {
        if !output.is_null() {
            output.write(first.read());
        }
        first = first.wrapping_add(1);
        output = output.wrapping_add(1);
    }
    output
}

/// vector_copy_range_u32_alias_8f5c — original: `thunk_FUN_083e8f74`
/// @ 0x083e8f5c (40 bytes; raw extent 0x083e8f5c..0x083e8f84, bounded by
/// the separately linked `push {r4,r5,r6,lr}` at 0x083e8f84). Exactly four
/// direct `bl` call sites, all unconditional — 0x083e2aa8, 0x083e2afc,
/// 0x083e2b7c, and 0x083e2bbc — verified by decoding every ARM B/BL word
/// in `osos.dec`; no predicated calls and no direct tail branches target
/// this entry.
///
/// A byte-identical `vector_copy_range_u32` instantiation (the 40 bytes
/// match 0x083e9418 word for word): forward-copies the half-open
/// `[first, last)` range of aligned 4-byte vector elements into `output`
/// while the current output cursor is nonzero, advances both cursors by
/// one word per element, and returns the advanced output cursor. An
/// initially NULL output skips only the first source word, then advances
/// to address 4. Ghidra again splits the scheduled loop header at
/// 0x083e8f74 and labels the four-byte entry a thunk; the raw entry
/// branches into its own compare/loop header, so the 40-byte extent is
/// one function. r3 (the vector argument passed by all four callers) is
/// never read and is omitted from the Rust ABI.
///
/// Deliberate deviation: none beyond the alias itself. This distinct
/// export and text section keep the independently hookable retailOS
/// address from being folded into the byte-identical
/// [`vector_copy_range_u32`] body (the [`deque_iter_assign_alias_9fd4`]
/// precedent).
///
/// # Safety
///
/// `first` and `last` must delimit contiguous, aligned readable `u32`
/// words. When `output` is non-NULL, it must be writable for the same
/// number of words. The original has no overlap guard and therefore
/// copies forward.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_copy_range_u32_alias_8f5c")]
#[inline(never)]
pub unsafe extern "C" fn vector_copy_range_u32_alias_8f5c(
    mut first: *const u32,
    last: *const u32,
    mut output: *mut u32,
) -> *mut u32 {
    while first != last {
        if !output.is_null() {
            output.write(first.read());
        }
        first = first.wrapping_add(1);
        output = output.wrapping_add(1);
    }
    output
}

/// Firmware load address of `FUN_083d7e1c`, the 0x0c-byte element
/// copy-construct helper [`vector_copy_construct_range_elem12`] calls once
/// per element. Unported; dispatched through
/// [`VECTOR_COPY_CONSTRUCT_ELEM12_OPS`].
pub const VECTOR_COPY_CONSTRUCT_ELEM12_ADDRESS: usize = 0x083d_7e1c;

/// Indirect dispatch for the one unported callee of
/// [`vector_copy_construct_range_elem12`] (the
/// [`VECTOR_COPY_CONSTRUCT_ELEM32_OPS`] pattern): host tests install a
/// recording model; a later port of the helper replaces the default without
/// touching this caller.
#[derive(Clone, Copy)]
pub struct VectorCopyConstructElem12Ops {
    /// Helper 0x083d7e1c `(vector, output, source)`: copy-constructs the
    /// 0x0c-byte element at `source` into `output` (the plain words at
    /// +0x00 and +0x04, then the byte at +0x08 masked to its low bit — a
    /// `bool` field), skipping all construction when `output` is NULL
    /// (`movs r0, r1; bxeq lr` at the head). Its return value is unused by
    /// the caller; `vector` is forwarded verbatim from the range function's
    /// r3 although the observed helper never reads its r0 (its first
    /// instruction overwrites r0 with r1).
    pub copy_construct: unsafe extern "C" fn(
        vector: *mut VectorStorage,
        output: *mut u8,
        source: *const u8,
    ),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_copy_construct_elem12(
    vector: *mut VectorStorage,
    output: *mut u8,
    source: *const u8,
) {
    let f: unsafe extern "C" fn(*mut VectorStorage, *mut u8, *const u8) =
        core::mem::transmute(VECTOR_COPY_CONSTRUCT_ELEM12_ADDRESS);
    f(vector, output, source)
}

/// Host default: inert — every test installs its own model.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_copy_construct_elem12(
    _vector: *mut VectorStorage,
    _output: *mut u8,
    _source: *const u8,
) {
}

pub const DEFAULT_VECTOR_COPY_CONSTRUCT_ELEM12_OPS: VectorCopyConstructElem12Ops =
    VectorCopyConstructElem12Ops {
        copy_construct: firmware_copy_construct_elem12,
    };

pub static mut VECTOR_COPY_CONSTRUCT_ELEM12_OPS: VectorCopyConstructElem12Ops =
    DEFAULT_VECTOR_COPY_CONSTRUCT_ELEM12_OPS;

fn vector_copy_construct_elem12_ops() -> VectorCopyConstructElem12Ops {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(VECTOR_COPY_CONSTRUCT_ELEM12_OPS)) }
}

/// vector_copy_construct_range_elem12 — original: `FUN_083e8f1c` @
/// 0x083e8f1c (64 bytes; extent 0x083e8f1c..0x083e8f5c, bounded by the
/// `b 0x083e8f74` entry of [`vector_copy_range_u32_alias_8f5c`] at
/// 0x083e8f5c; reference
/// `ipod-decomp/decomp/c/038/083e8f1c_FUN_083e8f1c.c`).
///
/// `std::vector<T>` uninitialized-copy over a range of 0x0c-byte elements
/// (a record of two plain words at +0x00/+0x04 and a `bool` at +0x08 —
/// the layout its per-element helper 0x083d7e1c constructs). Word-for-word
/// twin of `vector_copy_construct_range_elem16` with 0x0c strides:
///
/// ```text
/// 083e8f1c  push {r4, r5, r6, r7, r8, lr}
/// 083e8f20  mov  r7, r3           ; vector (dead in the helper, forwarded)
/// 083e8f24  mov  r6, r1           ; last
/// 083e8f28  mov  r5, r2           ; output cursor
/// 083e8f2c  mov  r4, r0           ; source cursor
/// 083e8f30  b    test
/// loop:
/// 083e8f34  mov  r2, r4
/// 083e8f38  mov  r1, r5
/// 083e8f3c  mov  r0, r7
/// 083e8f40  bl   0x083d7e1c       ; element copy-construct(vector, out, src)
/// 083e8f44  add  r4, r4, #0xc
/// 083e8f48  add  r5, r5, #0xc
/// test:
/// 083e8f4c  cmp  r4, r6
/// 083e8f50  bne  loop
/// 083e8f54  mov  r0, r5           ; return advanced output
/// 083e8f58  pop  {r4, r5, r6, r7, r8, pc}
/// ```
///
/// **Call count**, verified by decoding every B/BL word in osos.dec:
/// exactly four inbound direct `bl` sites (0x083e2794, 0x083e2808,
/// 0x083e2898, 0x083e28ec), all unconditional; no predicated calls target
/// this entry. The body itself contains one plain `bl` (to 0x083d7e1c)
/// and no predicated calls; its only other branch is the `bne` back-edge.
/// Ghidra reports the 64-byte size correctly and its C matches this decode.
///
/// The loop terminates on cursor EQUALITY (`cmp r4, r6; bne`), not a
/// less-than bound, matching every caller's whole-element ranges; the
/// helper's return value is discarded and the advanced output cursor is
/// returned whether or not any construction happened (the NULL-output
/// guard lives inside the helper, not here).
///
/// # Deviations
///
/// The element helper `FUN_083d7e1c` is unported and dispatches through
/// [`VECTOR_COPY_CONSTRUCT_ELEM12_OPS`]: target builds transmute
/// [`VECTOR_COPY_CONSTRUCT_ELEM12_ADDRESS`], the host default is inert and
/// every test installs a recording model.
///
/// # Safety
/// `first` and `last` must delimit a whole number of contiguous readable
/// 0x0c-byte elements; `output` must be writable for the same number of
/// elements whenever the installed helper writes. `vector` is passed
/// through untouched.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_copy_construct_range_elem12(
    mut first: *const u8,
    last: *const u8,
    mut output: *mut u8,
    vector: *mut VectorStorage,
) -> *mut u8 {
    while first != last {
        (vector_copy_construct_elem12_ops().copy_construct)(vector, output, first);
        first = first.wrapping_add(0x0c);
        output = output.wrapping_add(0x0c);
    }
    output
}

/// Firmware load address of `FUN_083d7f2c`, the 0x20-byte element
/// copy-construct helper [`vector_copy_construct_range_elem32`] calls once
/// per element. Unported (its own StringObject copy-constructor chain
/// 0x082773e0 and allocating callee 0x08266c70 are not ported either);
/// dispatched through [`VECTOR_COPY_CONSTRUCT_ELEM32_OPS`].
pub const VECTOR_COPY_CONSTRUCT_ELEM32_ADDRESS: usize = 0x083d_7f2c;

/// Indirect dispatch for the one unported callee of
/// [`vector_copy_construct_range_elem32`] (the
/// [`VECTOR_PUSH_BACK_ELEM12_OPS`] pattern): host tests install a recording
/// model; a later port of the helper replaces the default without touching
/// this caller.
#[derive(Clone, Copy)]
pub struct VectorCopyConstructElem32Ops {
    /// Helper 0x083d7f2c `(vector, output, source)`: copy-constructs the
    /// 0x20-byte element at `source` into `output` (StringObject copy
    /// constructor on the head, then the trailing fields), skipping all
    /// construction when `output` is NULL. Its return value is unused by
    /// the caller; `vector` is forwarded verbatim from the range
    /// function's r3 although the observed helper never reads its r0
    /// (its first instruction overwrites r0 with r1).
    pub copy_construct: unsafe extern "C" fn(
        vector: *mut VectorStorage,
        output: *mut u8,
        source: *const u8,
    ),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_copy_construct_elem32(
    vector: *mut VectorStorage,
    output: *mut u8,
    source: *const u8,
) {
    let f: unsafe extern "C" fn(*mut VectorStorage, *mut u8, *const u8) =
        core::mem::transmute(VECTOR_COPY_CONSTRUCT_ELEM32_ADDRESS);
    f(vector, output, source)
}

/// Host default: inert — every test installs its own model.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_copy_construct_elem32(
    _vector: *mut VectorStorage,
    _output: *mut u8,
    _source: *const u8,
) {
}

/// Wired default: the ROM address on target, a documented inert stub on
/// host.
pub const DEFAULT_VECTOR_COPY_CONSTRUCT_ELEM32_OPS: VectorCopyConstructElem32Ops =
    VectorCopyConstructElem32Ops {
        copy_construct: firmware_copy_construct_elem32,
    };

/// The active callee, read through `read_volatile` so LLVM cannot fold
/// the indirect call to the default.
pub static mut VECTOR_COPY_CONSTRUCT_ELEM32_OPS: VectorCopyConstructElem32Ops =
    DEFAULT_VECTOR_COPY_CONSTRUCT_ELEM32_OPS;

#[inline(always)]
fn vector_copy_construct_elem32_ops() -> VectorCopyConstructElem32Ops {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(VECTOR_COPY_CONSTRUCT_ELEM32_OPS)) }
}

/// vector_copy_construct_range_elem32 — original: `FUN_083e90f8` @
/// 0x083e90f8 (64 bytes; extent 0x083e90f8..0x083e9138, the next function
/// opening `b 0x083e9150` at 0x083e9138; reference
/// `ipod-decomp/decomp/c/038/083e90f8_FUN_083e90f8.c`).
///
/// `std::vector<T>` uninitialized-copy over a range of 0x20-byte elements
/// (a record headed by a StringObject with an embedded vector at +0x0c —
/// the layout its per-element helper 0x083d7f2c constructs):
///
/// ```text
/// 083e90f8  push {r4, r5, r6, r7, r8, lr}
/// 083e90fc  mov  r7, r3           ; vector (dead in the helper, forwarded)
/// 083e9100  mov  r6, r1           ; last
/// 083e9104  mov  r5, r2           ; output cursor
/// 083e9108  mov  r4, r0           ; source cursor
/// 083e910c  b    test
/// loop:
/// 083e9110  mov  r2, r4
/// 083e9114  mov  r1, r5
/// 083e9118  mov  r0, r7
/// 083e911c  bl   0x083d7f2c       ; element copy-construct(vector, out, src)
/// 083e9120  add  r4, r4, #0x20
/// 083e9124  add  r5, r5, #0x20
/// test:
/// 083e9128  cmp  r4, r6
/// 083e912c  bne  loop
/// 083e9130  mov  r0, r5           ; return advanced output
/// 083e9134  pop  {r4, r5, r6, r7, r8, pc}
/// ```
///
/// **Call count**, verified by decoding every B/BL word in osos.dec:
/// exactly four inbound direct `bl` sites (0x083e3f34, 0x083e3fa0,
/// 0x083e402c, 0x083e406c — the vector reallocation paths of
/// `FUN_083e3ed0`), all unconditional; no predicated calls target this
/// entry. The body itself contains one plain `bl` (to 0x083d7f2c) and no
/// predicated calls; its only other branch is the `bne` back-edge. Ghidra
/// reports the 64-byte size correctly and its C matches this decode.
///
/// The loop terminates on cursor EQUALITY (`cmp r4, r6; bne`), not a
/// less-than bound, matching every caller's whole-element ranges; the
/// helper's return value is discarded and the advanced output cursor is
/// returned whether or not any construction happened (the NULL-output
/// guard lives inside the helper, not here).
///
/// # Deviations
///
/// The element helper `FUN_083d7f2c` is unported and dispatches through
/// [`VECTOR_COPY_CONSTRUCT_ELEM32_OPS`]: target builds transmute
/// [`VECTOR_COPY_CONSTRUCT_ELEM32_ADDRESS`], the host default is inert and
/// every test installs a recording model.
///
/// # Safety
/// `first` and `last` must delimit a whole number of contiguous readable
/// 0x20-byte elements; `output` must be writable for the same number of
/// elements whenever the installed helper writes. `vector` is passed
/// through untouched.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_copy_construct_range_elem32(
    mut first: *const u8,
    last: *const u8,
    mut output: *mut u8,
    vector: *mut VectorStorage,
) -> *mut u8 {
    while first != last {
        (vector_copy_construct_elem32_ops().copy_construct)(vector, output, first);
        first = first.wrapping_add(0x20);
        output = output.wrapping_add(0x20);
    }
    output
}

/// Firmware load address of `FUN_083d7ec0`, the 0x10-byte element
/// copy-construct helper [`vector_copy_construct_range_elem16`] calls once
/// per element. Unported (its StringObject copy-constructor chain callee
/// 0x082773e0 is not ported either); dispatched through
/// [`VECTOR_COPY_CONSTRUCT_ELEM16_OPS`].
pub const VECTOR_COPY_CONSTRUCT_ELEM16_ADDRESS: usize = 0x083d_7ec0;

/// Indirect dispatch for the one unported callee of
/// [`vector_copy_construct_range_elem16`] (the
/// [`VECTOR_COPY_CONSTRUCT_ELEM32_OPS`] pattern): host tests install a
/// recording model; a later port of the helper replaces the default without
/// touching this caller.
#[derive(Clone, Copy)]
pub struct VectorCopyConstructElem16Ops {
    /// Helper 0x083d7ec0 `(vector, output, source)`: copy-constructs the
    /// 0x10-byte element at `source` into `output` (two adjacent StringObject
    /// copy constructions at +0x00 and +0x08), skipping all construction when
    /// `output` is NULL (`movs r0, r1; popeq {r4, pc}` at the head). Its
    /// return value is unused by the caller; `vector` is forwarded verbatim
    /// from the range function's r3 although the observed helper never reads
    /// its r0 (its first instructions overwrite r0 with r1).
    pub copy_construct: unsafe extern "C" fn(
        vector: *mut VectorStorage,
        output: *mut u8,
        source: *const u8,
    ),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_copy_construct_elem16(
    vector: *mut VectorStorage,
    output: *mut u8,
    source: *const u8,
) {
    let f: unsafe extern "C" fn(*mut VectorStorage, *mut u8, *const u8) =
        core::mem::transmute(VECTOR_COPY_CONSTRUCT_ELEM16_ADDRESS);
    f(vector, output, source)
}

/// Host default: inert — every test installs its own model.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_copy_construct_elem16(
    _vector: *mut VectorStorage,
    _output: *mut u8,
    _source: *const u8,
) {
}

pub const DEFAULT_VECTOR_COPY_CONSTRUCT_ELEM16_OPS: VectorCopyConstructElem16Ops =
    VectorCopyConstructElem16Ops {
        copy_construct: firmware_copy_construct_elem16,
    };

pub static mut VECTOR_COPY_CONSTRUCT_ELEM16_OPS: VectorCopyConstructElem16Ops =
    DEFAULT_VECTOR_COPY_CONSTRUCT_ELEM16_OPS;

fn vector_copy_construct_elem16_ops() -> VectorCopyConstructElem16Ops {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(VECTOR_COPY_CONSTRUCT_ELEM16_OPS)) }
}

/// vector_copy_construct_range_elem16 — original: `FUN_083e9078` @
/// 0x083e9078 (64 bytes; extent 0x083e9078..0x083e90b8, bounded by the
/// `push {r4-r8, lr}` of [`vector_copy_construct_range_elem28`] at
/// 0x083e90b8; reference
/// `ipod-decomp/decomp/c/038/083e9078_FUN_083e9078.c`).
///
/// `std::vector<T>` uninitialized-copy over a range of 0x10-byte elements
/// (a record of two adjacent StringObjects at +0x00 and +0x08 — the layout
/// its per-element helper 0x083d7ec0 constructs, one StringObject copy
/// construction per 8 bytes through the chain at 0x082773e0). Word-for-word
/// twin of `vector_copy_construct_range_elem28` with 0x10 strides:
///
/// ```text
/// 083e9078  push {r4, r5, r6, r7, r8, lr}
/// 083e907c  mov  r7, r3           ; vector (dead in the helper, forwarded)
/// 083e9080  mov  r6, r1           ; last
/// 083e9084  mov  r5, r2           ; output cursor
/// 083e9088  mov  r4, r0           ; source cursor
/// 083e908c  b    test
/// loop:
/// 083e9090  mov  r2, r4
/// 083e9094  mov  r1, r5
/// 083e9098  mov  r0, r7
/// 083e909c  bl   0x083d7ec0       ; element copy-construct(vector, out, src)
/// 083e90a0  add  r4, r4, #0x10
/// 083e90a4  add  r5, r5, #0x10
/// test:
/// 083e90a8  cmp  r4, r6
/// 083e90ac  bne  loop
/// 083e90b0  mov  r0, r5           ; return advanced output
/// 083e90b4  pop  {r4, r5, r6, r7, r8, pc}
/// ```
///
/// **Call count**, verified by decoding every B/BL word in osos.dec:
/// exactly four inbound direct `bl` sites (0x083e392c, 0x083e3984,
/// 0x083e3a04, 0x083e3a44), all unconditional; no predicated calls target
/// this entry. The body itself contains one plain `bl` (to 0x083d7ec0)
/// and no predicated calls; its only other branch is the `bne` back-edge.
/// Ghidra reports the 64-byte size correctly and its C matches this decode.
///
/// The loop terminates on cursor EQUALITY (`cmp r4, r6; bne`), not a
/// less-than bound, matching every caller's whole-element ranges; the
/// helper's return value is discarded and the advanced output cursor is
/// returned whether or not any construction happened (the NULL-output
/// guard lives inside the helper, not here).
///
/// # Deviations
///
/// The element helper `FUN_083d7ec0` is unported and dispatches through
/// [`VECTOR_COPY_CONSTRUCT_ELEM16_OPS`]: target builds transmute
/// [`VECTOR_COPY_CONSTRUCT_ELEM16_ADDRESS`], the host default is inert and
/// every test installs a recording model.
///
/// # Safety
/// `first` and `last` must delimit a whole number of contiguous readable
/// 0x10-byte elements; `output` must be writable for the same number of
/// elements whenever the installed helper writes. `vector` is passed
/// through untouched.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_copy_construct_range_elem16(
    mut first: *const u8,
    last: *const u8,
    mut output: *mut u8,
    vector: *mut VectorStorage,
) -> *mut u8 {
    while first != last {
        (vector_copy_construct_elem16_ops().copy_construct)(vector, output, first);
        first = first.wrapping_add(0x10);
        output = output.wrapping_add(0x10);
    }
    output
}
/// vector_copy_construct_range_string_pair — original: `FUN_083e8dfc` @
/// 0x083e8dfc (72 bytes; true extent 0x083e8dfc..0x083e8e44, bounded by the
/// next `push {r4, r5, r6, lr}` at 0x083e8e44; reference
/// `ipod-decomp/decomp/c/038/083e8dfc_FUN_083e8dfc.c`).
///
/// `std::vector<T>` uninitialized-copy over a half-open range of 0x10-byte
/// elements, each a pair of adjacent 0x08-byte StringObjects. For every
/// element it calls the StringObject copy constructor at +0, then at +8,
/// advancing both cursors by 0x10 and returning the advanced output cursor.
/// The output-null check is deliberately per element: a NULL output skips both
/// constructors but still advances both cursors.
/// ported `string_object_copy_construct` @ 0x082773e0, and no predicated
/// calls. Ghidra's 72-byte extent and C loop match the raw decode; the three
/// reported call sites are inbound, rather than a third body call.
///
/// # Deviations
///
/// None on target: both direct calls use the ported callee. Host pointers are
/// wider than retailOS fields, so the host test inspects the 0x10-byte cursor
/// protocol through aligned word storage rather than treating two host
/// `StringObject` values as a 16-byte retail pair.
///
/// # Safety
///
/// `first` and `last` must delimit a whole number of contiguous 0x10-byte
/// StringObject-pair elements. When `output` is non-NULL, it must be writable
/// for the same number of elements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_copy_construct_range_string_pair(
    mut first: *const u8,
    last: *const u8,
    mut output: *mut u8,
) -> *mut u8 {
    while first != last {
        if !output.is_null() {
            string_object_copy_construct(output.cast::<StringObject>(), first.cast::<StringObject>());
            string_object_copy_construct(
                output.add(8).cast::<StringObject>(),
                first.add(8).cast::<StringObject>(),
            );
        }
        first = first.wrapping_add(0x10);
        output = output.wrapping_add(0x10);
    }
    output
}


/// Firmware load address of `FUN_083d7df4`, the 0x10-byte element
/// copy-construct helper [`vector_copy_construct_range_elem16_alt`] calls
/// once per element. Unported (it forwards through the 4-byte-stride range
/// loop whose test entry sits at 0x083e8c30 and tail-branches to
/// 0x083e5b00, neither ported); dispatched through
/// [`VECTOR_COPY_CONSTRUCT_ELEM16_ALT_OPS`].
pub const VECTOR_COPY_CONSTRUCT_ELEM16_ALT_ADDRESS: usize = 0x083d_7df4;

/// Indirect dispatch for the one unported callee of
/// [`vector_copy_construct_range_elem16_alt`] (the
/// [`VECTOR_COPY_CONSTRUCT_ELEM16_OPS`] pattern): host tests install a
/// recording model; a later port of the helper replaces the default without
/// touching this caller.
#[derive(Clone, Copy)]
pub struct VectorCopyConstructElem16AltOps {
    /// Helper 0x083d7df4 `(vector, output, source)`: copy-constructs the
    /// element at `source` into `output`, skipping all construction when
    /// `output` is NULL (`movs r0, r1; popeq {r4, pc}` at the head). Its
    /// return value is unused by the caller; `vector` is forwarded verbatim
    /// from the range function's r3 although the observed helper never reads
    /// its r0 (its first instruction overwrites r0 with r1).
    pub copy_construct: unsafe extern "C" fn(
        vector: *mut VectorStorage,
        output: *mut u8,
        source: *const u8,
    ),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_copy_construct_elem16_alt(
    vector: *mut VectorStorage,
    output: *mut u8,
    source: *const u8,
) {
    let f: unsafe extern "C" fn(*mut VectorStorage, *mut u8, *const u8) =
        core::mem::transmute(VECTOR_COPY_CONSTRUCT_ELEM16_ALT_ADDRESS);
    f(vector, output, source)
}

/// Host default: inert — every test installs its own model.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_copy_construct_elem16_alt(
    _vector: *mut VectorStorage,
    _output: *mut u8,
    _source: *const u8,
) {
}

/// Wired default: the ROM address on target, a documented inert stub on
/// host.
pub const DEFAULT_VECTOR_COPY_CONSTRUCT_ELEM16_ALT_OPS: VectorCopyConstructElem16AltOps =
    VectorCopyConstructElem16AltOps {
        copy_construct: firmware_copy_construct_elem16_alt,
    };

/// The active callee, read through `read_volatile` so LLVM cannot fold
/// the indirect call to the default.
pub static mut VECTOR_COPY_CONSTRUCT_ELEM16_ALT_OPS: VectorCopyConstructElem16AltOps =
    DEFAULT_VECTOR_COPY_CONSTRUCT_ELEM16_ALT_OPS;

#[inline(always)]
fn vector_copy_construct_elem16_alt_ops() -> VectorCopyConstructElem16AltOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(VECTOR_COPY_CONSTRUCT_ELEM16_ALT_OPS)) }
}

/// vector_copy_construct_range_elem16_alt — original: `FUN_083e8cb0` @
/// 0x083e8cb0 (64 bytes; extent 0x083e8cb0..0x083e8cf0, bounded by the
/// `push {r4, r5, r6, lr}` of the next function at 0x083e8cf0).
///
/// `std::vector<T>` uninitialized-copy over a range of 0x10-byte elements.
/// Word-for-word twin of [`vector_copy_construct_range_elem16`] except its
/// per-element helper is 0x083d7df4 instead of 0x083d7ec0 (the helper
/// differs: it drives a 4-byte-stride copy chain rather than two StringObject
/// constructions, so this is a distinct element type on the same stride):
///
/// ```text
/// 083e8cb0  push {r4, r5, r6, r7, r8, lr}
/// 083e8cb4  mov  r7, r3           ; vector (dead in the helper, forwarded)
/// 083e8cb8  mov  r6, r1           ; last
/// 083e8cbc  mov  r5, r2           ; output cursor
/// 083e8cc0  mov  r4, r0           ; source cursor
/// 083e8cc4  b    test
/// loop:
/// 083e8cc8  mov  r2, r4
/// 083e8ccc  mov  r1, r5
/// 083e8cd0  mov  r0, r7
/// 083e8cd4  bl   0x083d7df4       ; element copy-construct(vector, out, src)
/// 083e8cd8  add  r4, r4, #0x10
/// 083e8cdc  add  r5, r5, #0x10
/// test:
/// 083e8ce0  cmp  r4, r6
/// 083e8ce4  bne  loop
/// 083e8ce8  mov  r0, r5           ; return advanced output
/// 083e8cec  pop  {r4, r5, r6, r7, r8, pc}
/// ```
///
/// **Call count**, verified by decoding every B/BL word in osos.dec:
/// exactly four inbound direct `bl` sites (0x08197bf8, 0x083c1610,
/// 0x083e2634, 0x083e2714), all unconditional; no predicated calls target
/// this entry. The body itself contains one plain `bl` (to 0x083d7df4) and
/// no predicated calls; its only other branches are the `b` to the loop
/// test and the `bne` back-edge. Ghidra's 64-byte size matches this decode.
///
/// The loop terminates on cursor EQUALITY (`cmp r4, r6; bne`), not a
/// less-than bound, matching every caller's whole-element ranges; the
/// helper's return value is discarded and the advanced output cursor is
/// returned whether or not any construction happened (the NULL-output
/// guard lives inside the helper, not here).
///
/// # Deviations
///
/// The element helper `FUN_083d7df4` is unported and dispatches through
/// [`VECTOR_COPY_CONSTRUCT_ELEM16_ALT_OPS`]: target builds transmute
/// [`VECTOR_COPY_CONSTRUCT_ELEM16_ALT_ADDRESS`], the host default is inert
/// and every test installs a recording model.
///
/// # Safety
/// `first` and `last` must delimit a whole number of contiguous readable
/// 0x10-byte elements; `output` must be writable for the same number of
/// elements whenever the installed helper writes. `vector` is passed
/// through untouched.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_copy_construct_range_elem16_alt(
    mut first: *const u8,
    last: *const u8,
    mut output: *mut u8,
    vector: *mut VectorStorage,
) -> *mut u8 {
    while first != last {
        (vector_copy_construct_elem16_alt_ops().copy_construct)(vector, output, first);
        first = first.wrapping_add(0x10);
        output = output.wrapping_add(0x10);
    }
    output
}

/// Firmware load address of `FUN_083d7ee8`, the 0x1c-byte element
/// copy-construct helper [`vector_copy_construct_range_elem28`] calls once
/// per element. Unported (its StringObject copy-constructor chain callee
/// 0x082773e0 is not ported either); dispatched through
/// [`VECTOR_COPY_CONSTRUCT_ELEM28_OPS`].
pub const VECTOR_COPY_CONSTRUCT_ELEM28_ADDRESS: usize = 0x083d_7ee8;

/// Indirect dispatch for the one unported callee of
/// [`vector_copy_construct_range_elem28`] (the
/// [`VECTOR_COPY_CONSTRUCT_ELEM32_OPS`] pattern): host tests install a
/// recording model; a later port of the helper replaces the default without
/// touching this caller.
#[derive(Clone, Copy)]
pub struct VectorCopyConstructElem28Ops {
    /// Helper 0x083d7ee8 `(vector, output, source)`: copy-constructs the
    /// 0x1c-byte element at `source` into `output` (three plain words at
    /// +0x00, a StringObject copy construction at +0x0c, then the tail at
    /// +0x14), skipping all construction when `output` is NULL
    /// (`movs r0, r1; popeq {r4, pc}` at the head). Its return value is
    /// unused by the caller; `vector` is forwarded verbatim from the range
    /// function's r3 although the observed helper never reads its r0 (its
    /// first instruction overwrites r0 with r1).
    pub copy_construct: unsafe extern "C" fn(
        vector: *mut VectorStorage,
        output: *mut u8,
        source: *const u8,
    ),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_copy_construct_elem28(
    vector: *mut VectorStorage,
    output: *mut u8,
    source: *const u8,
) {
    let f: unsafe extern "C" fn(*mut VectorStorage, *mut u8, *const u8) =
        core::mem::transmute(VECTOR_COPY_CONSTRUCT_ELEM28_ADDRESS);
    f(vector, output, source)
}

/// Host default: inert — every test installs its own model.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_copy_construct_elem28(
    _vector: *mut VectorStorage,
    _output: *mut u8,
    _source: *const u8,
) {
}

/// Wired default: the ROM address on target, a documented inert stub on
/// host.
pub const DEFAULT_VECTOR_COPY_CONSTRUCT_ELEM28_OPS: VectorCopyConstructElem28Ops =
    VectorCopyConstructElem28Ops {
        copy_construct: firmware_copy_construct_elem28,
    };

/// The active callee, read through `read_volatile` so LLVM cannot fold
/// the indirect call to the default.
pub static mut VECTOR_COPY_CONSTRUCT_ELEM28_OPS: VectorCopyConstructElem28Ops =
    DEFAULT_VECTOR_COPY_CONSTRUCT_ELEM28_OPS;

#[inline(always)]
fn vector_copy_construct_elem28_ops() -> VectorCopyConstructElem28Ops {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(VECTOR_COPY_CONSTRUCT_ELEM28_OPS)) }
}

/// vector_copy_construct_range_elem28 — original: `FUN_083e90b8` @
/// 0x083e90b8 (64 bytes; extent 0x083e90b8..0x083e90f8, bounded by the
/// `push {r4-r8, lr}` of [`vector_copy_construct_range_elem32`] at
/// 0x083e90f8; reference
/// `ipod-decomp/decomp/c/038/083e90b8_FUN_083e90b8.c`).
///
/// `std::vector<T>` uninitialized-copy over a range of 0x1c-byte elements
/// (a record of three plain words followed by a StringObject at +0x0c and
/// an 8-byte tail at +0x14 — the layout its per-element helper 0x083d7ee8
/// constructs). Word-for-word twin of `vector_copy_construct_range_elem32`
/// with 0x1c strides:
///
/// ```text
/// 083e90b8  push {r4, r5, r6, r7, r8, lr}
/// 083e90bc  mov  r7, r3           ; vector (dead in the helper, forwarded)
/// 083e90c0  mov  r6, r1           ; last
/// 083e90c4  mov  r5, r2           ; output cursor
/// 083e90c8  mov  r4, r0           ; source cursor
/// 083e90cc  b    test
/// loop:
/// 083e90d0  mov  r2, r4
/// 083e90d4  mov  r1, r5
/// 083e90d8  mov  r0, r7
/// 083e90dc  bl   0x083d7ee8       ; element copy-construct(vector, out, src)
/// 083e90e0  add  r4, r4, #0x1c
/// 083e90e4  add  r5, r5, #0x1c
/// test:
/// 083e90e8  cmp  r4, r6
/// 083e90ec  bne  loop
/// 083e90f0  mov  r0, r5           ; return advanced output
/// 083e90f4  pop  {r4, r5, r6, r7, r8, pc}
/// ```
///
/// **Call count**, verified by decoding every B/BL word in osos.dec:
/// exactly four inbound direct `bl` sites (0x083e3cec, 0x083e3d60,
/// 0x083e3df0, 0x083e3e44), all unconditional; no predicated calls target
/// this entry. The body itself contains one plain `bl` (to 0x083d7ee8)
/// and no predicated calls; its only other branch is the `bne` back-edge.
/// Ghidra reports the 64-byte size correctly and its C matches this decode.
///
/// The loop terminates on cursor EQUALITY (`cmp r4, r6; bne`), not a
/// less-than bound, matching every caller's whole-element ranges; the
/// helper's return value is discarded and the advanced output cursor is
/// returned whether or not any construction happened (the NULL-output
/// guard lives inside the helper, not here).
///
/// # Deviations
///
/// The element helper `FUN_083d7ee8` is unported and dispatches through
/// [`VECTOR_COPY_CONSTRUCT_ELEM28_OPS`]: target builds transmute
/// [`VECTOR_COPY_CONSTRUCT_ELEM28_ADDRESS`], the host default is inert and
/// every test installs a recording model.
///
/// # Safety
/// `first` and `last` must delimit a whole number of contiguous readable
/// 0x1c-byte elements; `output` must be writable for the same number of
/// elements whenever the installed helper writes. `vector` is passed
/// through untouched.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_copy_construct_range_elem28(
    mut first: *const u8,
    last: *const u8,
    mut output: *mut u8,
    vector: *mut VectorStorage,
) -> *mut u8 {
    while first != last {
        (vector_copy_construct_elem28_ops().copy_construct)(vector, output, first);
        first = first.wrapping_add(0x1c);
        output = output.wrapping_add(0x1c);
    }
    output
}

/// Firmware load address of `FUN_083d7d20`, the 0x14-byte element
/// copy-construct helper [`vector_copy_construct_range_elem20`] calls once
/// per element. Unported; dispatched through
/// [`VECTOR_COPY_CONSTRUCT_ELEM20_OPS`].
pub const VECTOR_COPY_CONSTRUCT_ELEM20_ADDRESS: usize = 0x083d_7d20;

/// Indirect dispatch for the one unported callee of
/// [`vector_copy_construct_range_elem20`] (the
/// [`VECTOR_COPY_CONSTRUCT_ELEM28_OPS`] pattern): host tests install a
/// recording model; a later port of the helper replaces the default without
/// touching this caller.
#[derive(Clone, Copy)]
pub struct VectorCopyConstructElem20Ops {
    /// Helper 0x083d7d20 `(vector, output, source)`: copy-constructs the
    /// 0x14-byte element at `source` into `output`, skipping all
    /// construction when `output` is NULL (`movs r0, r1; beq` at the head).
    /// Raw ARM shows it loads a pooled base pointer, stores `output` at
    /// base+0x00, copies the source word at +0x04 there, and zeroes the
    /// two words at +0x08/+0x0c; the full element type is not recovered.
    /// Its return value is unused by the caller; `vector` is forwarded
    /// verbatim from the range function's r3.
    pub copy_construct: unsafe extern "C" fn(
        vector: *mut VectorStorage,
        output: *mut u8,
        source: *const u8,
    ),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_copy_construct_elem20(
    vector: *mut VectorStorage,
    output: *mut u8,
    source: *const u8,
) {
    let f: unsafe extern "C" fn(*mut VectorStorage, *mut u8, *const u8) =
        core::mem::transmute(VECTOR_COPY_CONSTRUCT_ELEM20_ADDRESS);
    f(vector, output, source)
}

/// Host default: inert — every test installs its own model.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_copy_construct_elem20(
    _vector: *mut VectorStorage,
    _output: *mut u8,
    _source: *const u8,
) {
}

/// Wired default: the ROM address on target, a documented inert stub on
/// host.
pub const DEFAULT_VECTOR_COPY_CONSTRUCT_ELEM20_OPS: VectorCopyConstructElem20Ops =
    VectorCopyConstructElem20Ops {
        copy_construct: firmware_copy_construct_elem20,
    };

/// The active callee, read through `read_volatile` so LLVM cannot fold
/// the indirect call to the default.
pub static mut VECTOR_COPY_CONSTRUCT_ELEM20_OPS: VectorCopyConstructElem20Ops =
    DEFAULT_VECTOR_COPY_CONSTRUCT_ELEM20_OPS;

#[inline(always)]
fn vector_copy_construct_elem20_ops() -> VectorCopyConstructElem20Ops {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(VECTOR_COPY_CONSTRUCT_ELEM20_OPS)) }
}

/// vector_copy_construct_range_elem20 — original: `FUN_083e8afc` @
/// 0x083e8afc (64 bytes; extent 0x083e8afc..0x083e8b3c, bounded by the
/// `push {r4, r5, r6, lr}` of the next function at 0x083e8b3c; reference
/// `ipod-decomp/decomp/c/038/083e8afc_FUN_083e8afc.c`).
///
/// `std::vector<T>` uninitialized-copy over a range of 0x14-byte elements
/// (the layout its per-element helper 0x083d7d20 constructs; the element
/// type is not recovered). Word-for-word twin of
/// [`vector_copy_construct_range_elem28`] with 0x14 strides:
///
/// ```text
/// 083e8afc  push {r4, r5, r6, r7, r8, lr}
/// 083e8b00  mov  r7, r3           ; vector (dead in the helper, forwarded)
/// 083e8b04  mov  r6, r1           ; last
/// 083e8b08  mov  r5, r2           ; output cursor
/// 083e8b0c  mov  r4, r0           ; source cursor
/// 083e8b10  b    test
/// loop:
/// 083e8b14  mov  r2, r4
/// 083e8b18  mov  r1, r5
/// 083e8b1c  mov  r0, r7
/// 083e8b20  bl   0x083d7d20       ; element copy-construct(vector, out, src)
/// 083e8b24  add  r4, r4, #0x14
/// 083e8b28  add  r5, r5, #0x14
/// test:
/// 083e8b2c  cmp  r4, r6
/// 083e8b30  bne  loop
/// 083e8b34  mov  r0, r5           ; return advanced output
/// 083e8b38  pop  {r4, r5, r6, r7, r8, pc}
/// ```
///
/// **Call count**, verified by decoding every B/BL word in osos.dec:
/// exactly four inbound direct `bl` sites (0x083e168c, 0x083e16f4,
/// 0x083e1778, 0x083e17cc — the vector reallocation/insert paths of
/// `FUN_083e1614`), all unconditional; no predicated calls target this
/// entry. The body itself contains one plain `bl` (to 0x083d7d20) and no
/// predicated calls; its only other branch is the `bne` back-edge. Ghidra
/// reports the 64-byte size correctly and its C matches this decode.
///
/// The loop terminates on cursor EQUALITY (`cmp r4, r6; bne`), not a
/// less-than bound, matching every caller's whole-element ranges; the
/// helper's return value is discarded and the advanced output cursor is
/// returned whether or not any construction happened (the NULL-output
/// guard lives inside the helper, not here).
///
/// # Deviations
///
/// The element helper `FUN_083d7d20` is unported and dispatches through
/// [`VECTOR_COPY_CONSTRUCT_ELEM20_OPS`]: target builds transmute
/// [`VECTOR_COPY_CONSTRUCT_ELEM20_ADDRESS`], the host default is inert and
/// every test installs a recording model.
///
/// # Safety
/// `first` and `last` must delimit a whole number of contiguous readable
/// 0x14-byte elements; `output` must be writable for the same number of
/// elements whenever the installed helper writes. `vector` is passed
/// through untouched.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_copy_construct_range_elem20(
    mut first: *const u8,
    last: *const u8,
    mut output: *mut u8,
    vector: *mut VectorStorage,
) -> *mut u8 {
    while first != last {
        (vector_copy_construct_elem20_ops().copy_construct)(vector, output, first);
        first = first.wrapping_add(0x14);
        output = output.wrapping_add(0x14);
    }
    output
}

/// vector_copy_construct_range_attach — original: `FUN_083e8a44` @
/// 0x083e8a44 (56 bytes; extent 0x083e8a44..0x083e8a7c, bounded by the
/// `b test` loop entry of the next leaf function at 0x083e8a7c;
/// reference `ipod-decomp/decomp/c/038/083e8a44_FUN_083e8a44.c`).
///
/// `std::vector<RefcountedBody*>` uninitialized-copy over a slot range:
/// for each source slot in `[first, last)` it attaches the slot's body
/// into the output cursor via the ported [`refcounted_body_attach`] @
/// 0x0839d370 (store the body pointer, bump its refcount), returning
/// the advanced output cursor:
///
/// ```text
/// 083e8a44  push {r4, r5, r6, lr}
/// 083e8a48  mov  r6, r1           ; last
/// 083e8a4c  mov  r5, r2           ; output cursor
/// 083e8a50  mov  r4, r0           ; source cursor
/// 083e8a54  b    test
/// loop:
/// 083e8a58  movs r0, r5           ; NULL-check the DESTINATION cursor
/// 083e8a5c  ldrne r1, [r4]        ; body = *first
/// 083e8a60  blne 0x0839d370       ; refcounted_body_attach(output, body)
/// 083e8a64  add  r4, r4, #4
/// 083e8a68  add  r5, r5, #4
/// test:
/// 083e8a6c  cmp  r4, r6
/// 083e8a70  bne  loop
/// 083e8a74  mov  r0, r5           ; return advanced output
/// 083e8a78  pop  {r4, r5, r6, pc}
/// ```
///
/// **Call count**, verified by decoding every B/BL word in osos.dec:
/// exactly four inbound direct `bl` sites (0x083e0ce0, 0x083e0d4c,
/// 0x083e0dd8, 0x083e0e18 — reallocation/insert paths of the refcounted
/// vector), all unconditional; no predicated calls target this entry.
/// The body itself contains exactly ONE `bl`: the predicated `blne` to
/// [`refcounted_body_attach`]; its only other branch is the `bne`
/// back-edge. Ghidra reports the 56-byte size correctly (the "4 bl"
/// figure counts inbound callers) and its C matches this decode.
///
/// As in the sibling range copiers, the loop terminates on cursor
/// EQUALITY. The `movs` guard re-checks the output CURSOR on every
/// iteration, so a NULL initial output skips only the FIRST attach —
/// after the cursor advances it is non-NULL and later bodies land at
/// 0x4, 0x8, ... No caller passes NULL (the guard exists for the
/// generic vector algorithms sharing this shape); that path is
/// therefore not host-testable (address 0 cannot be fixture-mapped).
///
/// # Deviations
///
/// None: the per-element helper [`refcounted_body_attach`] is already
/// ported, so this calls the real Rust body directly (no ops seam).
/// Cursors advance with `wrapping_add` so the NULL-output path can run
/// on host without forming out-of-bounds pointers.
///
/// # Safety
/// `first` and `last` must delimit a whole number of contiguous readable
/// `*mut RefcountedBody` slots; whenever `output` is non-NULL it must
/// be writable for the same number of slots, and each non-NULL body
/// must satisfy [`refcounted_body_attach`]'s preconditions.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_copy_construct_range_attach(
    mut first: *const *mut RefcountedBody,
    last: *const *mut RefcountedBody,
    mut output: *mut *mut RefcountedBody,
) -> *mut *mut RefcountedBody {
    while first != last {
        // `movs r0, r5` predicates BOTH the body load and the attach on
        // the CURRENT destination cursor being non-NULL: an initial NULL
        // output skips the first attach only.
        if !output.is_null() {
            refcounted_body_attach(output, first.read());
        }
        first = first.wrapping_add(1);
        output = output.wrapping_add(1);
    }
    output
}
/// vector_copy_construct_range_attach_8c0c — original: `FUN_083e8c0c` @
/// 0x083e8c0c (56 bytes; exact extent 0x083e8c0c..0x083e8c44, ending before
/// the next independent `push {r4,lr}` entry).
///
/// Copies a `std::vector<RefcountedBody*>` range into uninitialized output.
/// Each iteration conditionally attaches the source body when the current
/// output cursor is non-NULL, then advances both target-word cursors and
/// returns the output end.
///
/// Raw A32 words verify zero plain `bl` instructions and one predicated
/// `blne` at 0x083e8c28, targeting the already ported
/// [`refcounted_body_attach`] @ 0x0839d370.
///
/// # Deviations
///
/// `wrapping_add` preserves target cursor wrapping while avoiding host
/// pointer-arithmetic UB for the raw NULL-output path.
///
/// # Safety
///
/// `first` and `last` must delimit readable `RefcountedBody` slots. A
/// non-NULL `output` must be writable for the same number of slots, and each
/// non-NULL body must satisfy [`refcounted_body_attach`]'s preconditions.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(
    target_os = "none",
    link_section = ".text.vector_copy_construct_range_attach_8c0c"
)]
#[inline(never)]
pub unsafe extern "C" fn vector_copy_construct_range_attach_8c0c(
    mut first: *const *mut RefcountedBody,
    last: *const *mut RefcountedBody,
    mut output: *mut *mut RefcountedBody,
) -> *mut *mut RefcountedBody {
    while first != last {
        if !output.is_null() {
            refcounted_body_attach(output, first.read());
        }
        first = first.wrapping_add(1);
        output = output.wrapping_add(1);
    }
    output
}




/// A target-layout container head whose elements are destroyed by
/// [`container_delete_enabled_elements`].
///
/// On ARM, `count` and `delete_enabled` reside at byte offsets +0x04 and
/// +0x10. `repr(C)` preserves those target offsets while keeping the native
/// host vtable pointer and subsequent fields disjoint.
#[repr(C)]
pub struct ContainerDeleteEnabledElements {
    vtable: *const ElementSlotFn,
    count: i32,
    _unknown_08: u32,
    _unknown_0c: u32,
    delete_enabled: u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x04] = [0; core::mem::offset_of!(ContainerDeleteEnabledElements, count)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x10] = [0; core::mem::offset_of!(ContainerDeleteEnabledElements, delete_enabled)];

/// container_delete_enabled_elements — original: `FUN_083d1f40` @
/// 0x083d1f40 (64 bytes; Ghidra reports 60).
///
/// Raw `osos.dec` establishes the complete 16-word body from `push
/// {r4,r5,r6,lr}` through `pop {r4,r5,r6,pc}` at 0x083d1f7c; the next
/// independently linked function begins at 0x083d1f80. Three inbound calls
/// are unconditional plain `bl` instructions (0x081b9430, 0x083d1fc0, and
/// 0x083d1ff8), with no predicated `bl` forms. The body has two plain direct
/// `bl` calls per iteration, to `container_element_at_alias_6c6c` and
/// `operator_delete`, and no predicated calls.
///
/// When `delete_enabled` is nonzero, walks signed indices from zero while
/// less than `count`; it obtains each element from the container's vtable
/// +0x40 accessor and passes the returned pointer to tag-2 `operator_delete`.
/// A disabled flag or nonpositive count performs no access. Deliberate
/// deviation: the two verified, already ported callees are ordinary Rust calls
/// rather than ARM `bl` instructions.
///
/// # Safety
///
/// `container` must point to a readable target-layout head. When enabled with
/// a positive count, its vtable and each selected element slot must satisfy
/// [`container_element_at_alias_6c6c`]'s contract; every returned element must
/// satisfy [`crate::heap::veneers::operator_delete`]'s ownership contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_delete_enabled_elements")]
#[inline(never)]
pub unsafe extern "C" fn container_delete_enabled_elements(
    container: *mut ContainerDeleteEnabledElements,
) {
    if (*container).delete_enabled == 0 {
        return;
    }
    let count = (*container).count;
    let mut index = 0;
    while index < count {
        crate::heap::veneers::operator_delete(container_element_at_alias_6c6c(
            container.cast(),
            index as usize,
        ));
        index += 1;
    }
}

/// scoped_context_container_delete_enabled_elements — original:
/// `FUN_083d10b8` @ `0x083d10b8` (76 bytes; Ghidra reports 76).
///
/// Raw `osos.dec` establishes the full 19-word extent from `push
/// {r4,r5,r6,lr}` through `pop {r4,r5,r6,pc}` at `0x083d1100`; the next
/// independently linked function begins at `0x083d1104`. The body contains
/// three plain direct `bl` calls — `container_element_at_alias_6a68`,
/// `scoped_context_destroy`, and `operator_delete` — and no predicated `bl`
/// calls.
///
/// When `delete_enabled` is nonzero, walks signed indices from zero while
/// less than `count`. Each indexed container element is a ScopedContext:
/// destroy its no-op body, then tag-2-delete the same element pointer. A
/// disabled flag or nonpositive count performs no access.
///
/// Deliberate deviation: the three verified ported callees are ordinary Rust
/// calls rather than ARM `bl` instructions. `scoped_context_destroy` is
/// explicitly followed by `operator_delete(element)` because its recovered
/// void ABI does not promise the original's incidental r0 pass-through.
///
/// # Safety
///
/// `container` must point to a readable target-layout head. When enabled with
/// a positive count, its vtable and selected element slots must satisfy
/// [`container_element_at_alias_6a68`]'s contract; every element must be a
/// valid [`ScopedContext`] allocation accepted by
/// [`crate::heap::veneers::operator_delete`].
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.scoped_context_container_delete_enabled_elements")]
#[inline(never)]
pub unsafe extern "C" fn scoped_context_container_delete_enabled_elements(
    container: *mut ContainerDeleteEnabledElements,
) {
    if (*container).delete_enabled == 0 {
        return;
    }
    let count = (*container).count;
    let mut index = 0;
    while index < count {
        let element = container_element_at_alias_6a68(container.cast(), index as usize);
        if !element.is_null() {
            scoped_context_destroy(element.cast());
            crate::heap::veneers::operator_delete(element);
        }
        index += 1;
    }
}

/// A target-layout callback container whose release gate is at `+0x28`.
///
/// The leading vtable and count are consumed by
/// [`container_element_at_alias_5f74`]; the intervening words are opaque.
#[repr(C)]
pub struct ContainerReleaseEnabledElements {
    vtable: *const ElementSlotFn,
    count: i32,
    _unknown_08_24: [u32; 8],
    release_enabled: u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x04] = [0; core::mem::offset_of!(ContainerReleaseEnabledElements, count)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x28] = [0; core::mem::offset_of!(ContainerReleaseEnabledElements, release_enabled)];

/// The recovered callback object's vtable prefix.
#[repr(C)]
pub struct ContainerElementReleaseVtable {
    _slot_00: usize,
    release: unsafe extern "C" fn(*mut u8),
}

/// container_release_enabled_elements — original: `FUN_0839c540` @
/// `0x0839c540` (76 bytes; Ghidra agrees).
///
/// Raw `osos.dec` establishes the complete 19-word extent from `push
/// {r4,r5,r6,lr}` at `0x0839c540` through `pop {r4,r5,r6,pc}` at
/// `0x0839c588`; the next real function begins at `0x0839c58c`. The body has
/// one plain `bl`, to [`container_element_at_alias_5f74`], and one predicated
/// `blxne` virtual release call. There are three inbound plain `bl` sites
/// (0x08178d70, 0x0839c5d8, and 0x0839c5f0), and no predicated inbound calls.
///
/// # Algorithm
///
/// If `release_enabled` is nonzero, walk signed indices from zero while less
/// than `count`; resolve each element through the verified container accessor,
/// and invoke non-NULL elements' vtable slot `+0x04`.
///
/// # Deliberate deviations
///
/// The direct ARM call is a Rust call, and the indirect `blxne` is a typed
/// vtable call. Both preserve the original unchecked contracts; none else.
///
/// # Safety
///
/// `container` must identify a readable target-layout container. For every
/// enabled index, its accessor and any non-NULL element's release slot must be
/// valid to call.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_release_enabled_elements")]
#[inline(never)]
pub unsafe extern "C" fn container_release_enabled_elements(
    container: *mut ContainerReleaseEnabledElements,
) {
    if (*container).release_enabled == 0 {
        return;
    }
    let count = (*container).count;
    let mut index = 0;
    while index < count {
        let element = container_element_at_alias_5f74(container.cast(), index as usize);
        if !element.is_null() {
            let vtable = element.cast::<*const ContainerElementReleaseVtable>().read();
            ((*vtable).release)(element);
        }
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::string::StringRep;
    use crate::cxx::string_object::{
        StringObjectAssignCstrOps, StringObjectOps, STRING_OBJECT_ASSIGN_CSTR_OPS,
        STRING_OBJECT_OPS, STRING_OBJECT_VTABLE,
    };
    use crate::cxx::string_object::tests::STRING_OBJECT_OPS_TEST_LOCK;
    use crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK;
    use std::sync::MutexGuard;
    use std::vec::Vec;
    #[repr(C)]
    struct GuardedVectorStorage {
        left_guard: usize,
        vector: VectorStorage,
        right_guard: usize,
    }

    #[test]
    fn less_u32_pair_orders_each_word_unsigned_and_ignores_this() {
        let cases = [
            (
                U32Pair { first: 0, second: u32::MAX },
                U32Pair { first: 1, second: 0 },
                1,
            ),
            (
                U32Pair { first: 7, second: 3 },
                U32Pair { first: 7, second: 4 },
                1,
            ),
            (
                U32Pair { first: 7, second: 4 },
                U32Pair { first: 7, second: 4 },
                0,
            ),
            (
                U32Pair { first: 7, second: 5 },
                U32Pair { first: 7, second: 4 },
                0,
            ),
            (
                U32Pair { first: u32::MAX, second: 0 },
                U32Pair { first: 0, second: u32::MAX },
                0,
            ),
        ];

        for (left, right, expected) in cases {
            assert_eq!(
                unsafe { less_u32_pair(core::ptr::null(), &left, &right) },
                expected,
                "{left:?} < {right:?}",
            );
        }
    }

    #[test]
    fn vector_storage_init_clears_all_three_words_without_touching_guards() {
        let mut guarded = GuardedVectorStorage {
            left_guard: 0x1eed_c0de,
            vector: VectorStorage {
                begin: 0x1111usize as *mut u8,
                end: 0x2222usize as *mut u8,
                end_of_storage: 0x3333usize as *mut u8,
            },
            right_guard: 0xdec0_adde,
        };

        unsafe { vector_storage_init(&mut guarded.vector) };

        assert!(guarded.vector.begin.is_null());
        assert!(guarded.vector.end.is_null());
        assert!(guarded.vector.end_of_storage.is_null());
        assert_eq!(guarded.left_guard, 0x1eed_c0de);
        assert_eq!(guarded.right_guard, 0xdec0_adde);
    }


    static mut STRING_OBJECT_RELEASES: Vec<usize> = Vec::new();

    unsafe extern "C" fn record_string_object_release(this: *mut StringObject) {
        (*core::ptr::addr_of_mut!(STRING_OBJECT_RELEASES)).push(this as usize);
        (*this).payload = core::ptr::null_mut();
    }

    struct StringObjectReleaseGuard {
        _lock: MutexGuard<'static, ()>,
        saved: StringObjectOps,
    }

    impl Drop for StringObjectReleaseGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(STRING_OBJECT_OPS), self.saved);
            }
        }
    }

    fn record_string_object_releases() -> StringObjectReleaseGuard {
        let lock = STRING_OBJECT_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(STRING_OBJECT_RELEASES)).clear();
            let saved = core::ptr::read_volatile(core::ptr::addr_of!(STRING_OBJECT_OPS));
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(STRING_OBJECT_OPS),
                StringObjectOps {
                    release_payload: record_string_object_release,
                },
            );
            StringObjectReleaseGuard { _lock: lock, saved }
        }
    }

    static mut STRING_OBJECT_ASSIGN_CLEAR_CALLS: Vec<usize> = Vec::new();

    unsafe extern "C" fn no_string_object_assign_allocation(
        _this: *mut StringObject,
        _requested_size: usize,
        _flags: u32,
    ) -> *mut u8 {
        core::ptr::null_mut()
    }

    unsafe extern "C" fn record_string_object_assign_clear(this: *mut StringObject) {
        (*core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CLEAR_CALLS)).push(this as usize);
    }

    struct StringObjectAssignClearGuard {
        _lock: MutexGuard<'static, ()>,
        saved: StringObjectAssignCstrOps,
    }

    impl Drop for StringObjectAssignClearGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS),
                    self.saved,
                );
            }
        }
    }

    fn record_string_object_assign_clears() -> StringObjectAssignClearGuard {
        let lock = STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CLEAR_CALLS)).clear();
            let saved = core::ptr::read_volatile(core::ptr::addr_of!(
                STRING_OBJECT_ASSIGN_CSTR_OPS
            ));
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS),
                StringObjectAssignCstrOps {
                    allocate_payload: no_string_object_assign_allocation,
                    clear_payload: record_string_object_assign_clear,
                },
            );
            StringObjectAssignClearGuard { _lock: lock, saved }
        }
    }

    fn string_pair(first_payload: usize, second_payload: usize) -> StringObjectPair {
        StringObjectPair {
            first: StringObject {
                vtable: core::ptr::null(),
                payload: first_payload as *mut u8,
            },
            second: StringObject {
                vtable: core::ptr::null(),
                payload: second_payload as *mut u8,
            },
        }
    }

    fn string_object_releases() -> Vec<usize> {
        unsafe { (*core::ptr::addr_of!(STRING_OBJECT_RELEASES)).clone() }
    }

    #[repr(C)]
    struct StringRepStorage {
        rep: StringRep,
        data: u8,
    }

    fn string_rep_storage() -> StringRepStorage {
        StringRepStorage {
            rep: StringRep {
                refcount: 0,
                capacity: 0,
                length: 0,
            },
            data: 0,
        }
    }

    fn string_slot(storage: &mut StringRepStorage) -> *mut u8 {
        core::ptr::addr_of_mut!(storage.data)
    }

    #[test]
    fn record_range_destroy_8_releases_every_pair_second_then_first() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let mut first0 = string_rep_storage();
        let mut second0 = string_rep_storage();
        let mut first1 = string_rep_storage();
        let mut second1 = string_rep_storage();
        let mut records = [
            CxxStringPair {
                first: string_slot(&mut first0),
                second: string_slot(&mut second0),
            },
            CxxStringPair {
                first: string_slot(&mut first1),
                second: string_slot(&mut second1),
            },
        ];
        let first = records.as_mut_ptr();

        unsafe {
            cxx_record_range_destroy_8(core::ptr::null_mut(), first, first.add(records.len()));
        }

        assert_eq!(first0.rep.refcount, -1);
        assert_eq!(second0.rep.refcount, -1);
        assert_eq!(first1.rep.refcount, -1);
        assert_eq!(second1.rep.refcount, -1);
        let (free_calls, last_freed, _tag) = crate::heap::veneers::tests::free_log();
        assert_eq!(free_calls, 4);
        assert_eq!(
            last_freed,
            core::ptr::addr_of_mut!(first1.rep).cast::<u8>(),
            "the last release is the final record's first string"
        );
    }

    #[test]
    fn record_range_destroy_8_empty_does_not_dereference_bounds() {
        unsafe {
            cxx_record_range_destroy_8(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
        }
    }

    #[test]
    fn record_range_destroy_empty_does_not_dereference_bounds() {
        unsafe {
            cxx_record_range_destroy_16(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
        }
    }

    #[test]
    fn record_range_destroy_single_destroys_both_strings() {
        let _guard = record_string_object_releases();
        let mut records = [string_pair(0x11, 0x22)];
        let record = records.as_mut_ptr();
        unsafe {
            cxx_record_range_destroy_16(core::ptr::null_mut(), record, record.add(1));
            assert_eq!((*record).first.vtable, &STRING_OBJECT_VTABLE as *const _);
            assert_eq!((*record).second.vtable, &STRING_OBJECT_VTABLE as *const _);
            assert!((*record).first.payload.is_null());
            assert!((*record).second.payload.is_null());
        }
        assert_eq!(string_object_releases().len(), 2);
    }

    #[test]
    fn record_range_destroy_multiple_visits_each_pair() {
        let _guard = record_string_object_releases();
        let mut records = [
            string_pair(0x11, 0x12),
            string_pair(0x21, 0x22),
            string_pair(0x31, 0x32),
        ];
        let first = records.as_mut_ptr();
        unsafe {
            cxx_record_range_destroy_16(core::ptr::null_mut(), first, first.add(records.len()));
            for record in &records {
                assert_eq!(record.first.vtable, &STRING_OBJECT_VTABLE as *const _);
                assert_eq!(record.second.vtable, &STRING_OBJECT_VTABLE as *const _);
                assert!(record.first.payload.is_null());
                assert!(record.second.payload.is_null());
            }
        }
        assert_eq!(string_object_releases().len(), 6);
    }

    #[test]
    fn record_range_destroy_releases_second_then_first_per_record() {
        let _guard = record_string_object_releases();
        let mut records = [string_pair(0x11, 0x12), string_pair(0x21, 0x22)];
        let first = records.as_mut_ptr();
        unsafe {
            let expected = [
                core::ptr::addr_of_mut!((*first).second) as usize,
                core::ptr::addr_of_mut!((*first).first) as usize,
                core::ptr::addr_of_mut!((*first.add(1)).second) as usize,
                core::ptr::addr_of_mut!((*first.add(1)).first) as usize,
            ];
            cxx_record_range_destroy_16(core::ptr::null_mut(), first, first.add(records.len()));
            assert_eq!(string_object_releases(), expected);
        }
    }


    #[test]
    fn pair_assign_copies_two_words_and_returns_dst() {
        unsafe {
            let src: [u32; 2] = [0x1111_1111, 0x2222_2222];
            let mut dst: [u32; 3] = [0; 3];
            let ret = pair_assign_guarded(dst.as_mut_ptr(), src.as_ptr());
            assert_eq!(ret, dst.as_mut_ptr());
            assert_eq!(&dst[..2], &src);
            assert_eq!(dst[2], 0, "nothing past the 8 bytes");
        }
    }

    /// src == dst: the whole copy is skipped — nothing is loaded or
    /// stored, so the words stay put (trivially) and no overlap hazard
    /// exists at all.
    #[test]
    fn pair_assign_self_assign_is_a_noop() {
        unsafe {
            let mut pair: [u32; 2] = [0xaaaa_bbbb, 0xcccc_dddd];
            let ret = pair_assign_guarded(pair.as_mut_ptr(), pair.as_ptr());
            assert_eq!(ret, pair.as_mut_ptr());
            assert_eq!(pair, [0xaaaa_bbbb, 0xcccc_dddd]);
        }
    }

    #[test]
    fn pair_assign_dst_is_returned_on_the_skipped_path() {
        unsafe {
            let pair: [u32; 2] = [1, 2];
            // Two disjoint buffers, so the guard fires only on equality;
            // NULL==NULL exercises the equal-pointer skip without any
            // valid memory.
            assert!(pair_assign_guarded(core::ptr::null_mut(), core::ptr::null()).is_null());
            assert_eq!(pair, [1, 2]);
        }
    }

    #[test]
    fn vector_pair_copy_null_destination_is_a_noop() {
        unsafe {
            assert!(vector_pair_copy_into(
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null(),
            )
            .is_null());
        }
    }

    #[test]
    fn vector_pair_copy_copies_exactly_two_words() {
        unsafe {
            let src = [0x1111_1111, 0x2222_2222];
            let mut dst = [0u32; 2];
            let ret = vector_pair_copy_into(core::ptr::null(), dst.as_mut_ptr(), src.as_ptr());
            assert_eq!(ret, dst.as_mut_ptr());
            assert_eq!(dst, src);
        }
    }

    #[test]
    fn vector_pair_copy_does_not_write_adjacent_words() {
        unsafe {
            let src = [0x1111_1111, 0x2222_2222];
            let mut surrounding = [0xaaaa_aaaa, 0, 0, 0xbbbb_bbbb];
            vector_pair_copy_into(
                core::ptr::null(),
                surrounding.as_mut_ptr().add(1),
                src.as_ptr(),
            );
            assert_eq!(surrounding, [0xaaaa_aaaa, 0x1111_1111, 0x2222_2222, 0xbbbb_bbbb]);
        }
    }


    #[test]
    fn iter_assign_copies_four_words_and_returns_dst() {
        unsafe {
            let src: [u32; 4] = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];
            let mut dst: [u32; 5] = [0; 5];
            let ret = deque_iter_assign(dst.as_mut_ptr(), src.as_ptr());
            assert_eq!(ret, dst.as_mut_ptr());
            assert_eq!(&dst[..4], &src);
            assert_eq!(dst[4], 0, "nothing past the 16 bytes");
        }
    }

    #[test]
    fn iter_assign_alias_9ec8_preserves_destination_and_forward_overlap() {
        unsafe {
            let src = [0xdead_beefu32, 0, 0xffff_ffff, 0x1234_5678];
            let mut dst = [0xaaaa_aaaa; 5];
            assert_eq!(
                deque_iter_assign_alias_9ec8(dst.as_mut_ptr(), src.as_ptr()),
                dst.as_mut_ptr(),
            );
            assert_eq!(&dst[..4], &src);
            assert_eq!(dst[4], 0xaaaa_aaaa, "does not write past 16 bytes");

            let mut overlapping = [1u32, 2, 3, 4, 5];
            deque_iter_assign_alias_9ec8(overlapping.as_mut_ptr().add(1), overlapping.as_ptr());
            assert_eq!(overlapping, [1, 1, 1, 1, 1]);
        }
    }

    #[test]
    fn iter_assign_alias_9fd4_copies_four_words_and_returns_dst() {
        unsafe {
            let src: [u32; 4] = [0xdead_beef, 0, 0xffff_ffff, 0x1234_5678];
            let mut dst: [u32; 5] = [0xaaaa_aaaa; 5];
            let ret = deque_iter_assign_alias_9fd4(dst.as_mut_ptr(), src.as_ptr());
            assert_eq!(ret, dst.as_mut_ptr());
            assert_eq!(&dst[..4], &src, "including zero and all-ones words");
            assert_eq!(dst[4], 0xaaaa_aaaa, "nothing past the 16 bytes");
        }
    }

    #[test]
    fn iter_assign_alias_9f64_preserves_destination_and_forward_overlap() {
        unsafe {
            let src = [0xdead_beefu32, 0, 0xffff_ffff, 0x1234_5678];
            let mut dst = [0xaaaa_aaaa; 5];
            assert_eq!(
                deque_iter_assign_alias_9f64(dst.as_mut_ptr(), src.as_ptr()),
                dst.as_mut_ptr(),
            );
            assert_eq!(&dst[..4], &src);
            assert_eq!(dst[4], 0xaaaa_aaaa, "does not write past 16 bytes");

            let mut overlapping = [1u32, 2, 3, 4, 5];
            deque_iter_assign_alias_9f64(overlapping.as_mut_ptr().add(1), overlapping.as_ptr());
            assert_eq!(overlapping, [1, 1, 1, 1, 1]);
        }
    }

    #[test]
    fn iter_assign_alias_a34c_copies_four_words_and_returns_dst() {
        unsafe {
            let src: [u32; 4] = [0, 0xffff_ffff, 0x1357_9bdf, 0x2468_ace0];
            let mut dst: [u32; 5] = [0xaaaa_aaaa; 5];
            let ret = deque_iter_assign_alias_a34c(dst.as_mut_ptr(), src.as_ptr());
            assert_eq!(ret, dst.as_mut_ptr());
            assert_eq!(&dst[..4], &src, "including zero and all-ones words");
            assert_eq!(dst[4], 0xaaaa_aaaa, "nothing past the 16 bytes");
        }
    }
    #[test]
    fn iter_assign_alias_c774_is_a_forward_word_copy() {
        unsafe {
            let mut words = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444, 0x5555_5555];
            let dst = words.as_mut_ptr().add(1);
            let ret = deque_iter_assign_alias_c774(dst, words.as_ptr());
            assert_eq!(ret, dst);
            assert_eq!(words, [0x1111_1111; 5]);
        }
    }



    #[test]
    fn iter_init_elem4_anchors_on_the_slot_segment() {
        let mut segment = [0u8; 0x80];
        let mut slot = segment.as_mut_ptr();
        let mut iter = DequeIter::NULL;
        unsafe {
            let ret = deque_iter_init_elem4(
                &mut iter,
                segment.as_mut_ptr().add(0x14),
                &mut slot,
            );
            assert_eq!(ret, &mut iter as *mut DequeIter);
            assert_eq!(iter.cur, segment.as_mut_ptr().add(0x14));
            assert_eq!(iter.seg_base, segment.as_mut_ptr());
            assert_eq!(iter.seg_end, segment.as_mut_ptr().add(0x80));
            assert_eq!(iter.seg_slot, &mut slot as *mut *mut u8);
        }
    }

    #[test]
    fn iter_init_elem4_distinguishes_null_slot_from_null_segment() {
        let mut null_segment = core::ptr::null_mut();
        let mut iter = DequeIter::NULL;
        unsafe {
            deque_iter_init_elem4(&mut iter, 0x24 as *mut u8, &mut null_segment);
            assert_eq!(iter.cur, 0x24 as *mut u8);
            assert!(iter.seg_base.is_null());
            assert_eq!(iter.seg_end, 0x80 as *mut u8);
            assert_eq!(iter.seg_slot, &mut null_segment as *mut *mut u8);

            deque_iter_init_elem4(&mut iter, core::ptr::null_mut(), core::ptr::null_mut());
            assert!(iter.cur.is_null());
            assert!(iter.seg_base.is_null());
            assert!(iter.seg_end.is_null());
            assert!(iter.seg_slot.is_null());
        }
    }

    #[test]
    fn iter_increment_elem4_advances_within_its_segment() {
        let mut segment = [0u8; 0x80];
        let mut slots = [segment.as_mut_ptr()];
        let mut iter = DequeIter {
            cur: unsafe { segment.as_mut_ptr().add(0x14) },
            seg_base: segment.as_mut_ptr(),
            seg_end: unsafe { segment.as_mut_ptr().add(0x80) },
            seg_slot: slots.as_mut_ptr(),
        };

        unsafe {
            let ret = deque_iter_increment_elem4(&mut iter);
            assert_eq!(ret, &mut iter as *mut DequeIter);
        }

        assert_eq!(iter.cur, unsafe { segment.as_mut_ptr().add(0x18) });
        assert_eq!(iter.seg_base, segment.as_mut_ptr());
        assert_eq!(iter.seg_end, unsafe { segment.as_mut_ptr().add(0x80) });
        assert_eq!(iter.seg_slot, slots.as_mut_ptr());
    }

    #[test]
    fn iter_increment_elem4_switches_to_the_next_segment_at_the_boundary() {
        let mut first = [0u8; 0x80];
        let mut second = [0u8; 0x80];
        let mut slots = [first.as_mut_ptr(), second.as_mut_ptr()];
        let mut iter = DequeIter {
            cur: unsafe { first.as_mut_ptr().add(0x7c) },
            seg_base: first.as_mut_ptr(),
            seg_end: unsafe { first.as_mut_ptr().add(0x80) },
            seg_slot: slots.as_mut_ptr(),
        };

        unsafe {
            deque_iter_increment_elem4(&mut iter);
        }

        assert_eq!(iter.cur, second.as_mut_ptr());
        assert_eq!(iter.seg_base, second.as_mut_ptr());
        assert_eq!(iter.seg_end, unsafe { second.as_mut_ptr().add(0x80) });
        assert_eq!(iter.seg_slot, unsafe { slots.as_mut_ptr().add(1) });
    }

    #[test]
    fn iter_increment_elem4_keeps_the_raw_null_next_segment_behavior() {
        let mut first = [0u8; 0x80];
        let mut slots = [first.as_mut_ptr(), core::ptr::null_mut()];
        let mut iter = DequeIter {
            cur: unsafe { first.as_mut_ptr().add(0x7c) },
            seg_base: first.as_mut_ptr(),
            seg_end: unsafe { first.as_mut_ptr().add(0x80) },
            seg_slot: slots.as_mut_ptr(),
        };

        unsafe {
            deque_iter_increment_elem4(&mut iter);
        }

        assert!(iter.cur.is_null());
        assert!(iter.seg_base.is_null());
        assert_eq!(iter.seg_end, 0x80 as *mut u8);
        assert_eq!(iter.seg_slot, unsafe { slots.as_mut_ptr().add(1) });
    }

    #[test]
    fn iter_init_elem4_alias_a3e4_preserves_null_slot_and_segment_edges() {
        let mut segment = [0u8; 0x80];
        let mut slot = segment.as_mut_ptr();
        let mut iter = DequeIter::NULL;
        unsafe {
            let ret = deque_iter_init_elem4_alias_a3e4(
                &mut iter,
                segment.as_mut_ptr().add(0x2c),
                &mut slot,
            );
            assert_eq!(ret, &mut iter as *mut DequeIter);
            assert_eq!(iter.cur, segment.as_mut_ptr().add(0x2c));
            assert_eq!(iter.seg_base, segment.as_mut_ptr());
            assert_eq!(iter.seg_end, segment.as_mut_ptr().add(0x80));
            assert_eq!(iter.seg_slot, &mut slot as *mut *mut u8);

            let mut null_segment = core::ptr::null_mut();
            deque_iter_init_elem4_alias_a3e4(
                &mut iter,
                core::ptr::null_mut(),
                &mut null_segment,
            );
            assert!(iter.seg_base.is_null());
            assert_eq!(iter.seg_end, 0x80 as *mut u8);

            deque_iter_init_elem4_alias_a3e4(&mut iter, 0x4 as *mut u8, core::ptr::null_mut());
            assert_eq!(iter.cur, 0x4 as *mut u8);
            assert!(iter.seg_base.is_null());
            assert!(iter.seg_end.is_null());
            assert!(iter.seg_slot.is_null());
        }
    }
    #[test]
    fn iter_init_elem4_alias_a26c_preserves_segment_and_null_edges() {
        let mut segment = [0u8; 0x80];
        let mut slot = segment.as_mut_ptr();
        let mut iter = DequeIter::NULL;
        unsafe {
            let ret = deque_iter_init_elem4_alias_a26c(
                &mut iter,
                segment.as_mut_ptr().add(0x3c),
                &mut slot,
            );
            assert_eq!(ret, &mut iter as *mut DequeIter);
            assert_eq!(iter.cur, segment.as_mut_ptr().add(0x3c));
            assert_eq!(iter.seg_base, segment.as_mut_ptr());
            assert_eq!(iter.seg_end, segment.as_mut_ptr().add(0x80));
            assert_eq!(iter.seg_slot, &mut slot as *mut *mut u8);

            let mut null_segment = core::ptr::null_mut();
            deque_iter_init_elem4_alias_a26c(
                &mut iter,
                core::ptr::null_mut(),
                &mut null_segment,
            );
            assert!(iter.seg_base.is_null());
            assert_eq!(iter.seg_end, 0x80 as *mut u8);

            deque_iter_init_elem4_alias_a26c(&mut iter, 0x4 as *mut u8, core::ptr::null_mut());
            assert_eq!(iter.cur, 0x4 as *mut u8);
            assert!(iter.seg_base.is_null());
            assert!(iter.seg_end.is_null());
            assert!(iter.seg_slot.is_null());
        }
    }
    #[test]
    fn iter_init_elem4_alias_a304_preserves_segment_and_null_edges() {
        let mut segment = [0u8; 0x80];
        let mut slot = segment.as_mut_ptr();
        let mut iter = DequeIter::NULL;
        unsafe {
            let ret = deque_iter_init_elem4_alias_a304(
                &mut iter,
                segment.as_mut_ptr().add(0x64),
                &mut slot,
            );
            assert_eq!(ret, &mut iter as *mut DequeIter);
            assert_eq!(iter.cur, segment.as_mut_ptr().add(0x64));
            assert_eq!(iter.seg_base, segment.as_mut_ptr());
            assert_eq!(iter.seg_end, segment.as_mut_ptr().add(0x80));
            assert_eq!(iter.seg_slot, &mut slot as *mut *mut u8);

            let mut null_segment = core::ptr::null_mut();
            deque_iter_init_elem4_alias_a304(
                &mut iter,
                core::ptr::null_mut(),
                &mut null_segment,
            );
            assert!(iter.seg_base.is_null());
            assert_eq!(iter.seg_end, 0x80 as *mut u8);

            deque_iter_init_elem4_alias_a304(&mut iter, 0x4 as *mut u8, core::ptr::null_mut());
            assert_eq!(iter.cur, 0x4 as *mut u8);
            assert!(iter.seg_base.is_null());
            assert!(iter.seg_end.is_null());
            assert!(iter.seg_slot.is_null());
        }
    }
    #[test]
    fn iter_init_elem4_alias_a370_preserves_segment_and_null_edges() {
        let mut segment = [0u8; 0x80];
        let mut slot = segment.as_mut_ptr();
        let mut iter = DequeIter::NULL;
        unsafe {
            let ret = deque_iter_init_elem4_alias_a370(
                &mut iter,
                segment.as_mut_ptr().add(0x70),
                &mut slot,
            );
            assert_eq!(ret, &mut iter as *mut DequeIter);
            assert_eq!(iter.cur, segment.as_mut_ptr().add(0x70));
            assert_eq!(iter.seg_base, segment.as_mut_ptr());
            assert_eq!(iter.seg_end, segment.as_mut_ptr().add(0x80));
            assert_eq!(iter.seg_slot, &mut slot as *mut *mut u8);

            let mut null_segment = core::ptr::null_mut();
            deque_iter_init_elem4_alias_a370(
                &mut iter,
                core::ptr::null_mut(),
                &mut null_segment,
            );
            assert!(iter.seg_base.is_null());
            assert_eq!(iter.seg_end, 0x80 as *mut u8);

            deque_iter_init_elem4_alias_a370(&mut iter, 0x4 as *mut u8, core::ptr::null_mut());
            assert_eq!(iter.cur, 0x4 as *mut u8);
            assert!(iter.seg_base.is_null());
            assert!(iter.seg_end.is_null());
            assert!(iter.seg_slot.is_null());
        }
    }


    #[test]
    fn iter_init_elem4_alias_a1d4_preserves_segment_and_null_edges() {
        let mut segment = [0u8; 0x80];
        let mut slot = segment.as_mut_ptr();
        let mut iter = DequeIter::NULL;
        unsafe {
            let ret = deque_iter_init_elem4_alias_a1d4(
                &mut iter,
                segment.as_mut_ptr().add(0x10),
                &mut slot,
            );
            assert_eq!(ret, &mut iter as *mut DequeIter);
            assert_eq!(iter.cur, segment.as_mut_ptr().add(0x10));
            assert_eq!(iter.seg_base, segment.as_mut_ptr());
            assert_eq!(iter.seg_end, segment.as_mut_ptr().add(0x80));
            assert_eq!(iter.seg_slot, &mut slot as *mut *mut u8);

            let mut null_segment = core::ptr::null_mut();
            deque_iter_init_elem4_alias_a1d4(
                &mut iter,
                core::ptr::null_mut(),
                &mut null_segment,
            );
            assert!(iter.seg_base.is_null());
            assert_eq!(iter.seg_end, 0x80 as *mut u8);

            deque_iter_init_elem4_alias_a1d4(&mut iter, 0x4 as *mut u8, core::ptr::null_mut());
            assert_eq!(iter.cur, 0x4 as *mut u8);
            assert!(iter.seg_base.is_null());
            assert!(iter.seg_end.is_null());
            assert!(iter.seg_slot.is_null());
        }
    }

    #[test]
    fn iter_init_elem4_alias_9ff8_preserves_segment_and_null_edges() {
        let mut segment = [0u8; 0x80];
        let mut slot = segment.as_mut_ptr();
        let mut iter = DequeIter::NULL;
        unsafe {
            let ret = deque_iter_init_elem4_alias_9ff8(
                &mut iter,
                segment.as_mut_ptr().add(0x54),
                &mut slot,
            );
            assert_eq!(ret, &mut iter as *mut DequeIter);
            assert_eq!(iter.cur, segment.as_mut_ptr().add(0x54));
            assert_eq!(iter.seg_base, segment.as_mut_ptr());
            assert_eq!(iter.seg_end, segment.as_mut_ptr().add(0x80));
            assert_eq!(iter.seg_slot, &mut slot as *mut *mut u8);

            let mut null_segment = core::ptr::null_mut();
            deque_iter_init_elem4_alias_9ff8(
                &mut iter,
                core::ptr::null_mut(),
                &mut null_segment,
            );
            assert!(iter.seg_base.is_null());
            assert_eq!(iter.seg_end, 0x80 as *mut u8);

            deque_iter_init_elem4_alias_9ff8(&mut iter, 0x4 as *mut u8, core::ptr::null_mut());
            assert_eq!(iter.cur, 0x4 as *mut u8);
            assert!(iter.seg_base.is_null());
            assert!(iter.seg_end.is_null());
            assert!(iter.seg_slot.is_null());
        }
    }

    #[test]
    fn deque_back_elem4_steps_within_and_across_segment_map() {
        let mut previous = [0u8; 0x80];
        let mut current = [0u8; 0x100];
        let mut next = [0u8; 0x80];
        let mut map = [
            previous.as_mut_ptr(),
            current.as_mut_ptr(),
            next.as_mut_ptr(),
        ];
        let mut deque = BlockDeque {
            begin: DequeIter::NULL,
            end: DequeIter {
                cur: unsafe { current.as_mut_ptr().add(0x14) },
                seg_base: current.as_mut_ptr(),
                seg_end: unsafe { current.as_mut_ptr().add(0x80) },
                seg_slot: unsafe { map.as_mut_ptr().add(1) },
            },
            count: 1,
            map: map.as_mut_ptr(),
            map_cap: 3,
        };

        unsafe {
            assert_eq!(deque_back_elem4(&deque), current.as_mut_ptr().add(0x10));

            deque.end.cur = current.as_mut_ptr();
            assert_eq!(deque_back_elem4(&deque), previous.as_mut_ptr().add(0x7c));

            // The raw quotient path also permits spans beyond one segment.
            deque.end.cur = current.as_mut_ptr().add(0x84);
            assert_eq!(deque_back_elem4(&deque), next.as_mut_ptr());
        }
    }




    #[test]
    fn less_signed_is_signed() {
        unsafe {
            let neg: i32 = -1;
            let one: i32 = 1;
            assert_eq!(less_signed(core::ptr::null(), &neg, &one), 1);
            assert_eq!(less_signed(core::ptr::null(), &one, &neg), 0);
            assert_eq!(less_signed(core::ptr::null(), &one, &one), 0, "strict");
            let min = i32::MIN;
            let max = i32::MAX;
            assert_eq!(less_signed(core::ptr::null(), &min, &max), 1);
        }
    }

    /// The same bit patterns compare the other way round unsigned —
    /// this is the whole difference between the two families.
    #[test]
    fn less_unsigned_byte_edges() {
        unsafe {
            // equal / less / greater
            assert_eq!(less_unsigned_byte(core::ptr::null(), &7, &7), 0, "strict");
            assert_eq!(less_unsigned_byte(core::ptr::null(), &3, &9), 1);
            assert_eq!(less_unsigned_byte(core::ptr::null(), &9, &3), 0);
            // unsigned, not signed: 255 is the largest byte, not -1
            assert_eq!(less_unsigned_byte(core::ptr::null(), &255, &0), 0);
            assert_eq!(less_unsigned_byte(core::ptr::null(), &0, &255), 1);
            assert_eq!(less_unsigned_byte(core::ptr::null(), &255, &255), 0, "strict");
            assert_eq!(less_unsigned_byte(core::ptr::null(), &0, &0), 0, "strict");
            assert_eq!(less_unsigned_byte(core::ptr::null(), &254, &255), 1);
        }
    }

    #[test]
    fn less_unsigned_byte_matches_reference_exhaustively() {
        fn reference(a: u8, b: u8) -> u32 {
            u32::from(a < b)
        }
        unsafe {
            for a in 0..=u8::MAX {
                for b in 0..=u8::MAX {
                    assert_eq!(
                        less_unsigned_byte(core::ptr::null(), &a, &b),
                        reference(a, b),
                        "{a} vs {b}"
                    );
                }
            }
        }
    }

    #[test]
    fn less_unsigned_byte_alias_73d4_truth_table() {
        unsafe {
            // equal / less / greater, plus the unsigned edges
            assert_eq!(less_unsigned_byte_alias_73d4(core::ptr::null(), &7, &7), 0, "strict");
            assert_eq!(less_unsigned_byte_alias_73d4(core::ptr::null(), &3, &9), 1);
            assert_eq!(less_unsigned_byte_alias_73d4(core::ptr::null(), &9, &3), 0);
            assert_eq!(less_unsigned_byte_alias_73d4(core::ptr::null(), &255, &0), 0);
            assert_eq!(less_unsigned_byte_alias_73d4(core::ptr::null(), &0, &255), 1);
            assert_eq!(less_unsigned_byte_alias_73d4(core::ptr::null(), &0, &0), 0, "strict");
        }
    }

    #[test]
    fn less_unsigned_byte_alias_73d4_matches_primary_exhaustively() {
        unsafe {
            for a in 0..=u8::MAX {
                for b in 0..=u8::MAX {
                    assert_eq!(
                        less_unsigned_byte_alias_73d4(core::ptr::null(), &a, &b),
                        less_unsigned_byte(core::ptr::null(), &a, &b),
                        "{a} vs {b}"
                    );
                }
            }
        }
    }

    #[test]
    fn less_unsigned_byte_alias_73ec_matches_primary_exhaustively() {
        unsafe {
            for a in 0..=u8::MAX {
                for b in 0..=u8::MAX {
                    assert_eq!(
                        less_unsigned_byte_alias_73ec(core::ptr::null(), &a, &b),
                        less_unsigned_byte(core::ptr::null(), &a, &b),
                        "{a} vs {b}"
                    );
                }
            }
        }
    }

    #[test]
    fn less_unsigned_is_unsigned() {
        unsafe {
            let big: u32 = 0xffff_ffff;
            let one: u32 = 1;
            assert_eq!(less_unsigned(core::ptr::null(), &one, &big), 1);
            assert_eq!(less_unsigned(core::ptr::null(), &big, &one), 0);
            assert_eq!(less_unsigned(core::ptr::null(), &big, &big), 0, "strict");
            let as_signed_neg: i32 = -1;
            let as_signed_one: i32 = 1;
            assert_eq!(
                less_signed(core::ptr::null(), &as_signed_neg, &as_signed_one),
                1,
                "0xffffffff < 1 signed, but not unsigned"
            );
        }
    }
    #[test]
    fn less_unsigned_alias_7404_matches_unsigned_reference_edges() {
        unsafe {
            let values = [0, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX];
            let ignored_this = 0u8;
            for a in values {
                for b in values {
                    assert_eq!(
                        less_unsigned_alias_7404(&ignored_this, &a, &b),
                        u32::from(a < b),
                        "{a:#010x} < {b:#010x}"
                    );
                }
            }
        }
    }
    #[test]
    fn less_unsigned_alias_7434_matches_unsigned_reference_edges() {
        unsafe {
            let values = [0, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX];
            let ignored_this = 0u8;
            for a in values {
                for b in values {
                    assert_eq!(
                        less_unsigned_alias_7434(&ignored_this, &a, &b),
                        u32::from(a < b),
                        "{a:#010x} < {b:#010x}"
                    );
                }
            }
        }
    }
    #[test]
    fn less_unsigned_alias_741c_matches_unsigned_reference_edges() {
        unsafe {
            let values = [0, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX];
            let ignored_this = 0u8;
            for a in values {
                for b in values {
                    assert_eq!(
                        less_unsigned_alias_741c(&ignored_this, &a, &b),
                        u32::from(a < b),
                        "{a:#010x} < {b:#010x}"
                    );
                }
            }
        }
    }


    #[test]
    fn less_unsigned_alias_744c_matches_unsigned_reference_edges() {
        unsafe {
            let values = [0, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX];
            let ignored_this = 0u8;
            for a in values {
                for b in values {
                    assert_eq!(
                        less_unsigned_alias_744c(&ignored_this, &a, &b),
                        u32::from(a < b),
                        "{a:#010x} < {b:#010x}"
                    );
                }
            }
        }
    }

    #[test]
    fn less_unsigned_alias_7464_matches_unsigned_reference_edges() {
        unsafe {
            let values = [0, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX];
            let ignored_this = 0u8;
            for a in values {
                for b in values {
                    assert_eq!(
                        less_unsigned_alias_7464(&ignored_this, &a, &b),
                        u32::from(a < b),
                        "{a:#010x} < {b:#010x}"
                    );
                }
            }
        }
    }

    #[test]
    fn less_unsigned_alias_747c_matches_unsigned_reference_edges() {
        unsafe {
            let values = [0, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX];
            let ignored_this = 0u8;
            for a in values {
                for b in values {
                    assert_eq!(
                        less_unsigned_alias_747c(&ignored_this, &a, &b),
                        u32::from(a < b),
                        "{a:#010x} < {b:#010x}"
                    );
                }
            }
        }
    }

    #[test]
    fn less_unsigned_alias_7494_matches_unsigned_reference_edges() {
        unsafe {
            let values = [0, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX];
            let ignored_this = 0u8;
            for a in values {
                for b in values {
                    assert_eq!(
                        less_unsigned_alias_7494(&ignored_this, &a, &b),
                        u32::from(a < b),
                        "{a:#010x} < {b:#010x}"
                    );
                }
            }
        }
    }


    #[test]
    fn less_unsigned_alias_7568_matches_unsigned_reference_edges() {
        unsafe {
            let values = [0, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX];
            let ignored_this = 0u8;
            for a in values {
                for b in values {
                    assert_eq!(
                        less_unsigned_alias_7568(&ignored_this, &a, &b),
                        u32::from(a < b),
                        "{a:#010x} < {b:#010x}"
                    );
                }
            }
        }
    }
    #[test]
    fn less_unsigned_alias_74c4_matches_unsigned_reference_edges() {
        unsafe {
            let values = [0, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX];
            let ignored_this = 0u8;
            for a in values {
                for b in values {
                    assert_eq!(
                        less_unsigned_alias_74c4(&ignored_this, &a, &b),
                        u32::from(a < b),
                        "{a:#010x} < {b:#010x}"
                    );
                }
            }
        }
    }

    #[test]
    fn less_unsigned_alias_74ac_matches_unsigned_reference_edges() {
        unsafe {
            let values = [0, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX];
            let ignored_this = 0u8;
            for a in values {
                for b in values {
                    assert_eq!(
                        less_unsigned_alias_74ac(&ignored_this, &a, &b),
                        u32::from(a < b),
                        "{a:#010x} < {b:#010x}"
                    );
                }
            }
        }
    }

    #[test]
    fn less_unsigned_alias_74dc_matches_unsigned_reference_edges() {
        unsafe {
            let values = [0, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX];
            let ignored_this = 0u8;
            for a in values {
                for b in values {
                    assert_eq!(
                        less_unsigned_alias_74dc(&ignored_this, &a, &b),
                        u32::from(a < b),
                        "{a:#010x} < {b:#010x}"
                    );
                }
            }
        }
    }



    #[test]
    fn not_equal_deref_compares_words_by_value() {
        unsafe {
            let one: u32 = 1;
            let other_one: u32 = 1;
            let two: u32 = 2;
            assert_eq!(not_equal_deref(&one, &two), 1);
            assert_eq!(not_equal_deref(&two, &one), 1);
            assert_eq!(not_equal_deref(&one, &other_one), 0, "by value, not by address");
            assert_eq!(not_equal_deref(&one, &one), 0);
            let min: u32 = 0;
            let max: u32 = 0xffff_ffff;
            assert_eq!(not_equal_deref(&min, &max), 1);
        }
    }

    #[test]
    fn equal_deref_f650_f668_f680_f698_f6b0_f6c8_f6e0_f6f8_f758_f770_f788_f7a0_f7b8_f7e8_f830_f860_f8a8_f8c0_f890_f8f0_f908_f920_f938_f950_f968_f980_f998_f9b0_f9c8_copies_compare_words_by_value() {
        unsafe {
            let one: u32 = 1;
            let other_one: u32 = 1;
            let two: u32 = 2;
            assert_eq!(equal_deref(&one, &other_one), 1, "by value, not by address");
            assert_eq!(equal_deref(&one, &one), 1);
            assert_eq!(equal_deref(&one, &two), 0);
            assert_eq!(equal_deref(&two, &one), 0);
            let min: u32 = 0;
            let max: u32 = 0xffff_ffff;
            assert_eq!(equal_deref(&min, &max), 0);
            assert_eq!(equal_deref(&max, &max), 1, "sign bit is not special-cased");
            // Iterator-shaped use, as the 0x083cf980 copy's callers do
            // it: compare the FIRST word of two wider records.
            let cursor = [0x083d_0000u32, 0xaaaa_aaaa];
            let end = [0x083d_0000u32, 0xbbbb_bbbb];
            let other = [0x083d_0004u32, 0xaaaa_aaaa];
            assert_eq!(equal_deref(cursor.as_ptr(), end.as_ptr()), 1,
                "trailing words are never read");
            assert_eq!(equal_deref(cursor.as_ptr(), other.as_ptr()), 0);
        }
    }

    #[test]
    fn iterator_equal_compares_only_iterator_words() {
        unsafe {
            let cursor = [0x083d_0000u32, 0xaaaa_aaaa];
            let same_node = [0x083d_0000u32, 0xbbbb_bbbb];
            let next_node = [0x083d_0004u32, 0xaaaa_aaaa];
            let zero: u32 = 0;
            let max: u32 = u32::MAX;

            assert_eq!(iterator_equal(cursor.as_ptr(), same_node.as_ptr()), 1,
                "equal values compare equal even at distinct addresses");
            assert_eq!(iterator_equal(cursor.as_ptr(), next_node.as_ptr()), 0);
            assert_eq!(iterator_equal(&zero, &max), 0);
            assert_eq!(iterator_equal(&max, &max), 1, "all word bits are compared");
        }
    }

    #[test]
    fn container_is_empty_reports_only_exact_zero() {
        unsafe {
            let mut words = [1u32; 9];
            assert_eq!(container_is_empty(words.as_ptr() as *const u8), 0);
            words[8] = 0;
            assert_eq!(container_is_empty(words.as_ptr() as *const u8), 1);
            words[8] = 2;
            assert_eq!(container_is_empty(words.as_ptr() as *const u8), 0, "not a <= 1 test");
            words[8] = u32::MAX;
            assert_eq!(container_is_empty(words.as_ptr() as *const u8), 0);
        }
    }

    #[test]
    fn container_is_empty_ignores_the_other_words() {
        unsafe {
            let mut words = [0u32; 9];
            words[8] = 7;
            assert_eq!(container_is_empty(words.as_ptr() as *const u8), 0);
            words[8] = 0;
            assert_eq!(container_is_empty(words.as_ptr() as *const u8), 1);
        }
    }

    // ---- container_element_at ----------------------------------------

    /// A container whose element-slot method hands out the address of
    /// `slots[index]`.
    #[repr(C)]
    struct FakeContainer {
        vtable: *const ElementSlotFn,
        slots: [*mut u8; 3],
    }

    static mut LAST_INDEX: usize = usize::MAX;

    unsafe extern "C" fn fake_element_slot(this: *mut u8, index: usize) -> *mut *mut u8 {
        LAST_INDEX = index;
        let container = this as *mut FakeContainer;
        core::ptr::addr_of_mut!((*container).slots[index])
    }

    #[test]
    fn element_at_dispatches_through_slot_0x40_and_derefs() {
        unsafe {
            // Only the one slot the port reads has to be real.
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            assert_eq!(container_element_at(this, 0), &mut a as *mut u8);
            assert_eq!(LAST_INDEX, 0, "the index is passed through in r1");
            assert_eq!(container_element_at(this, 1), &mut b as *mut u8);
            assert!(container_element_at(this, 2).is_null(), "NULL element, not NULL slot");
        }
    }
    #[test]
    fn element_at_alias_9bac0_dispatches_through_slot_0x40_and_derefs() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            assert_eq!(container_element_at_alias_9bac0(this, 0), &mut a as *mut u8);
            assert_eq!(LAST_INDEX, 0, "the index is passed through in r1");
            assert_eq!(container_element_at_alias_9bac0(this, 1), &mut b as *mut u8);
            assert!(container_element_at_alias_9bac0(this, 2).is_null(), "NULL element, not NULL slot");
        }
    }

    #[test]
    fn element_at_alias_5f14_dispatches_through_slot_0x40_and_derefs() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            assert_eq!(container_element_at_alias_5f14(this, 0), &mut a as *mut u8);
            assert_eq!(LAST_INDEX, 0, "the index is passed through in r1");
            assert_eq!(container_element_at_alias_5f14(this, 1), &mut b as *mut u8);
            assert!(container_element_at_alias_5f14(this, 2).is_null(), "NULL element, not NULL slot");
        }
    }

    #[test]
    fn element_at_alias_5f2c_dispatches_through_slot_0x40_and_derefs() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            assert_eq!(container_element_at_alias_5f2c(this, 0), &mut a as *mut u8);
            assert_eq!(LAST_INDEX, 0, "the index is passed through in r1");
            assert_eq!(container_element_at_alias_5f2c(this, 1), &mut b as *mut u8);
            assert!(container_element_at_alias_5f2c(this, 2).is_null(), "NULL element, not NULL slot");
        }
    }

    #[test]
    fn element_at_alias_5f44_dispatches_through_slot_0x40_and_derefs() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            assert_eq!(container_element_at_alias_5f44(this, 0), &mut a as *mut u8);
            assert_eq!(LAST_INDEX, 0, "the index is passed through in r1");
            assert_eq!(container_element_at_alias_5f44(this, 1), &mut b as *mut u8);
            assert!(container_element_at_alias_5f44(this, 2).is_null(), "NULL element, not NULL slot");
        }
    }

    #[test]
    fn element_at_alias_5f74_dispatches_through_slot_0x40_and_derefs() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            assert_eq!(container_element_at_alias_5f74(this, 0), &mut a as *mut u8);
            assert_eq!(LAST_INDEX, 0, "the index is passed through in r1");
            assert_eq!(container_element_at_alias_5f74(this, 1), &mut b as *mut u8);
            assert!(container_element_at_alias_5f74(this, 2).is_null(), "NULL element, not NULL slot");
        }
    }

    #[test]
    fn element_at_alias_5f74_matches_primary() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            for index in 0..3 {
                assert_eq!(
                    container_element_at_alias_5f74(this, index),
                    container_element_at(this, index),
                    "index {index}"
                );
            }
        }
    }

    #[test]
    fn element_at_veneer_9cef0_adjusts_to_embedded_container() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            #[repr(align(8))]
            struct AlignedOwner([u8; 4 + 0x24 + core::mem::size_of::<FakeContainer>()]);
            let mut storage = AlignedOwner([0; 4 + 0x24 + core::mem::size_of::<FakeContainer>()]);
            let owner = storage.0.as_mut_ptr().add(4);
            let container = owner.add(0x24).cast::<FakeContainer>();
            container.write(FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            });
            for index in 0..3 {
                assert_eq!(
                    container_element_at_veneer_9cef0(owner, index),
                    container_element_at_alias_5f74(container.cast(), index),
                    "index {index}"
                );
            }
        }
    }


    #[test]
    fn element_at_alias_5f44_matches_primary() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            for index in 0..3 {
                assert_eq!(
                    container_element_at_alias_5f44(this, index),
                    container_element_at(this, index),
                    "index {index}"
                );
            }
        }
    }


    /// The vtable comes out of the object, so a different one takes
    /// over — the property `heap/block_deque` relies on for element
    /// destructors.
    #[test]
    fn element_at_honors_the_object_vtable() {
        unsafe extern "C" fn other_slot(this: *mut u8, _index: usize) -> *mut *mut u8 {
            let container = this as *mut FakeContainer;
            core::ptr::addr_of_mut!((*container).slots[2])
        }
        unsafe {
            let mut vtable = [other_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut sentinel: u8 = 7;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [core::ptr::null_mut(), core::ptr::null_mut(), &mut sentinel],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            assert_eq!(container_element_at(this, 0), &mut sentinel as *mut u8);
        }
    }

    #[test]
    fn element_at_alias_68dc_dispatches_through_slot_0x40_and_derefs() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            assert_eq!(container_element_at_alias_68dc(this, 0), &mut a as *mut u8);
            assert_eq!(LAST_INDEX, 0, "the index is passed through in r1");
            assert_eq!(container_element_at_alias_68dc(this, 1), &mut b as *mut u8);
            assert!(container_element_at_alias_68dc(this, 2).is_null(), "NULL element, not NULL slot");
        }
    }

    /// Byte-identical bodies must agree on every dispatch: same vtable,
    /// same index, same element out — including the NULL-element edge.
    #[test]
    fn element_at_alias_68dc_matches_primary() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            for index in 0..3 {
                assert_eq!(
                    container_element_at_alias_68dc(this, index),
                    container_element_at(this, index),
                    "index {index}"
                );
            }
        }
    }

    #[test]
    fn element_at_alias_6870_dispatches_through_slot_0x40_and_derefs() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            assert_eq!(container_element_at_alias_6870(this, 0), &mut a as *mut u8);
            assert_eq!(LAST_INDEX, 0, "the index is passed through in r1");
            assert_eq!(container_element_at_alias_6870(this, 1), &mut b as *mut u8);
            assert!(container_element_at_alias_6870(this, 2).is_null(), "NULL element, not NULL slot");
        }
    }

    /// Byte-identical bodies must agree on every dispatch: same vtable,
    /// same index, same element out — including the NULL-element edge.
    #[test]
    fn element_at_alias_6870_matches_primary() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            for index in 0..3 {
                assert_eq!(
                    container_element_at_alias_6870(this, index),
                    container_element_at(this, index),
                    "index {index}"
                );
            }
        }
    }

    #[test]
    fn element_at_alias_689c_dispatches_through_slot_0x40_and_derefs() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            assert_eq!(container_element_at_alias_689c(this, 0), &mut a as *mut u8);
            assert_eq!(LAST_INDEX, 0, "the index is passed through in r1");
            assert_eq!(container_element_at_alias_689c(this, 1), &mut b as *mut u8);
            assert!(container_element_at_alias_689c(this, 2).is_null(), "NULL element, not NULL slot");
        }
    }

    /// Byte-identical bodies must agree on every dispatch: same vtable,
    /// same index, same element out — including the NULL-element edge.
    #[test]
    fn element_at_alias_689c_matches_primary() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            for index in 0..3 {
                assert_eq!(
                    container_element_at_alias_689c(this, index),
                    container_element_at(this, index),
                    "index {index}"
                );
            }
        }
    }

    #[test]
    fn element_at_alias_6908_dispatches_through_slot_0x40_and_derefs() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            assert_eq!(container_element_at_alias_6908(this, 0), &mut a as *mut u8);
            assert_eq!(LAST_INDEX, 0, "the index is passed through in r1");
            assert_eq!(container_element_at_alias_6908(this, 1), &mut b as *mut u8);
            assert!(container_element_at_alias_6908(this, 2).is_null(), "NULL element, not NULL slot");
        }
    }

    /// Byte-identical bodies must agree on every dispatch: same vtable,
    /// same index, same element out — including the NULL-element edge.
    #[test]
    fn element_at_alias_6908_matches_primary() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            for index in 0..3 {
                assert_eq!(
                    container_element_at_alias_6908(this, index),
                    container_element_at(this, index),
                    "index {index}"
                );
            }
        }
    }
    #[test]
    fn element_at_alias_6a68_dispatches_through_slot_0x40_and_derefs() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            assert_eq!(container_element_at_alias_6a68(this, 0), &mut a as *mut u8);
            assert_eq!(LAST_INDEX, 0, "the index is passed through in r1");
            assert_eq!(container_element_at_alias_6a68(this, 1), &mut b as *mut u8);
            assert!(container_element_at_alias_6a68(this, 2).is_null(), "NULL element, not NULL slot");
        }
    }

    /// Byte-identical bodies must agree on every dispatch: same vtable,
    /// same index, same element out — including the NULL-element edge.
    #[test]
    fn element_at_alias_6a68_matches_primary() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            for index in 0..3 {
                assert_eq!(
                    container_element_at_alias_6a68(this, index),
                    container_element_at(this, index),
                    "index {index}"
                );
            }
        }
    }

    #[test]
    fn element_at_alias_6b14_dispatches_through_slot_0x40_and_derefs() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            assert_eq!(container_element_at_alias_6b14(this, 0), &mut a as *mut u8);
            assert_eq!(LAST_INDEX, 0, "the index is passed through in r1");
            assert_eq!(container_element_at_alias_6b14(this, 1), &mut b as *mut u8);
            assert!(container_element_at_alias_6b14(this, 2).is_null(), "NULL element, not NULL slot");
        }
    }

    #[test]
    fn element_at_alias_6b14_matches_primary() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            for index in 0..3 {
                assert_eq!(
                    container_element_at_alias_6b14(this, index),
                    container_element_at(this, index),
                    "index {index}"
                );
            }
        }
    }
    #[test]
    fn element_at_alias_6b40_dispatches_through_slot_0x40_and_derefs() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            assert_eq!(container_element_at_alias_6b40(this, 0), &mut a as *mut u8);
            assert_eq!(LAST_INDEX, 0, "the index is passed through in r1");
            assert_eq!(container_element_at_alias_6b40(this, 1), &mut b as *mut u8);
            assert!(
                container_element_at_alias_6b40(this, 2).is_null(),
                "NULL element, not NULL slot"
            );
        }
    }


    #[test]
    fn element_at_alias_6b6c_dispatches_through_slot_0x40_and_derefs() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            assert_eq!(container_element_at_alias_6b6c(this, 0), &mut a as *mut u8);
            assert_eq!(LAST_INDEX, 0, "the index is passed through in r1");
            assert_eq!(container_element_at_alias_6b6c(this, 1), &mut b as *mut u8);
            assert!(container_element_at_alias_6b6c(this, 2).is_null(), "NULL element, not NULL slot");
        }
    }

    #[test]
    fn element_at_alias_6b6c_matches_primary() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            for index in 0..3 {
                assert_eq!(
                    container_element_at_alias_6b6c(this, index),
                    container_element_at(this, index),
                    "index {index}"
                );
            }
        }
    }


    #[test]
    fn element_at_alias_6bc0_dispatches_through_slot_0x40_and_derefs() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            assert_eq!(container_element_at_alias_6bc0(this, 0), &mut a as *mut u8);
            assert_eq!(LAST_INDEX, 0, "the index is passed through in r1");
            assert_eq!(container_element_at_alias_6bc0(this, 1), &mut b as *mut u8);
            assert!(container_element_at_alias_6bc0(this, 2).is_null(), "NULL element, not NULL slot");
        }
    }

    #[test]
    fn element_at_alias_6bc0_matches_primary() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            for index in 0..3 {
                assert_eq!(
                    container_element_at_alias_6bc0(this, index),
                    container_element_at(this, index),
                    "index {index}"
                );
            }
        }
    }
    #[test]
    fn element_at_alias_6bec_dispatches_through_slot_0x40_and_derefs() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            assert_eq!(container_element_at_alias_6bec(this, 0), &mut a as *mut u8);
            assert_eq!(LAST_INDEX, 0, "the index is passed through in r1");
            assert_eq!(container_element_at_alias_6bec(this, 1), &mut b as *mut u8);
            assert!(container_element_at_alias_6bec(this, 2).is_null(), "NULL element, not NULL slot");
        }
    }

    /// Byte-identical bodies must agree on every dispatch: same vtable,
    /// same index, same element out — including the NULL-element edge.
    #[test]
    fn element_at_alias_6bec_matches_primary() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            for index in 0..3 {
                assert_eq!(
                    container_element_at_alias_6bec(this, index),
                    container_element_at(this, index),
                    "index {index}"
                );
            }
        }
    }
    #[test]
    fn element_at_alias_6c6c_dispatches_through_slot_0x40_and_derefs() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            assert_eq!(container_element_at_alias_6c6c(this, 0), &mut a as *mut u8);
            assert_eq!(LAST_INDEX, 0, "the index is passed through in r1");
            assert_eq!(container_element_at_alias_6c6c(this, 1), &mut b as *mut u8);
            assert!(container_element_at_alias_6c6c(this, 2).is_null(), "NULL element, not NULL slot");
        }
    }

    /// Byte-identical bodies must agree on every dispatch: same vtable,
    /// same index, same element out — including the NULL-element edge.
    #[test]
    fn element_at_alias_6c6c_matches_primary() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut a: u8 = 1;
            let mut b: u8 = 2;
            let mut container = FakeContainer {
                vtable: vtable.as_mut_ptr(),
                slots: [&mut a, &mut b, core::ptr::null_mut()],
            };
            let this = core::ptr::addr_of_mut!(container) as *mut u8;
            for index in 0..3 {
                assert_eq!(
                    container_element_at_alias_6c6c(this, index),
                    container_element_at(this, index),
                    "index {index}"
                );
            }
        }
    }



    // ---- vector_is_empty ---------------------------------------------

    #[test]
    fn vector_is_empty_returns_a_word_sized_boolean_for_equal_bounds() {
        unsafe {
            let storage = [0u8; 2];
            let begin = storage.as_ptr() as *mut u8;
            let occupied = VectorBounds { begin, end: begin.add(1) };
            let empty = VectorBounds { begin, end: begin };
            assert_eq!(vector_is_empty(&empty), 1, "same non-NULL bound");
            assert_eq!(vector_is_empty(&occupied), 0, "one element differs");
        }
    }

    #[test]
    fn vector_is_empty_compares_pointer_values_without_dereferencing_them() {
        unsafe {
            let null = core::ptr::null_mut();
            let null_bounds = VectorBounds { begin: null, end: null };
            let nonempty = VectorBounds { begin: null, end: 0x4 as *mut u8 };
            assert_eq!(vector_is_empty(&null_bounds), 1, "NULL equals NULL");
            assert_eq!(vector_is_empty(&nonempty), 0, "only equality is empty");
        }
    }

    // ---- vector_size_elem* -------------------------------------------

    #[test]
    fn vector_size_divides_the_span_by_the_element_size() {
        unsafe {
            let storage = [0u8; 64];
            let begin = storage.as_ptr() as *mut u8;
            for elements in 0..8usize {
                for (shift, size) in [(2usize, 4usize), (3, 8), (4, 16), (5, 32)] {
                    let bounds =
                        VectorBounds { begin, end: begin.add(elements * size) };
                    let got = match shift {
                        2 => vector_size_elem4(&bounds),
                        3 => vector_size_elem8(&bounds),
                        4 => vector_size_elem16(&bounds),
                        _ => vector_size_elem32(&bounds),
                    };
                    assert_eq!(got, elements as i32, "elem size {size}");
                }
            }
        }
    }

    /// The shift is arithmetic, so a reversed vector yields a negative
    /// count rather than a huge one.
    #[test]
    fn vector_size_is_signed() {
        unsafe {
            let storage = [0u8; 64];
            let begin = storage.as_ptr() as *mut u8;
            let reversed = VectorBounds { begin: begin.add(16), end: begin };
            assert_eq!(vector_size_elem4(&reversed), -4);
            // -16 bytes / asr #3 = -2 — the 0x083d7664 copy's exact body.
            assert_eq!(vector_size_elem8(&reversed), -2);
            assert_eq!(vector_size_elem16(&reversed), -1);
        }
    }

    #[test]
    fn embedded_vector_size_elem8_uses_the_owner_vector_after_three_words() {
        unsafe {
            let storage = [0u8; 64];
            let begin = storage.as_ptr() as *mut u8;
            for (end, expected) in [
                (begin, 0),
                (begin.add(8), 1),
                (begin.add(23), 2),
                (begin.add(15), 1),
            ] {
                let owner = EmbeddedVectorSizeElem8 {
                    _prefix: [0x1111_1111, 0x2222_2222, 0x3333_3333],
                    vector: VectorBounds { begin, end },
                };
                assert_eq!(embedded_vector_size_elem8(&owner), expected);
                assert_eq!(owner._prefix, [0x1111_1111, 0x2222_2222, 0x3333_3333]);
            }

            let reversed = EmbeddedVectorSizeElem8 {
                _prefix: [0x4444_4444, 0x5555_5555, 0x6666_6666],
                vector: VectorBounds { begin: begin.add(15), end: begin },
            };
            // ARM `asr #3` rounds a negative partial span down.
            assert_eq!(embedded_vector_size_elem8(&reversed), -2);
        }
    }

    #[test]
    fn vector_size_elem4_alias_76c8_counts_normal_and_reversed_spans() {
        unsafe {
            let storage = [0u8; 32];
            let begin = storage.as_ptr() as *mut u8;
            let normal = VectorBounds { begin, end: begin.add(28) };
            assert_eq!(vector_size_elem4_alias_76c8(&normal), 7);

            // ARM `asr #2` rounds negative, non-element-aligned spans down:
            // -15 >> 2 is -4, rather than a truncating -3.
            let reversed = VectorBounds { begin: begin.add(15), end: begin };
            assert_eq!(vector_size_elem4_alias_76c8(&reversed), -4);
        }
    }

    #[test]
    fn vector_size_elem4_alias_76e8_counts_normal_and_reversed_spans() {
        unsafe {
            let storage = [0u8; 32];
            let begin = storage.as_ptr() as *mut u8;
            let normal = VectorBounds { begin, end: begin.add(28) };
            assert_eq!(vector_size_elem4_alias_76e8(&normal), 7);

            // ARM `asr #2` rounds negative, non-element-aligned spans down:
            // -15 >> 2 is -4, rather than a truncating -3.
            let reversed = VectorBounds { begin: begin.add(15), end: begin };
            assert_eq!(vector_size_elem4_alias_76e8(&reversed), -4);
        }
    }

    #[test]
    fn vector_size_elem4_alias_77cc_counts_normal_and_reversed_spans() {
        unsafe {
            let storage = [0u8; 32];
            let begin = storage.as_ptr() as *mut u8;
            let normal = VectorBounds { begin, end: begin.add(28) };
            assert_eq!(vector_size_elem4_alias_77cc(&normal), 7);

            // ARM `asr #2` rounds negative, non-element-aligned spans down:
            // -15 >> 2 is -4, rather than a truncating -3.
            let reversed = VectorBounds { begin: begin.add(15), end: begin };
            assert_eq!(vector_size_elem4_alias_77cc(&reversed), -4);
        }
    }

    #[test]
    fn vector_size_elem4_alias_78c4_counts_normal_and_reversed_spans() {
        unsafe {
            let storage = [0u8; 32];
            let begin = storage.as_ptr() as *mut u8;
            let normal = VectorBounds { begin, end: begin.add(28) };
            assert_eq!(vector_size_elem4_alias_78c4(&normal), 7);

            // ARM `asr #2` rounds negative, non-element-aligned spans down:
            // -15 >> 2 is -4, rather than a truncating -3.
            let reversed = VectorBounds { begin: begin.add(15), end: begin };
            assert_eq!(vector_size_elem4_alias_78c4(&reversed), -4);
        }
    }

    #[test]
    fn vector_size_elem4_alias_78d4_counts_normal_and_reversed_spans() {
        unsafe {
            let storage = [0u8; 32];
            let begin = storage.as_ptr() as *mut u8;
            let normal = VectorBounds { begin, end: begin.add(28) };
            assert_eq!(vector_size_elem4_alias_78d4(&normal), 7);

            // ARM `asr #2` rounds negative, non-element-aligned spans down:
            // -15 >> 2 is -4, rather than a truncating -3.
            let reversed = VectorBounds { begin: begin.add(15), end: begin };
            assert_eq!(vector_size_elem4_alias_78d4(&reversed), -4);
        }
    }

    #[test]
    fn vector_size_elem4_alias_78e4_counts_normal_and_reversed_spans() {
        unsafe {
            let storage = [0u8; 32];
            let begin = storage.as_ptr() as *mut u8;
            let normal = VectorBounds { begin, end: begin.add(28) };
            assert_eq!(vector_size_elem4_alias_78e4(&normal), 7);

            // ARM `asr #2` rounds negative, non-element-aligned spans down:
            // -15 >> 2 is -4, rather than a truncating -3.
            let reversed = VectorBounds { begin: begin.add(15), end: begin };
            assert_eq!(vector_size_elem4_alias_78e4(&reversed), -4);
        }
    }

    #[test]
    fn vector_size_elem4_alias_78f4_counts_normal_and_reversed_spans() {
        unsafe {
            let storage = [0u8; 32];
            let begin = storage.as_ptr() as *mut u8;
            let normal = VectorBounds { begin, end: begin.add(28) };
            assert_eq!(vector_size_elem4_alias_78f4(&normal), 7);

            // ARM `asr #2` rounds negative, non-element-aligned spans down:
            // -15 >> 2 is -4, rather than a truncating -3.
            let reversed = VectorBounds { begin: begin.add(15), end: begin };
            assert_eq!(vector_size_elem4_alias_78f4(&reversed), -4);
        }
    }

    #[test]
    fn vector_size_elem4_alias_7904_counts_normal_and_reversed_spans() {
        unsafe {
            let storage = [0u8; 32];
            let begin = storage.as_ptr() as *mut u8;
            let normal = VectorBounds { begin, end: begin.add(28) };
            assert_eq!(vector_size_elem4_alias_7904(&normal), 7);

            // ARM `asr #2` rounds negative, non-element-aligned spans down:
            // -15 >> 2 is -4, rather than a truncating -3.
            let reversed = VectorBounds { begin: begin.add(15), end: begin };
            assert_eq!(vector_size_elem4_alias_7904(&reversed), -4);
        }
    }

    #[test]
    fn vector_size_elem4_alias_7914_counts_normal_and_reversed_spans() {
        unsafe {
            let storage = [0u8; 32];
            let begin = storage.as_ptr() as *mut u8;
            let normal = VectorBounds { begin, end: begin.add(28) };
            assert_eq!(vector_size_elem4_alias_7914(&normal), 7);

            // ARM `asr #2` rounds negative, non-element-aligned spans down:
            // -15 >> 2 is -4, rather than a truncating -3.
            let reversed = VectorBounds { begin: begin.add(15), end: begin };
            assert_eq!(vector_size_elem4_alias_7914(&reversed), -4);
        }
    }

    #[test]
    fn vector_size_elem4_alias_7924_counts_normal_and_reversed_spans() {
        unsafe {
            let storage = [0u8; 32];
            let begin = storage.as_ptr() as *mut u8;
            let normal = VectorBounds { begin, end: begin.add(28) };
            assert_eq!(vector_size_elem4_alias_7924(&normal), 7);

            // ARM `asr #2` rounds negative, non-element-aligned spans down:
            // -15 >> 2 is -4, rather than a truncating -3.
            let reversed = VectorBounds { begin: begin.add(15), end: begin };
            assert_eq!(vector_size_elem4_alias_7924(&reversed), -4);
        }
    }

    #[test]
    fn vector_size_elem4_alias_7934_counts_normal_and_reversed_spans() {
        unsafe {
            let storage = [0u8; 32];
            let begin = storage.as_ptr() as *mut u8;
            let normal = VectorBounds { begin, end: begin.add(28) };
            assert_eq!(vector_size_elem4_alias_7934(&normal), 7);

            // ARM `asr #2` rounds negative, non-element-aligned spans down:
            // -15 >> 2 is -4, rather than a truncating -3.
            let reversed = VectorBounds { begin: begin.add(15), end: begin };
            assert_eq!(vector_size_elem4_alias_7934(&reversed), -4);
        }
    }

    #[test]
    fn vector_size_elem4_alias_7944_counts_normal_and_reversed_spans() {
        unsafe {
            let storage = [0u8; 32];
            let begin = storage.as_ptr() as *mut u8;
            let normal = VectorBounds { begin, end: begin.add(28) };
            assert_eq!(vector_size_elem4_alias_7944(&normal), 7);

            // ARM `asr #2` rounds negative, non-element-aligned spans down:
            // -15 >> 2 is -4, rather than a truncating -3.
            let reversed = VectorBounds { begin: begin.add(15), end: begin };
            assert_eq!(vector_size_elem4_alias_7944(&reversed), -4);
        }
    }


    #[test]
    fn vector_size_elem4_alias_7a38_counts_normal_and_reversed_spans() {
        unsafe {
            let storage = [0u8; 32];
            let begin = storage.as_ptr() as *mut u8;
            let normal = VectorBounds { begin, end: begin.add(28) };
            assert_eq!(vector_size_elem4_alias_7a38(&normal), 7);

            // ARM `asr #2` rounds negative, non-element-aligned spans down:
            // -15 >> 2 is -4, rather than a truncating -3.
            let reversed = VectorBounds { begin: begin.add(15), end: begin };
            assert_eq!(vector_size_elem4_alias_7a38(&reversed), -4);
        }
    }

    #[test]
    fn vector_size_elem4_alias_7a48_counts_normal_and_reversed_spans() {
        unsafe {
            let storage = [0u8; 32];
            let begin = storage.as_ptr() as *mut u8;
            let normal = VectorBounds { begin, end: begin.add(28) };
            assert_eq!(vector_size_elem4_alias_7a48(&normal), 7);

            // ARM `asr #2` rounds negative, non-element-aligned spans down:
            // -15 >> 2 is -4, rather than a truncating -3.
            let reversed = VectorBounds { begin: begin.add(15), end: begin };
            assert_eq!(vector_size_elem4_alias_7a48(&reversed), -4);
        }
    }

    #[test]
    fn vector_size_elem4_alias_7a58_counts_normal_and_reversed_spans() {
        unsafe {
            let storage = [0u8; 32];
            let begin = storage.as_ptr() as *mut u8;
            let normal = VectorBounds { begin, end: begin.add(28) };
            assert_eq!(vector_size_elem4_alias_7a58(&normal), 7);

            // ARM `asr #2` rounds negative, non-element-aligned spans down:
            // -15 >> 2 is -4, rather than a truncating -3.
            let reversed = VectorBounds { begin: begin.add(15), end: begin };
            assert_eq!(vector_size_elem4_alias_7a58(&reversed), -4);
        }
    }

    #[test]
    fn vector_size_elem4_alias_7a68_counts_normal_and_reversed_spans() {
        unsafe {
            let storage = [0u8; 32];
            let begin = storage.as_ptr() as *mut u8;
            let normal = VectorBounds { begin, end: begin.add(28) };
            assert_eq!(vector_size_elem4_alias_7a68(&normal), 7);

            // ARM `asr #2` rounds negative, non-element-aligned spans down:
            // -15 >> 2 is -4, rather than a truncating -3.
            let reversed = VectorBounds { begin: begin.add(15), end: begin };
            assert_eq!(vector_size_elem4_alias_7a68(&reversed), -4);
        }
    }

    // ---- vector_size_elem2 -------------------------------------------

    #[test]
    fn vector_size_elem2_counts_normal_and_reversed_spans() {
        unsafe {
            let storage = [0u8; 32];
            let begin = storage.as_ptr() as *mut u8;
            let normal = VectorBounds { begin, end: begin.add(14) };
            assert_eq!(vector_size_elem2(&normal), 7);

            // ARM `asr #1` rounds a negative odd span down:
            // -15 >> 1 is -8, rather than a truncating -7.
            let reversed = VectorBounds { begin: begin.add(15), end: begin };
            assert_eq!(vector_size_elem2(&reversed), -8);
        }
    }

    // ---- vector_size_elem2_clamped ----------------------------------

    #[test]
    fn vector_size_elem2_clamped_counts_forward_spans_and_clamps_the_rest() {
        unsafe {
            let storage = [0u8; 32];
            let begin = storage.as_ptr() as *mut u8;
            // 14 bytes = 7 u16 elements.
            let normal = VectorBounds { begin, end: begin.add(14) };
            assert_eq!(vector_size_elem2_clamped(&normal), 7);
            // Odd byte span: the asr #1 drops the half element.
            let odd = VectorBounds { begin, end: begin.add(13) };
            assert_eq!(vector_size_elem2_clamped(&odd), 6);
            // Empty: begin == end takes the movls arm.
            let empty = VectorBounds { begin, end: begin };
            assert_eq!(vector_size_elem2_clamped(&empty), 0);
            // Inverted: where vector_size_elem2 returns -8, the guard
            // clamps to 0.
            let reversed = VectorBounds { begin: begin.add(15), end: begin };
            assert_eq!(vector_size_elem2_clamped(&reversed), 0);
        }
    }

    /// The guard is UNSIGNED (`hi`/`ls`): a head whose end word wraps
    /// below begin is clamped, not halved into a huge positive count.
    /// Fabricated bounds are never dereferenced — the body only
    /// compares and subtracts the two head words.
    #[test]
    fn vector_size_elem2_clamped_compares_unsigned() {
        unsafe {
            let wrapped =
                VectorBounds { begin: 0xffff_fff0 as *mut u8, end: 0x10 as *mut u8 };
            assert_eq!(vector_size_elem2_clamped(&wrapped), 0);
        }
    }

    // ---- vector_size_elem12 ------------------------------------------

    #[test]
    fn vector_size_elem12_divides_the_span_by_12() {
        unsafe {
            let storage = [0u8; 120];
            let begin = storage.as_ptr() as *mut u8;
            for elements in 0..10usize {
                let bounds = VectorBounds { begin, end: begin.add(elements * 12) };
                assert_eq!(vector_size_elem12(&bounds), elements as i32);
            }
        }
    }

    /// The division is the signed truncating `__rt_sdiv`, so a reversed
    /// (negative) span truncates toward zero, not toward -inf, and a
    /// partial element is dropped.
    #[test]
    fn vector_size_elem12_is_signed_and_truncating() {
        unsafe {
            let storage = [0u8; 120];
            let begin = storage.as_ptr() as *mut u8;
            let partial = VectorBounds { begin, end: begin.add(12 * 3 + 11) };
            assert_eq!(vector_size_elem12(&partial), 3, "partial element dropped");
            let reversed = VectorBounds { begin: begin.add(13), end: begin };
            assert_eq!(vector_size_elem12(&reversed), -1, "-13 / 12 truncates to -1");
        }
    }

    // ---- vector_size_elem24 ------------------------------------------

    #[test]
    fn vector_size_elem24_divides_the_span_by_24() {
        unsafe {
            let storage = [0u8; 240];
            let begin = storage.as_ptr() as *mut u8;
            for elements in 0..10usize {
                let bounds = VectorBounds { begin, end: begin.add(elements * 24) };
                assert_eq!(vector_size_elem24(&bounds), elements as i32);
            }
        }
    }

    /// The division is the signed truncating `__rt_sdiv`, so a reversed
    /// (negative) span truncates toward zero, not toward -inf, and a
    /// partial element is dropped.
    #[test]
    fn vector_size_elem24_is_signed_and_truncating() {
        unsafe {
            let storage = [0u8; 240];
            let begin = storage.as_ptr() as *mut u8;
            let partial = VectorBounds { begin, end: begin.add(24 * 3 + 23) };
            assert_eq!(vector_size_elem24(&partial), 3, "partial element dropped");
            let reversed = VectorBounds { begin: begin.add(25), end: begin };
            assert_eq!(vector_size_elem24(&reversed), -1, "-25 / 24 truncates to -1");
        }
    }

    // ---- vector_size_elem20 ------------------------------------------

    #[test]
    fn vector_size_elem20_divides_the_span_by_20() {
        unsafe {
            let storage = [0u8; 200];
            let begin = storage.as_ptr() as *mut u8;
            for elements in 0..10usize {
                let bounds = VectorBounds { begin, end: begin.add(elements * 20) };
                assert_eq!(vector_size_elem20(&bounds), elements as i32);
            }
        }
    }

    /// The division is the signed truncating `__rt_sdiv`, so a reversed
    /// (negative) span truncates toward zero, not toward -inf, and a
    /// partial element is dropped.
    #[test]
    fn vector_size_elem20_is_signed_and_truncating() {
        unsafe {
            let storage = [0u8; 200];
            let begin = storage.as_ptr() as *mut u8;
            let partial = VectorBounds { begin, end: begin.add(20 * 3 + 19) };
            assert_eq!(vector_size_elem20(&partial), 3, "partial element dropped");
            let reversed = VectorBounds { begin: begin.add(21), end: begin };
            assert_eq!(vector_size_elem20(&reversed), -1, "-21 / 20 truncates to -1");
        }
    }

    // ---- vector_size_elem28 ------------------------------------------

    #[test]
    fn vector_size_elem28_divides_the_span_by_28() {
        unsafe {
            let storage = [0u8; 280];
            let begin = storage.as_ptr() as *mut u8;
            for elements in 0..10usize {
                let bounds = VectorBounds { begin, end: begin.add(elements * 28) };
                assert_eq!(vector_size_elem28(&bounds), elements as i32);
            }
        }
    }

    /// The division is the signed truncating `__rt_sdiv`, so a reversed
    /// (negative) span truncates toward zero, not toward -inf, and a
    /// partial element is dropped.
    #[test]
    fn vector_size_elem28_is_signed_and_truncating() {
        unsafe {
            let storage = [0u8; 280];
            let begin = storage.as_ptr() as *mut u8;
            let partial = VectorBounds { begin, end: begin.add(28 * 3 + 27) };
            assert_eq!(vector_size_elem28(&partial), 3, "partial element dropped");
            let reversed = VectorBounds { begin: begin.add(29), end: begin };
            assert_eq!(vector_size_elem28(&reversed), -1, "-29 / 28 truncates to -1");
        }
    }

    // ---- vector_size_elem40 ------------------------------------------

    #[test]
    fn vector_size_elem40_divides_the_span_by_40() {
        unsafe {
            let storage = [0u8; 400];
            let begin = storage.as_ptr() as *mut u8;
            for elements in 0..10usize {
                let bounds = VectorBounds { begin, end: begin.add(elements * 40) };
                assert_eq!(vector_size_elem40(&bounds), elements as i32);
            }
        }
    }

    /// The division is the signed truncating `__rt_sdiv`, so a reversed
    /// (negative) span truncates toward zero, not toward -inf, and a
    /// partial element is dropped.
    #[test]
    fn vector_size_elem40_is_signed_and_truncating() {
        unsafe {
            let storage = [0u8; 400];
            let begin = storage.as_ptr() as *mut u8;
            let partial = VectorBounds { begin, end: begin.add(40 * 3 + 39) };
            assert_eq!(vector_size_elem40(&partial), 3, "partial element dropped");
            let reversed = VectorBounds { begin: begin.add(41), end: begin };
            assert_eq!(vector_size_elem40(&reversed), -1, "-41 / 40 truncates to -1");
        }
    }

    // ---- vector_size_bool ------------------------------------------

    #[test]
    fn vector_size_bool_counts_words_times_32_plus_bit_offsets() {
        unsafe {
            let storage = [0u32; 8];
            let base = storage.as_ptr() as *mut u32;
            // Same word: pure bit-offset difference.
            for begin_bit in 0..32u32 {
                for end_bit in begin_bit..32 {
                    let head = VectorBoolBounds {
                        begin_word: base,
                        begin_bit,
                        end_word: base,
                        end_bit,
                    };
                    assert_eq!(vector_size_bool(&head), (end_bit - begin_bit) as i32);
                }
            }
            // Spanning words: 32 bits per word plus the end offset,
            // minus the begin offset.
            for words in 0..8usize {
                let head = VectorBoolBounds {
                    begin_word: base,
                    begin_bit: 5,
                    end_word: base.add(words),
                    end_bit: 27,
                };
                assert_eq!(vector_size_bool(&head), (words * 32 + 27 - 5) as i32);
            }
            // An empty head reads as zero, NULL word pointers included
            // (the storage itself is never dereferenced).
            let empty = VectorBoolBounds {
                begin_word: core::ptr::null_mut(),
                begin_bit: 0,
                end_word: core::ptr::null_mut(),
                end_bit: 0,
            };
            assert_eq!(vector_size_bool(&empty), 0);
        }
    }

    /// The word span uses the original's arithmetic `asr #2`, so a
    /// reversed head's negative span floors to whole words and stays
    /// negative instead of truncating toward zero.
    #[test]
    fn vector_size_bool_reversed_head_floors_the_word_span() {
        unsafe {
            let storage = [0u32; 8];
            let base = storage.as_ptr() as *mut u32;
            // -16 bytes is exactly -4 words: -128 bits, then the bit
            // offsets apply.
            let reversed = VectorBoolBounds {
                begin_word: base.add(4),
                begin_bit: 3,
                end_word: base,
                end_bit: 7,
            };
            assert_eq!(vector_size_bool(&reversed), -4 * 32 + 7 - 3);
            // -20 bytes is -4.5 words; `asr #2` floors to -5, where C
            // division would truncate to -4.
            let partial = VectorBoolBounds {
                begin_word: base.add(5),
                begin_bit: 0,
                end_word: base,
                end_bit: 0,
            };
            assert_eq!(vector_size_bool(&partial), -5 * 32, "-20 >> 2 (asr) is -5");
        }
    }

    // ---- vector_bool_iter_not_equal --------------------------------

    #[test]
    fn vector_bool_iter_not_equal_is_zero_only_when_both_fields_match() {
        unsafe {
            let storage = [0u32; 4];
            let base = storage.as_ptr() as *mut u32;
            for a_word in 0..4usize {
                for b_word in 0..4usize {
                    for a_bit in 0..32u32 {
                        for b_bit in 0..32u32 {
                            let a = VectorBoolIter { word: base.add(a_word), bit: a_bit };
                            let b = VectorBoolIter { word: base.add(b_word), bit: b_bit };
                            let want = u32::from(a_word != b_word || a_bit != b_bit);
                            assert_eq!(
                                vector_bool_iter_not_equal(&a, &b),
                                want,
                                "a=({a_word},{a_bit}) b=({b_word},{b_bit})"
                            );
                        }
                    }
                }
            }
        }
    }

    /// The word storage is never dereferenced, so NULL word pointers
    /// compare like any other address.
    #[test]
    fn vector_bool_iter_not_equal_never_touches_the_word_storage() {
        unsafe {
            let null_iter = VectorBoolIter { word: core::ptr::null_mut(), bit: 0 };
            assert_eq!(vector_bool_iter_not_equal(&null_iter, &null_iter), 0);
            let other = VectorBoolIter { word: core::ptr::null_mut(), bit: 1 };
            assert_eq!(vector_bool_iter_not_equal(&null_iter, &other), 1);
        }
    }

    // ---- vector_bool_reference_init -----------------------------

    /// Every in-range bit offset produces its single-bit mask and the
    /// word pointer is copied verbatim; the original returns `mask_ref`
    /// in r0 untouched, and so does the port.
    #[test]
    fn vector_bool_reference_init_copies_word_and_shifts_mask() {
        unsafe {
            let storage = [0u32; 4];
            let mut reference = VectorBoolReference { word: core::ptr::null_mut(), mask: 0 };
            for word_index in 0..4usize {
                for bit in 0..32u32 {
                    let iter = VectorBoolIter { word: storage.as_ptr().add(word_index) as *mut u32, bit };
                    let dst = core::ptr::addr_of_mut!(reference);
                    let returned = vector_bool_reference_init(dst, &iter);
                    assert_eq!(returned, dst, "returns mask_ref untouched");
                    assert_eq!(reference.word, iter.word, "word copied for bit {bit}");
                    assert_eq!(reference.mask, 1u32 << bit, "mask for bit {bit}");
                    // The iterator itself is never written.
                    assert_eq!(iter.bit, bit);
                }
            }
        }
    }

    /// The word storage is never dereferenced: a NULL iterator word
    /// passes straight through into the reference.
    #[test]
    fn vector_bool_reference_init_never_touches_the_word_storage() {
        unsafe {
            let mut reference = VectorBoolReference { word: 1usize as *mut u32, mask: 0xff };
            let iter = VectorBoolIter { word: core::ptr::null_mut(), bit: 7 };
            vector_bool_reference_init(core::ptr::addr_of_mut!(reference), &iter);
            assert_eq!(reference.word, core::ptr::null_mut());
            assert_eq!(reference.mask, 0x80);
        }
    }

    /// The mask shift is an ARM register `lsl`: only the low byte of
    /// the bit offset counts and a shift of 32 or more yields zero
    /// (no wraparound).
    #[test]
    fn vector_bool_reference_init_matches_arm_register_shift_edges() {
        unsafe {
            let mut reference = VectorBoolReference { word: core::ptr::null_mut(), mask: 0 };
            for (bit, want) in [(32u32, 0u32), (63, 0), (255, 0), (0x100, 1), (0x101, 2), (0x11f, 1 << 31)] {
                let iter = VectorBoolIter { word: core::ptr::null_mut(), bit };
                vector_bool_reference_init(core::ptr::addr_of_mut!(reference), &iter);
                assert_eq!(reference.mask, want, "mask for bit {bit:#x}");
            }
        }
    }

    /// Firmware heads are only guaranteed 4-byte aligned; the port
    /// must write a 4-but-not-8-aligned destination without faulting
    /// on a 64-bit host.
    #[test]
    fn vector_bool_reference_init_writes_an_unaligned_destination() {
        unsafe {
            let mut buf = [0u8; 24];
            let storage = [0u32; 1];
            let unaligned = buf.as_mut_ptr().add(4) as *mut VectorBoolReference;
            let iter = VectorBoolIter { word: storage.as_ptr() as *mut u32, bit: 5 };
            vector_bool_reference_init(unaligned, &iter);
            let word = core::ptr::read_unaligned(core::ptr::addr_of!((*unaligned).word));
            let mask = core::ptr::read_unaligned(core::ptr::addr_of!((*unaligned).mask));
            assert_eq!(word, iter.word);
            assert_eq!(mask, 0x20);
        }
    }

    // ---- vector_bool_iter_advance ---------------------------------

    /// Straight-line reference for the target's signed bit addition:
    /// absolute bit position advances by `distance`, with a Euclidean
    /// quotient/remainder fold at each 32-bit storage-word boundary.
    fn reference_advance(word_index: isize, bit: u32, distance: i32) -> (isize, u32) {
        let total = (bit as i32).wrapping_add(distance);
        (
            word_index + total.div_euclid(32) as isize,
            total.rem_euclid(32) as u32,
        )
    }

    /// Positive and negative distances, exact word boundaries, and the
    /// negative floor fold all match the direct 0x083e5f84 port.
    #[test]
    fn vector_bool_iter_advance_matches_floor_division() {
        unsafe {
            let storage = [0u32; 8];
            let base = storage.as_ptr() as *mut u32;
            for bit in 0..=32u32 {
                for distance in [-65, -33, -32, -31, -1, 0, 1, 31, 32, 33, 65] {
                    let mut iter = VectorBoolIter { word: base.add(3), bit };
                    vector_bool_iter_advance(core::ptr::addr_of_mut!(iter), distance);
                    let (want_word, want_bit) = reference_advance(3, bit, distance);
                    assert_eq!(
                        iter.word,
                        base.offset(want_word),
                        "word for {bit} + {distance}"
                    );
                    assert_eq!(iter.bit, want_bit, "bit for {bit} + {distance}");
                }
            }
        }
    }

    /// The add is 32-bit wrapping before the floor fold; extreme signed
    /// distances therefore produce the same non-dereferenced address
    /// arithmetic as the ARM registers.
    #[test]
    fn vector_bool_iter_advance_wraps_signed_distances() {
        unsafe {
            let base = 0x1000usize as *mut u32;
            for distance in [i32::MIN, i32::MAX] {
                let mut iter = VectorBoolIter { word: base, bit: 7 };
                vector_bool_iter_advance(core::ptr::addr_of_mut!(iter), distance);
                let (want_word, want_bit) = reference_advance(0, 7, distance);
                assert_eq!(iter.word, base.wrapping_offset(want_word), "word for 7 + {distance}");
                assert_eq!(iter.bit, want_bit, "bit for 7 + {distance}");
            }
        }
    }

    /// Firmware iterator heads need only be 4-byte aligned; the direct
    /// port must load and store the `{word, bit}` pair without assuming
    /// the host's pointer alignment.
    #[test]
    fn vector_bool_iter_advance_handles_unaligned_heads() {
        unsafe {
            let mut buf = [0u8; 24];
            let storage = [0u32; 8];
            let base = storage.as_ptr() as *mut u32;
            let iter = buf.as_mut_ptr().add(4) as *mut VectorBoolIter;
            core::ptr::write_unaligned(core::ptr::addr_of_mut!((*iter).word), base.add(2));
            core::ptr::write_unaligned(core::ptr::addr_of_mut!((*iter).bit), 20u32);
            vector_bool_iter_advance(iter, -45);
            let word = core::ptr::read_unaligned(core::ptr::addr_of!((*iter).word));
            let bit = core::ptr::read_unaligned(core::ptr::addr_of!((*iter).bit));
            assert_eq!(word, base.add(1));
            assert_eq!(bit, 7);
        }
    }

    // ---- vector_bool_iter_index ------------------------------------

    /// Indexing advances a copy, preserves the source, and constructs the
    /// proxy mask at a positive, a negative, and an exact word boundary.
    #[test]
    fn vector_bool_iter_index_advances_a_copy_and_builds_a_reference() {
        unsafe {
            let storage = [0u32; 8];
            let base = storage.as_ptr() as *mut u32;
            for (bit, distance) in [(3u32, 29i32), (2, -3), (31, 1)] {
                let iter = VectorBoolIter { word: base.add(3), bit };
                let mut result = VectorBoolReference { word: core::ptr::null_mut(), mask: 0 };
                let returned =
                    vector_bool_iter_index(core::ptr::addr_of_mut!(result), core::ptr::addr_of!(iter), distance);
                let (word_index, result_bit) = reference_advance(3, bit, distance);
                assert_eq!(result.word, base.offset(word_index));
                assert_eq!(result.mask, 1u32 << result_bit);
                assert_eq!(returned, core::ptr::addr_of_mut!(result));
                assert_eq!(iter.word, base.add(3));
                assert_eq!(iter.bit, bit);
            }
        }
    }

    /// The original loads the iterator into its stack temporary before
    /// constructing the output, so a 4-byte-aligned destination may overlap
    /// the source head without changing the selected proxy.
    #[test]
    fn vector_bool_iter_index_accepts_unaligned_overlapping_heads() {
        unsafe {
            let mut buf = [0u8; 32];
            let storage = [0u32; 8];
            let base = storage.as_ptr() as *mut u32;
            let iter = buf.as_mut_ptr().add(4) as *mut VectorBoolIter;
            let result = iter as *mut VectorBoolReference;
            core::ptr::write_unaligned(core::ptr::addr_of_mut!((*iter).word), base.add(4));
            core::ptr::write_unaligned(core::ptr::addr_of_mut!((*iter).bit), 2u32);
            vector_bool_iter_index(result, iter, -3);
            assert_eq!(
                core::ptr::read_unaligned(core::ptr::addr_of!((*result).word)),
                base.add(3)
            );
            assert_eq!(
                core::ptr::read_unaligned(core::ptr::addr_of!((*result).mask)),
                1 << 31
            );
        }
    }

    // ---- vector_bool_iter_increment -------------------------------

    /// The direct increment changes only the bit offset except at the
    /// 31-to-0 boundary, where it crosses one four-byte storage word.
    /// It also preserves the raw ARM wrapping behavior for a noncanonical
    /// offset and accepts a firmware-aligned head on a 64-bit host.
    #[test]
    fn vector_bool_iter_increment_advances_only_at_word_boundary() {
        unsafe {
            let storage = [0u32; 3];
            let base = storage.as_ptr() as *mut u32;
            let mut buf = [0u8; 24];
            let iter = buf.as_mut_ptr().add(4) as *mut VectorBoolIter;

            for (word, bit, want_word, want_bit) in [
                (base, 30, base, 31),
                (base, 31, base.add(1), 0),
                (base.add(2), u32::MAX, base.add(2), 0),
            ] {
                core::ptr::write_unaligned(core::ptr::addr_of_mut!((*iter).word), word);
                core::ptr::write_unaligned(core::ptr::addr_of_mut!((*iter).bit), bit);
                vector_bool_iter_increment(iter);
                assert_eq!(
                    core::ptr::read_unaligned(core::ptr::addr_of!((*iter).word)),
                    want_word,
                    "word after incrementing bit {bit}"
                );
                assert_eq!(
                    core::ptr::read_unaligned(core::ptr::addr_of!((*iter).bit)),
                    want_bit,
                    "bit after incrementing bit {bit}"
                );
            }
        }
    }

    // ---- vector_bool_iter_minus -------------------------------------

    /// The caller preserves its input while the direct advance moves a
    /// stack copy by the wrapping-negated distance, and returns that
    /// copy's word pointer rather than the sret destination.
    #[test]
    fn vector_bool_iter_minus_advances_a_copy_by_the_negated_distance() {
        unsafe {
            let storage = [0u32; 4];
            let base = storage.as_ptr() as *mut u32;
            let iter = VectorBoolIter { word: base.add(2), bit: 7 };
            let mut result = VectorBoolIter { word: core::ptr::null_mut(), bit: 0xaa };
            let returned =
                vector_bool_iter_minus(core::ptr::addr_of_mut!(result), core::ptr::addr_of!(iter), 5);
            assert_eq!(result.word, base.add(2));
            assert_eq!(result.bit, 2);
            assert_eq!(returned, result.word);
            assert_eq!(iter.word, base.add(2));
            assert_eq!(iter.bit, 7);
        }
    }

    /// `i32::MIN` negates to itself under the original `rsb`, then the
    /// direct advance performs the same floor division as its source.
    #[test]
    fn vector_bool_iter_minus_negates_the_distance_wrapping() {
        unsafe {
            let base = 0x1000usize as *mut u32;
            let iter = VectorBoolIter { word: base, bit: 7 };
            let mut result = VectorBoolIter { word: core::ptr::null_mut(), bit: 0 };
            vector_bool_iter_minus(
                core::ptr::addr_of_mut!(result),
                core::ptr::addr_of!(iter),
                i32::MIN,
            );
            let (want_word, want_bit) = reference_advance(0, 7, i32::MIN);
            assert_eq!(result.word, base.wrapping_offset(want_word));
            assert_eq!(result.bit, want_bit);
        }
    }

    /// result == iter round-trips through the original's stack temp,
    /// so an in-place `it = it - n` works.
    #[test]
    fn vector_bool_iter_minus_allows_in_place_update() {
        unsafe {
            let storage = [0u32; 4];
            let base = storage.as_ptr() as *mut u32;
            let mut iter = VectorBoolIter { word: base.add(2), bit: 3 };
            vector_bool_iter_minus(core::ptr::addr_of_mut!(iter), core::ptr::addr_of!(iter), 35);
            assert_eq!(iter.word, base.add(1));
            assert_eq!(iter.bit, 0);
        }
    }

    /// The caller's own unaligned source and destination accesses remain
    /// correct after replacing its former dispatch seam with the direct port.
    #[test]
    fn vector_bool_iter_minus_reads_and_writes_unaligned_heads() {
        unsafe {
            let mut buf = [0u8; 48];
            let storage = [0u32; 8];
            let base = storage.as_ptr() as *mut u32;
            let iter = buf.as_mut_ptr().add(4) as *mut VectorBoolIter;
            let result = buf.as_mut_ptr().add(24) as *mut VectorBoolIter;
            core::ptr::write_unaligned(core::ptr::addr_of_mut!((*iter).word), base.add(2));
            core::ptr::write_unaligned(core::ptr::addr_of_mut!((*iter).bit), 20u32);
            let returned = vector_bool_iter_minus(result, iter, 45);
            let word = core::ptr::read_unaligned(core::ptr::addr_of!((*result).word));
            let bit = core::ptr::read_unaligned(core::ptr::addr_of!((*result).bit));
            assert_eq!(word, base.add(1));
            assert_eq!(bit, 7);
            assert_eq!(returned, base.add(1));
        }
    }
    // ---- vector_bool_reference_assign -------------------------------

    /// The zero/nonzero branch follows `movs ip,r1`: zero clears exactly
    /// the selected bit and every nonzero raw C++ bool sets it.
    #[test]
    fn vector_bool_reference_assign_sets_and_clears_each_bit() {
        unsafe {
            for bit in 0..32u32 {
                let mask = 1u32 << bit;
                let initial = 0xa5a5_5a5a;
                let mut storage = [initial; 1];
                let mut reference =
                    VectorBoolReference { word: core::ptr::addr_of_mut!(storage[0]), mask };
                vector_bool_reference_assign(&mut reference, 0);
                assert_eq!(storage[0], initial & !mask, "clear bit {bit}");

                for value in [1u32, 2, 0x8000_0000, u32::MAX] {
                    storage[0] = initial & !mask;
                    vector_bool_reference_assign(&mut reference, value);
                    assert_eq!(storage[0], (initial & !mask) | mask, "set bit {bit}, value {value:#x}");
                }
            }
        }
    }

    /// A mask need not be a single bit at this ABI boundary: the exact
    /// `bic`/`orr` sequence clears or sets every selected bit and preserves
    /// every unselected bit.
    #[test]
    fn vector_bool_reference_assign_updates_only_masked_bits() {
        unsafe {
            let mut storage = [0xa5a5_5a5a; 1];
            let mut reference = VectorBoolReference {
                word: core::ptr::addr_of_mut!(storage[0]),
                mask: 0x00f0_000f,
            };
            vector_bool_reference_assign(&mut reference, 0);
            assert_eq!(storage[0], 0xa5a5_5a5a & !0x00f0_000f);
            vector_bool_reference_assign(&mut reference, 0xffff_fffe);
            assert_eq!(storage[0], (0xa5a5_5a5a & !0x00f0_000f) | 0x00f0_000f);
        }
    }

    /// Firmware proxy heads may be only 4-byte aligned; the head loads
    /// remain valid on the 64-bit host without changing the aligned storage
    /// word they select.
    #[test]
    fn vector_bool_reference_assign_reads_an_unaligned_head() {
        unsafe {
            let mut buf = [0u8; 24];
            let mut storage = [0xffff_ffffu32; 1];
            let reference = buf.as_mut_ptr().add(4) as *mut VectorBoolReference;
            core::ptr::write_unaligned(
                core::ptr::addr_of_mut!((*reference).word),
                core::ptr::addr_of_mut!(storage[0]),
            );
            core::ptr::write_unaligned(core::ptr::addr_of_mut!((*reference).mask), 0x0000_0081);
            vector_bool_reference_assign(reference, 0);
            assert_eq!(storage[0], 0xffff_ff7e);
            vector_bool_reference_assign(reference, 7);
            assert_eq!(storage[0], 0xffff_ffff);
        }
    }

    // ---- vector_bool_reference_test ---------------------------------

    /// The masked bit set answers 1, clear answers 0, across every bit
    /// position of a storage word.
    #[test]
    fn vector_bool_reference_test_reports_the_masked_bit() {
        unsafe {
            let mut storage = [0u32; 1];
            let mut reference =
                VectorBoolReference { word: core::ptr::addr_of_mut!(storage[0]), mask: 0 };
            for bit in 0..32u32 {
                let mask = 1u32 << bit;
                reference.mask = mask;
                storage[0] = mask;
                assert_eq!(vector_bool_reference_test(&reference), 1, "bit {bit} set");
                storage[0] = !mask;
                assert_eq!(vector_bool_reference_test(&reference), 0, "bit {bit} clear");
            }
        }
    }

    /// Only the masked bit counts: other bits set in the word do not
    /// leak into the answer, and a multi-bit mask ORs its bits (the
    /// `ands`/`movne` idiom tests the whole intersection).
    #[test]
    fn vector_bool_reference_test_masks_the_word_exactly() {
        unsafe {
            let mut storage = [0xffff_fffeu32; 1];
            let reference = VectorBoolReference { word: core::ptr::addr_of_mut!(storage[0]), mask: 1 };
            assert_eq!(vector_bool_reference_test(&reference), 0);
            storage[0] |= 1;
            assert_eq!(vector_bool_reference_test(&reference), 1);
            let reference = VectorBoolReference { word: core::ptr::addr_of_mut!(storage[0]), mask: 0x0000_0006 };
            storage[0] = 0x0000_0002;
            assert_eq!(vector_bool_reference_test(&reference), 1);
            storage[0] = 0x0000_0008;
            assert_eq!(vector_bool_reference_test(&reference), 0);
        }
    }

    /// Firmware heads are only guaranteed 4-byte aligned; the port
    /// must read a 4-but-not-8-aligned reference without faulting on a
    /// 64-bit host.
    #[test]
    fn vector_bool_reference_test_reads_an_unaligned_head() {
        unsafe {
            let mut buf = [0u8; 24];
            let mut storage = [0x0000_0080u32; 1];
            let unaligned = buf.as_mut_ptr().add(4) as *mut VectorBoolReference;
            core::ptr::write_unaligned(
                core::ptr::addr_of_mut!((*unaligned).word),
                core::ptr::addr_of_mut!(storage[0]),
            );
            core::ptr::write_unaligned(core::ptr::addr_of_mut!((*unaligned).mask), 0x80);
            assert_eq!(vector_bool_reference_test(unaligned), 1);
            storage[0] = 0;
            assert_eq!(vector_bool_reference_test(unaligned), 0);
        }
    }

    // ---- vector_capacity ---------------------------------------------

    #[test]
    fn vector_capacity_divides_the_allocated_span_by_24() {
        unsafe {
            let storage = [0u8; 240];
            let begin = storage.as_ptr() as *mut u8;
            for elements in 0..10usize {
                let head = VectorStorage {
                    begin,
                    // `end` is not read by capacity; set it anywhere in
                    // the allocation to keep the head plausible.
                    end: begin.add(elements * 12),
                    end_of_storage: begin.add(elements * 24),
                };
                assert_eq!(vector_capacity(&head), elements as i32);
            }
        }
    }

    /// The division is the signed truncating `__rt_sdiv`, so a reversed
    /// (negative) span truncates toward zero, not toward -inf, and a
    /// partial element is dropped.
    #[test]
    fn vector_capacity_is_signed_and_truncating() {
        unsafe {
            let storage = [0u8; 240];
            let begin = storage.as_ptr() as *mut u8;
            let head = VectorStorage {
                begin,
                end: begin,
                end_of_storage: begin.add(24 * 3 + 23),
            };
            assert_eq!(vector_capacity(&head), 3, "partial element dropped");
            let reversed = VectorStorage {
                begin: begin.add(25),
                end: begin,
                end_of_storage: begin,
            };
            assert_eq!(vector_capacity(&reversed), -1, "-25 / 24 truncates to -1");
        }
    }

    // ---- vector_capacity_elem12 --------------------------------------

    #[test]
    fn vector_capacity_elem12_divides_the_allocated_span_by_12() {
        unsafe {
            let storage = [0u8; 120];
            let begin = storage.as_ptr() as *mut u8;
            for elements in 0..10usize {
                let head = VectorStorage {
                    begin,
                    // `end` is not read by capacity; set it anywhere in
                    // the allocation to keep the head plausible.
                    end: begin.add(elements * 6),
                    end_of_storage: begin.add(elements * 12),
                };
                assert_eq!(vector_capacity_elem12(&head), elements as i32);
            }
        }
    }

    /// The division is the signed truncating `__rt_sdiv`, so a reversed
    /// (negative) span truncates toward zero, not toward -inf, and a
    /// partial element is dropped.
    #[test]
    fn vector_capacity_elem12_is_signed_and_truncating() {
        unsafe {
            let storage = [0u8; 120];
            let begin = storage.as_ptr() as *mut u8;
            let head = VectorStorage {
                begin,
                end: begin,
                end_of_storage: begin.add(12 * 3 + 11),
            };
            assert_eq!(vector_capacity_elem12(&head), 3, "partial element dropped");
            let reversed = VectorStorage {
                begin: begin.add(13),
                end: begin,
                end_of_storage: begin,
            };
            assert_eq!(vector_capacity_elem12(&reversed), -1, "-13 / 12 truncates to -1");
        }
    }

    // ---- vector_capacity_elem16 --------------------------------------

    #[test]
    fn vector_capacity_elem16_shifts_the_allocated_span_by_4() {
        unsafe {
            let storage = [0u8; 160];
            let begin = storage.as_ptr() as *mut u8;
            for elements in 0..10usize {
                let head = VectorStorage {
                    begin,
                    // `end` is not read by capacity; set it anywhere in
                    // the allocation to keep the head plausible.
                    end: begin.add(elements * 8),
                    end_of_storage: begin.add(elements * 16),
                };
                assert_eq!(vector_capacity_elem16(&head), elements as i32);
            }
        }
    }

    /// The shift is arithmetic, so a reversed (negative) span stays
    /// negative (arithmetic shift rounds toward -inf, unlike the divide
    /// members' truncation), and a partial element is dropped.
    #[test]
    fn vector_capacity_elem16_is_signed_and_floor_shifting() {
        unsafe {
            let storage = [0u8; 160];
            let begin = storage.as_ptr() as *mut u8;
            let head = VectorStorage {
                begin,
                end: begin,
                end_of_storage: begin.add(16 * 3 + 15),
            };
            assert_eq!(vector_capacity_elem16(&head), 3, "partial element dropped");
            let reversed = VectorStorage {
                begin: begin.add(17),
                end: begin,
                end_of_storage: begin,
            };
            assert_eq!(vector_capacity_elem16(&reversed), -2, "-17 >> 4 (asr) is -2");
        }
    }

    // ---- vector_capacity_elem24_copy_77ec -----------------------------

    #[test]
    fn vector_capacity_elem24_copy_77ec_divides_the_allocated_span_by_24() {
        unsafe {
            let storage = [0u8; 240];
            let begin = storage.as_ptr() as *mut u8;
            for elements in 0..10usize {
                let head = VectorStorage {
                    begin,
                    // `end` is not read by capacity; set it anywhere in
                    // the allocation to keep the head plausible.
                    end: begin.add(elements * 12),
                    end_of_storage: begin.add(elements * 24),
                };
                assert_eq!(vector_capacity_elem24_copy_77ec(&head), elements as i32);
            }
        }
    }

    /// The division is the signed truncating `__rt_sdiv`, so a reversed
    /// (negative) span truncates toward zero, not toward -inf, and a
    /// partial element is dropped — matching the primary
    /// [`vector_capacity`] byte for byte.
    #[test]
    fn vector_capacity_elem24_copy_77ec_is_signed_and_truncating() {
        unsafe {
            let storage = [0u8; 240];
            let begin = storage.as_ptr() as *mut u8;
            let head = VectorStorage {
                begin,
                end: begin,
                end_of_storage: begin.add(24 * 3 + 23),
            };
            assert_eq!(vector_capacity_elem24_copy_77ec(&head), 3, "partial element dropped");
            let reversed = VectorStorage {
                begin: begin.add(25),
                end: begin,
                end_of_storage: begin,
            };
            assert_eq!(
                vector_capacity_elem24_copy_77ec(&reversed),
                -1,
                "-25 / 24 truncates to -1"
            );
            assert_eq!(
                vector_capacity_elem24_copy_77ec(&reversed),
                vector_capacity(&reversed),
                "byte-identical twin of the 24-byte primary"
            );
        }
    }

    // ---- vector_capacity_elem40 --------------------------------------

    #[test]
    fn vector_capacity_elem40_divides_the_allocated_span_by_40() {
        unsafe {
            let storage = [0u8; 400];
            let begin = storage.as_ptr() as *mut u8;
            for elements in 0..10usize {
                let head = VectorStorage {
                    begin,
                    // `end` is not read by capacity; set it anywhere in
                    // the allocation to keep the head plausible.
                    end: begin.add(elements * 20),
                    end_of_storage: begin.add(elements * 40),
                };
                assert_eq!(vector_capacity_elem40(&head), elements as i32);
            }
        }
    }

    /// The division is the signed truncating `__rt_sdiv`, so a reversed
    /// (negative) span truncates toward zero, not toward -inf, and a
    /// partial element is dropped.
    #[test]
    fn vector_capacity_elem40_is_signed_and_truncating() {
        unsafe {
            let storage = [0u8; 400];
            let begin = storage.as_ptr() as *mut u8;
            let head = VectorStorage {
                begin,
                end: begin,
                end_of_storage: begin.add(40 * 3 + 39),
            };
            assert_eq!(vector_capacity_elem40(&head), 3, "partial element dropped");
            let reversed = VectorStorage {
                begin: begin.add(41),
                end: begin,
                end_of_storage: begin,
            };
            assert_eq!(vector_capacity_elem40(&reversed), -1, "-41 / 40 truncates to -1");
        }
    }

    // ---- vector_capacity_elem8 ---------------------------------------

    #[test]
    fn vector_capacity_elem8_shifts_the_allocated_span_by_3() {
        unsafe {
            let storage = [0u8; 80];
            let begin = storage.as_ptr() as *mut u8;
            for elements in 0..10usize {
                let head = VectorStorage {
                    begin,
                    // `end` is not read by capacity; set it anywhere in
                    // the allocation to keep the head plausible.
                    end: begin.add(elements * 4),
                    end_of_storage: begin.add(elements * 8),
                };
                assert_eq!(vector_capacity_elem8(&head), elements as i32);
            }
        }
    }

    /// The shift is arithmetic, so a reversed (negative) span stays
    /// negative (arithmetic shift rounds toward -inf, unlike the divide
    /// members' truncation), and a partial element is dropped.
    #[test]
    fn vector_capacity_elem8_is_signed_and_floor_shifting() {
        unsafe {
            let storage = [0u8; 80];
            let begin = storage.as_ptr() as *mut u8;
            let head = VectorStorage {
                begin,
                end: begin,
                end_of_storage: begin.add(8 * 3 + 7),
            };
            assert_eq!(vector_capacity_elem8(&head), 3, "partial element dropped");
            let reversed = VectorStorage {
                begin: begin.add(9),
                end: begin,
                end_of_storage: begin,
            };
            assert_eq!(vector_capacity_elem8(&reversed), -2, "-9 >> 3 (asr) is -2");
        }
    }

    // ---- vector_capacity_elem4 ---------------------------------------

    #[test]
    fn vector_capacity_elem4_shifts_the_allocated_span_by_2() {
        unsafe {
            let storage = [0u8; 40];
            let begin = storage.as_ptr() as *mut u8;
            for elements in 0..10usize {
                let head = VectorStorage {
                    begin,
                    // `end` is not read by capacity; set it anywhere in
                    // the allocation to keep the head plausible.
                    end: begin.add(elements * 2),
                    end_of_storage: begin.add(elements * 4),
                };
                assert_eq!(vector_capacity_elem4(&head), elements as i32);
            }
        }
    }

    /// The shift is arithmetic, so a reversed (negative) span stays
    /// negative (arithmetic shift rounds toward -inf, unlike the divide
    /// members' truncation), and a partial element is dropped.
    #[test]
    fn vector_capacity_elem4_is_signed_and_floor_shifting() {
        unsafe {
            let storage = [0u8; 40];
            let begin = storage.as_ptr() as *mut u8;
            let head = VectorStorage {
                begin,
                end: begin,
                end_of_storage: begin.add(4 * 3 + 3),
            };
            assert_eq!(vector_capacity_elem4(&head), 3, "partial element dropped");
            let reversed = VectorStorage {
                begin: begin.add(5),
                end: begin,
                end_of_storage: begin,
            };
            assert_eq!(vector_capacity_elem4(&reversed), -2, "-5 >> 2 (asr) is -2");
        }
    }

    // ---- vector_capacity_elem20 --------------------------------------

    #[test]
    fn vector_capacity_elem20_divides_the_allocated_span_by_20() {
        unsafe {
            let storage = [0u8; 200];
            let begin = storage.as_ptr() as *mut u8;
            for elements in 0..10usize {
                let head = VectorStorage {
                    begin,
                    // `end` is not read by capacity; set it anywhere in
                    // the allocation to keep the head plausible.
                    end: begin.add(elements * 10),
                    end_of_storage: begin.add(elements * 20),
                };
                assert_eq!(vector_capacity_elem20(&head), elements as i32);
            }
        }
    }

    /// The division is the signed truncating `__rt_sdiv`, so a reversed
    /// (negative) span truncates toward zero, not toward -inf, and a
    /// partial element is dropped.
    #[test]
    fn vector_capacity_elem20_is_signed_and_truncating() {
        unsafe {
            let storage = [0u8; 200];
            let begin = storage.as_ptr() as *mut u8;
            let head = VectorStorage {
                begin,
                end: begin,
                end_of_storage: begin.add(20 * 3 + 19),
            };
            assert_eq!(vector_capacity_elem20(&head), 3, "partial element dropped");
            let reversed = VectorStorage {
                begin: begin.add(21),
                end: begin,
                end_of_storage: begin,
            };
            assert_eq!(vector_capacity_elem20(&reversed), -1, "-21 / 20 truncates to -1");
        }
    }

    // ---- array_at_checked --------------------------------------------

    #[test]
    fn array_at_checked_bounds() {
        unsafe {
            let mut a: u8 = 10;
            let mut b: u8 = 20;
            let mut slots: [*mut u8; 2] = [&mut a, &mut b];
            let array = PtrArray { base: slots.as_mut_ptr(), count: 2 };
            assert_eq!(array_at_checked(&array, 0), &mut a as *mut u8);
            assert_eq!(array_at_checked(&array, 1), &mut b as *mut u8);
            assert!(array_at_checked(&array, 2).is_null(), "count is exclusive");
            assert!(array_at_checked(&array, 99).is_null());
        }
    }

    /// The compare is signed: a negative index is rejected, not
    /// reinterpreted as a huge unsigned one.
    #[test]
    fn array_at_checked_rejects_negative_indices() {
        unsafe {
            let mut a: u8 = 10;
            let mut slots: [*mut u8; 1] = [&mut a];
            let array = PtrArray { base: slots.as_mut_ptr(), count: 1 };
            assert!(array_at_checked(&array, -1).is_null());
            assert!(array_at_checked(&array, i32::MIN).is_null());
        }
    }

    /// An empty (or negatively-sized) array never loads `base`, so a
    /// garbage base pointer is harmless — the original only loads it on
    /// the in-range path.
    #[test]
    fn array_at_checked_never_touches_an_empty_base() {
        unsafe {
            let array = PtrArray { base: 0x5555 as *mut *mut u8, count: 0 };
            assert!(array_at_checked(&array, 0).is_null());
            let negative = PtrArray { base: 0x5555 as *mut *mut u8, count: -1 };
            assert!(array_at_checked(&negative, 0).is_null());
        }
    }

    #[repr(C)]
    struct SearchString<const N: usize> {
        rep: StringRep,
        data: [u8; N],
    }

    fn search_string<const N: usize>(data: [u8; N]) -> SearchString<N> {
        SearchString {
            rep: StringRep { refcount: 0, capacity: N as u32, length: N as u32 },
            data,
        }
    }

    fn search_owner(
        records: &mut [CxxStringPair],
        length: usize,
    ) -> CxxStringPairVector {
        CxxStringPairVector {
            prefix: 0,
            begin: records.as_mut_ptr(),
            end: unsafe { records.as_mut_ptr().add(length) },
        }
    }

    #[test]
    fn cxx_vector_find_equal_writes_the_matching_record() {
        let mut first = search_string(*b"one");
        let mut second = search_string(*b"two");
        let mut needle_data = search_string(*b"two");
        let mut records = [
            CxxStringPair { first: first.data.as_mut_ptr(), second: core::ptr::null_mut() },
            CxxStringPair { first: second.data.as_mut_ptr(), second: core::ptr::null_mut() },
        ];
        let record_count = records.len();
        let owner = search_owner(&mut records, record_count);
        let mut needle = needle_data.data.as_mut_ptr();
        let mut out = core::ptr::null_mut();
        unsafe {
            assert_eq!(cxx_vector_find_equal(&owner, &mut needle, &mut out), 1);
            assert_eq!(out as usize, (&mut records[1] as *mut CxxStringPair) as usize);
        }
    }

    #[test]
    fn cxx_vector_find_equal_leaves_out_on_a_miss() {
        let mut first = search_string(*b"one");
        let mut needle_data = search_string(*b"two");
        let mut records =
            [CxxStringPair { first: first.data.as_mut_ptr(), second: core::ptr::null_mut() }];
        let record_count = records.len();
        let owner = search_owner(&mut records, record_count);
        let mut needle = needle_data.data.as_mut_ptr();
        let sentinel = 0x4321usize as *mut CxxStringPair;
        let mut out = sentinel;
        unsafe {
            assert_eq!(cxx_vector_find_equal(&owner, &mut needle, &mut out), 0);
            assert_eq!(out, sentinel);
        }
    }

    #[test]
    fn cxx_vector_find_equal_returns_the_first_equal_record() {
        let mut first = search_string(*b"key");
        let mut second = search_string(*b"key");
        let mut needle_data = search_string(*b"key");
        let mut records = [
            CxxStringPair { first: first.data.as_mut_ptr(), second: core::ptr::null_mut() },
            CxxStringPair { first: second.data.as_mut_ptr(), second: core::ptr::null_mut() },
        ];
        let record_count = records.len();
        let owner = search_owner(&mut records, record_count);
        let mut needle = needle_data.data.as_mut_ptr();
        let mut out = core::ptr::null_mut();
        unsafe {
            assert_eq!(cxx_vector_find_equal(&owner, &mut needle, &mut out), 1);
            assert_eq!(out, records.as_mut_ptr());
        }
    }

    #[test]
    fn cxx_vector_find_equal_stops_at_the_end_bound() {
        let mut first = search_string(*b"one");
        let mut excluded = search_string(*b"key");
        let mut needle_data = search_string(*b"key");
        let mut records = [
            CxxStringPair { first: first.data.as_mut_ptr(), second: core::ptr::null_mut() },
            CxxStringPair { first: excluded.data.as_mut_ptr(), second: core::ptr::null_mut() },
        ];
        let owner = search_owner(&mut records, 1);
        let mut needle = needle_data.data.as_mut_ptr();
        let sentinel = 0x4321usize as *mut CxxStringPair;
        let mut out = sentinel;
        unsafe {
            assert_eq!(cxx_vector_find_equal(&owner, &mut needle, &mut out), 0);
            assert_eq!(out, sentinel);
        }
    }

    // ---- deque_iter_advance_copy_elem4 -------------------------------

    /// Serializes swaps of [`DEQUE_ITER_ADVANCE_ELEM4_OPS`] across these
    /// tests.
    static DEQUE_ITER_ADVANCE_ELEM4_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct DequeIterAdvanceElem4Guard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for DequeIterAdvanceElem4Guard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(DEQUE_ITER_ADVANCE_ELEM4_OPS)
                    .write_volatile(DEFAULT_DEQUE_ITER_ADVANCE_ELEM4_OPS);
            }
        }
    }

    fn deque_iter_advance_elem4_guard() -> DequeIterAdvanceElem4Guard {
        let lock = DEQUE_ITER_ADVANCE_ELEM4_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        DequeIterAdvanceElem4Guard { _lock: lock }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct DequeIterAdvanceCall {
        iter: usize,
        distance: i32,
        source: [usize; 4],
    }

    static mut DEQUE_ITER_ADVANCE_ELEM4_CALLS: Vec<DequeIterAdvanceCall> = Vec::new();
    static mut DEQUE_ITER_ADVANCE_ELEM4_RETURN: *mut DequeIter = core::ptr::null_mut();

    unsafe extern "C" fn recording_deque_iter_advance_elem4(
        iter: *mut DequeIter,
        distance: i32,
    ) -> *mut DequeIter {
        (*core::ptr::addr_of_mut!(DEQUE_ITER_ADVANCE_ELEM4_CALLS)).push(DequeIterAdvanceCall {
            iter: iter as usize,
            distance,
            source: [
                (*iter).cur as usize,
                (*iter).seg_base as usize,
                (*iter).seg_end as usize,
                (*iter).seg_slot as usize,
            ],
        });
        let returned = core::ptr::read_volatile(core::ptr::addr_of!(
            DEQUE_ITER_ADVANCE_ELEM4_RETURN
        ));
        if returned.is_null() {
            (*iter).cur = 0x1111usize as *mut u8;
            (*iter).seg_base = 0x2222usize as *mut u8;
            (*iter).seg_end = 0x3333usize as *mut u8;
            (*iter).seg_slot = 0x4444usize as *mut *mut u8;
            iter
        } else {
            returned
        }
    }

    unsafe fn install_recording_deque_iter_advance_elem4() {
        (*core::ptr::addr_of_mut!(DEQUE_ITER_ADVANCE_ELEM4_CALLS)).clear();
        core::ptr::addr_of_mut!(DEQUE_ITER_ADVANCE_ELEM4_RETURN)
            .write_volatile(core::ptr::null_mut());
        core::ptr::addr_of_mut!(DEQUE_ITER_ADVANCE_ELEM4_OPS)
            .write_volatile(DequeIterAdvanceElem4Ops {
                advance: recording_deque_iter_advance_elem4,
            });
    }

    #[test]
    fn deque_iter_advance_copy_elem4_advances_a_private_copy_by_a_negative_distance() {
        let _guard = deque_iter_advance_elem4_guard();
        unsafe { install_recording_deque_iter_advance_elem4() };
        let source = DequeIter {
            cur: 0x10usize as *mut u8,
            seg_base: 0x20usize as *mut u8,
            seg_end: 0x30usize as *mut u8,
            seg_slot: 0x40usize as *mut *mut u8,
        };
        let mut dst = DequeIter::NULL;

        let returned = unsafe { deque_iter_advance_copy_elem4(&mut dst, &source, -7) };

        assert!(returned == &mut dst as *mut DequeIter);
        let calls = unsafe { &*core::ptr::addr_of!(DEQUE_ITER_ADVANCE_ELEM4_CALLS) };
        assert_eq!(calls.len(), 1);
        assert_ne!(calls[0].iter, &source as *const DequeIter as usize);
        assert_ne!(calls[0].iter, &dst as *const DequeIter as usize);
        assert_eq!(calls[0].distance, -7);
        assert_eq!(
            calls[0].source,
            [0x10, 0x20, 0x30, 0x40],
            "the helper receives a stack copy, with its signed distance untouched"
        );
        assert_eq!(source.cur as usize, 0x10, "source cur is not mutated");
        assert_eq!(source.seg_base as usize, 0x20, "source base is not mutated");
        assert_eq!(source.seg_end as usize, 0x30, "source end is not mutated");
        assert_eq!(source.seg_slot as usize, 0x40, "source slot is not mutated");
        assert_eq!(dst.cur as usize, 0x1111);
        assert_eq!(dst.seg_base as usize, 0x2222);
        assert_eq!(dst.seg_end as usize, 0x3333);
        assert_eq!(dst.seg_slot as usize, 0x4444);
    }
    #[test]
    fn deque_element_at_returns_null_without_advancing_an_empty_target_layout_deque() {
        let _guard = deque_iter_advance_elem4_guard();
        unsafe { install_recording_deque_iter_advance_elem4() };
        let words = [0u32; 12];

        let result = unsafe { deque_element_at(words.as_ptr() as *const u8, i32::MIN) };

        assert!(result.is_null());
        let calls = unsafe { &*core::ptr::addr_of!(DEQUE_ITER_ADVANCE_ELEM4_CALLS) };
        assert!(calls.is_empty());
    }

    #[test]
    fn deque_element_at_advances_a_private_iterator_from_target_words() {
        let _guard = deque_iter_advance_elem4_guard();
        unsafe { install_recording_deque_iter_advance_elem4() };
        let mut words = [0u32; 12];
        words[1..5].copy_from_slice(&[0x10, 0x20, 0x30, 0x40]);
        words[9] = 1;

        let result = unsafe { deque_element_at(words.as_ptr() as *const u8, -7) };

        assert_eq!(result as usize, 0x1111);
        let calls = unsafe { &*core::ptr::addr_of!(DEQUE_ITER_ADVANCE_ELEM4_CALLS) };
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].distance, -7);
        assert_eq!(calls[0].source, [0x10, 0x20, 0x30, 0x40]);
    }

    #[test]
    fn deque_iter_advance_copy_elem4_copies_the_helper_return_for_minimum_distance() {
        let _guard = deque_iter_advance_elem4_guard();
        unsafe { install_recording_deque_iter_advance_elem4() };
        let source = DequeIter {
            cur: 0xa0usize as *mut u8,
            seg_base: 0xb0usize as *mut u8,
            seg_end: 0xc0usize as *mut u8,
            seg_slot: 0xd0usize as *mut *mut u8,
        };
        let mut helper_result = DequeIter {
            cur: 0xaaaausize as *mut u8,
            seg_base: 0xbbbbusize as *mut u8,
            seg_end: 0xccccusize as *mut u8,
            seg_slot: 0xddddusize as *mut *mut u8,
        };
        let mut dst = DequeIter::NULL;
        unsafe {
            core::ptr::addr_of_mut!(DEQUE_ITER_ADVANCE_ELEM4_RETURN)
                .write_volatile(&mut helper_result);
        }

        let returned =
            unsafe { deque_iter_advance_copy_elem4(&mut dst, &source, i32::MIN) };

        assert!(returned == &mut dst as *mut DequeIter);
        let calls = unsafe { &*core::ptr::addr_of!(DEQUE_ITER_ADVANCE_ELEM4_CALLS) };
        assert_eq!(calls.len(), 1);
        assert_ne!(calls[0].iter, &source as *const DequeIter as usize);
        assert_ne!(calls[0].iter, &dst as *const DequeIter as usize);
        assert_eq!(calls[0].distance, i32::MIN);
        assert_eq!(calls[0].source, [0xa0, 0xb0, 0xc0, 0xd0]);
        assert_eq!(dst.cur as usize, 0xaaaa);
        assert_eq!(dst.seg_base as usize, 0xbbbb);
        assert_eq!(dst.seg_end as usize, 0xcccc);
        assert_eq!(dst.seg_slot as usize, 0xdddd);
    }

    #[test]
    fn deque_iter_retreat_copy_elem4_retreats_a_private_copy() {
        let _guard = deque_iter_advance_elem4_guard();
        unsafe { install_recording_deque_iter_advance_elem4() };
        let source = DequeIter {
            cur: 0x10usize as *mut u8,
            seg_base: 0x20usize as *mut u8,
            seg_end: 0x30usize as *mut u8,
            seg_slot: 0x40usize as *mut *mut u8,
        };
        let mut dst = DequeIter::NULL;

        let returned = unsafe { deque_iter_retreat_copy_elem4(&mut dst, &source, 7) };

        assert_eq!(returned, &mut dst as *mut DequeIter);
        let calls = unsafe { &*core::ptr::addr_of!(DEQUE_ITER_ADVANCE_ELEM4_CALLS) };
        assert_eq!(calls.len(), 1);
        assert_ne!(calls[0].iter, &source as *const DequeIter as usize);
        assert_ne!(calls[0].iter, &dst as *const DequeIter as usize);
        assert_eq!(calls[0].distance, -7);
        assert_eq!(calls[0].source, [0x10, 0x20, 0x30, 0x40]);
        assert_eq!(source.cur as usize, 0x10);
        assert_eq!(source.seg_base as usize, 0x20);
        assert_eq!(source.seg_end as usize, 0x30);
        assert_eq!(source.seg_slot as usize, 0x40);
        assert_eq!(dst.cur as usize, 0x1111);
        assert_eq!(dst.seg_base as usize, 0x2222);
        assert_eq!(dst.seg_end as usize, 0x3333);
        assert_eq!(dst.seg_slot as usize, 0x4444);
    }

    #[test]
    fn deque_iter_retreat_copy_elem4_wraps_minimum_distance_and_copies_return() {
        let _guard = deque_iter_advance_elem4_guard();
        unsafe { install_recording_deque_iter_advance_elem4() };
        let source = DequeIter {
            cur: 0xa0usize as *mut u8,
            seg_base: 0xb0usize as *mut u8,
            seg_end: 0xc0usize as *mut u8,
            seg_slot: 0xd0usize as *mut *mut u8,
        };
        let mut helper_result = DequeIter {
            cur: 0xaaaausize as *mut u8,
            seg_base: 0xbbbbusize as *mut u8,
            seg_end: 0xccccusize as *mut u8,
            seg_slot: 0xddddusize as *mut *mut u8,
        };
        let mut dst = DequeIter::NULL;
        unsafe {
            core::ptr::addr_of_mut!(DEQUE_ITER_ADVANCE_ELEM4_RETURN)
                .write_volatile(&mut helper_result);
        }

        let returned = unsafe { deque_iter_retreat_copy_elem4(&mut dst, &source, i32::MIN) };

        assert_eq!(returned, &mut dst as *mut DequeIter);
        let calls = unsafe { &*core::ptr::addr_of!(DEQUE_ITER_ADVANCE_ELEM4_CALLS) };
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].distance, i32::MIN);
        assert_eq!(calls[0].source, [0xa0, 0xb0, 0xc0, 0xd0]);
        assert_eq!(dst.cur as usize, 0xaaaa);
        assert_eq!(dst.seg_base as usize, 0xbbbb);
        assert_eq!(dst.seg_end as usize, 0xcccc);
        assert_eq!(dst.seg_slot as usize, 0xdddd);
    }

    // ---- vector_push_back_elem12 --------------------------------------

    /// Serializes swaps of [`VECTOR_PUSH_BACK_ELEM12_OPS`] across this
    /// module's tests.
    static PUSH_BACK_ELEM12_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Restores the ops seam even if a test panics mid-run.
    struct PushBackElem12Guard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for PushBackElem12Guard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(VECTOR_PUSH_BACK_ELEM12_OPS)
                    .write_volatile(DEFAULT_VECTOR_PUSH_BACK_ELEM12_OPS);
            }
        }
    }

    fn push_back_elem12_guard() -> PushBackElem12Guard {
        let lock = PUSH_BACK_ELEM12_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        PushBackElem12Guard { _lock: lock }
    }

    /// One observed insert_aux call.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct InsertAux {
        vector: usize,
        position: usize,
        element: [u32; 3],
    }

    static mut INSERT_AUX_CALLS: Vec<InsertAux> = Vec::new();

    unsafe extern "C" fn recording_insert_aux(
        vector: *mut VectorStorage,
        position: *mut u8,
        element: *const u32,
    ) {
        (*core::ptr::addr_of_mut!(INSERT_AUX_CALLS)).push(InsertAux {
            vector: vector as usize,
            position: position as usize,
            element: [
                element.read(),
                element.add(1).read(),
                element.add(2).read(),
            ],
        });
    }

    unsafe fn install_recording_insert_aux() {
        (*core::ptr::addr_of_mut!(INSERT_AUX_CALLS)).clear();
        core::ptr::addr_of_mut!(VECTOR_PUSH_BACK_ELEM12_OPS)
            .write_volatile(VectorPushBackElem12Ops {
                insert_aux: recording_insert_aux,
            });
    }

    fn insert_aux_calls() -> Vec<InsertAux> {
        unsafe { (*core::ptr::addr_of!(INSERT_AUX_CALLS)).clone() }
    }

    /// Vector storage with poison guard words on both sides, so a write
    /// outside the promised slot shows up as a changed guard.
    #[repr(C)]
    struct GuardedStorage {
        before: u64,
        elements: [u32; 9], // three 12-byte elements
        after: u64,
    }

    const GUARD: u64 = 0x5a5a_5a5a_5a5a_5a5a;

    #[test]
    fn push_back_elem12_appends_the_full_element_when_capacity_remains() {
        let _guard = push_back_elem12_guard();
        unsafe { install_recording_insert_aux() };
        let mut storage = GuardedStorage {
            before: GUARD,
            elements: [0; 9],
            after: GUARD,
        };
        let begin = core::ptr::addr_of_mut!(storage.elements).cast::<u8>();
        // One element already present, room for two more.
        storage.elements[0] = 0xaaaa_0001;
        storage.elements[1] = 0xaaaa_0002;
        storage.elements[2] = 0xaaaa_0003;
        let mut vector = VectorStorage {
            begin,
            end: unsafe { begin.add(12) },
            end_of_storage: unsafe { begin.add(36) },
        };

        unsafe {
            vector_push_back_elem12(&mut vector, 0x1122_3344, 0x5566_7788, 0xdead_beef);
        }

        assert_eq!(vector.begin, begin, "begin untouched");
        assert_eq!(vector.end, unsafe { begin.add(24) }, "end advanced by 12");
        assert_eq!(vector.end_of_storage, unsafe { begin.add(36) }, "capacity untouched");
        assert_eq!(
            storage.elements,
            [
                0xaaaa_0001, 0xaaaa_0002, 0xaaaa_0003, // pre-existing element
                0x1122_3344, 0x5566_7788, 0xdead_beef, // appended element
                0, 0, 0,                               // spare capacity
            ],
            "all three words stored, word2 in FULL (the original's strb is redundant)"
        );
        assert_eq!(storage.before, GUARD, "prefix guard");
        assert_eq!(storage.after, GUARD, "suffix guard");
        assert!(insert_aux_calls().is_empty(), "no grow on the fast path");
    }

    #[test]
    fn push_back_elem12_full_vector_calls_insert_aux_with_the_spilled_element() {
        let _guard = push_back_elem12_guard();
        unsafe { install_recording_insert_aux() };
        let mut storage = GuardedStorage {
            before: GUARD,
            elements: [0x1111_2222; 9],
            after: GUARD,
        };
        let begin = core::ptr::addr_of_mut!(storage.elements).cast::<u8>();
        // Full: end == end_of_storage.
        let end = unsafe { begin.add(36) };
        let mut vector = VectorStorage {
            begin,
            end,
            end_of_storage: end,
        };

        unsafe {
            vector_push_back_elem12(&mut vector, 0xcafe_0001, 0xcafe_0002, 0xcafe_0003);
        }

        let calls = insert_aux_calls();
        assert_eq!(calls.len(), 1, "exactly one grow-and-insert");
        assert_eq!(
            calls[0],
            InsertAux {
                vector: core::ptr::addr_of_mut!(vector) as usize,
                position: end as usize,
                element: [0xcafe_0001, 0xcafe_0002, 0xcafe_0003],
            },
            "insert_aux(vector, end, &element) with the full third word"
        );
        assert_eq!(vector.end, end, "push_back itself never advances on the slow path");
        assert_eq!(storage.before, GUARD, "prefix guard");
        assert_eq!(storage.after, GUARD, "suffix guard");
        assert!(
            storage.elements.iter().all(|&word| word == 0x1111_2222),
            "no store into full storage"
        );
    }

    /// The `subs r0, r1, #12` NULL guard: a NULL `end` distinct from
    /// `end_of_storage` still advances (to 12) but stores nothing. The
    /// advance being unconditional is the behaviour this pins.
    #[test]
    fn push_back_elem12_null_end_advances_without_storing() {
        let _guard = push_back_elem12_guard();
        unsafe { install_recording_insert_aux() };
        let mut vector = VectorStorage {
            begin: core::ptr::null_mut(),
            end: core::ptr::null_mut(),
            // Distinct from end, so the fast path is taken; never
            // dereferenced.
            end_of_storage: 0x1000usize as *mut u8,
        };

        unsafe {
            vector_push_back_elem12(&mut vector, 1, 2, 3);
        }

        assert_eq!(vector.end, 12usize as *mut u8, "NULL end still advances by 12");
        assert!(insert_aux_calls().is_empty(), "end != capacity: no grow");
    }

    // ---- vector_push_back_elem4 ---------------------------------------

    static PUSH_BACK_ELEM4_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct PushBackElem4Guard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for PushBackElem4Guard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(VECTOR_PUSH_BACK_ELEM4_OPS)
                    .write_volatile(DEFAULT_VECTOR_PUSH_BACK_ELEM4_OPS);
            }
        }
    }

    fn push_back_elem4_guard() -> PushBackElem4Guard {
        let lock = PUSH_BACK_ELEM4_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        PushBackElem4Guard { _lock: lock }
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Elem4InsertAux {
        vector: usize,
        position: usize,
        element: u32,
    }

    static mut ELEM4_INSERT_AUX_CALLS: Vec<Elem4InsertAux> = Vec::new();

    unsafe extern "C" fn recording_insert_aux_elem4(
        vector: *mut VectorStorage,
        position: *mut u8,
        element: *const u32,
    ) {
        (*core::ptr::addr_of_mut!(ELEM4_INSERT_AUX_CALLS)).push(Elem4InsertAux {
            vector: vector as usize,
            position: position as usize,
            element: element.read(),
        });
    }

    unsafe fn install_recording_insert_aux_elem4() {
        (*core::ptr::addr_of_mut!(ELEM4_INSERT_AUX_CALLS)).clear();
        core::ptr::addr_of_mut!(VECTOR_PUSH_BACK_ELEM4_OPS)
            .write_volatile(VectorPushBackElem4Ops {
                insert_aux: recording_insert_aux_elem4,
            });
    }

    fn elem4_insert_aux_calls() -> Vec<Elem4InsertAux> {
        unsafe { (*core::ptr::addr_of!(ELEM4_INSERT_AUX_CALLS)).clone() }
    }

    #[test]
    fn push_back_elem4_stores_one_word_and_advances_end() {
        let _guard = push_back_elem4_guard();
        unsafe { install_recording_insert_aux_elem4() };
        let mut words = [0xaaaa_0001, 0, 0xcccc_0003];
        let begin = words.as_mut_ptr().cast::<u8>();
        let mut vector = VectorStorage {
            begin,
            end: unsafe { begin.add(4) },
            end_of_storage: unsafe { begin.add(12) },
        };
        let element = 0x1122_3344;

        unsafe { vector_push_back_elem4(&mut vector, &element) };

        assert_eq!(words, [0xaaaa_0001, element, 0xcccc_0003]);
        assert_eq!(vector.begin, begin);
        assert_eq!(vector.end, unsafe { begin.add(8) });
        assert_eq!(vector.end_of_storage, unsafe { begin.add(12) });
        assert!(elem4_insert_aux_calls().is_empty(), "spare slot skips growth");
    }

    #[test]
    fn push_back_elem4_full_vector_tail_dispatches_without_writing() {
        let _guard = push_back_elem4_guard();
        unsafe { install_recording_insert_aux_elem4() };
        let mut words: [u32; 2] = [0xaaaa_0001, 0xbbbb_0002];
        let begin = words.as_mut_ptr().cast::<u8>();
        let end = unsafe { begin.add(8) };
        let mut vector = VectorStorage {
            begin,
            end,
            end_of_storage: end,
        };
        let element = 0xcafe_babe;

        unsafe { vector_push_back_elem4(&mut vector, &element) };

        assert_eq!(
            elem4_insert_aux_calls(),
            std::vec![Elem4InsertAux {
                vector: core::ptr::addr_of_mut!(vector) as usize,
                position: end as usize,
                element,
            }]
        );
        assert_eq!(vector.end, end, "only the helper may advance a full vector");
        assert_eq!(words, [0xaaaa_0001u32, 0xbbbb_0002], "no full-slot write");
    }

    #[test]
    fn push_back_elem4_null_end_advances_without_reading_element() {
        let _guard = push_back_elem4_guard();
        unsafe { install_recording_insert_aux_elem4() };
        let mut vector = VectorStorage {
            begin: core::ptr::null_mut(),
            end: core::ptr::null_mut(),
            end_of_storage: 0x1000usize as *mut u8,
        };

        unsafe { vector_push_back_elem4(&mut vector, core::ptr::null()) };

        assert_eq!(vector.end, 4usize as *mut u8);
        assert!(
            elem4_insert_aux_calls().is_empty(),
            "distinct end/capacity stays on the fast path"
        );
    }

    #[test]
    fn string_object_word_range_copy_assigns_each_string_and_copies_words() {
        let source = [
            StringObjectWord {
                string: StringObject {
                    vtable: core::ptr::null(),
                    payload: core::ptr::null_mut(),
                },
                trailing_word: 0x1234_5678,
            },
            StringObjectWord {
                string: StringObject {
                    vtable: core::ptr::null(),
                    payload: core::ptr::null_mut(),
                },
                trailing_word: 0x9abc_def0,
            },
        ];
        let mut output = [
            StringObjectWord {
                string: StringObject {
                    vtable: core::ptr::null(),
                    payload: 0x1111_1111usize as *mut u8,
                },
                trailing_word: 0,
            },
            StringObjectWord {
                string: StringObject {
                    vtable: core::ptr::null(),
                    payload: 0x2222_2222usize as *mut u8,
                },
                trailing_word: 0,
            },
        ];
        let _guard = record_string_object_assign_clears();
        let output_start = output.as_mut_ptr();

        let returned = unsafe {
            string_object_word_range_copy(source.as_ptr(), source.as_ptr().add(2), output_start)
        };

        let clears = unsafe {
            (*core::ptr::addr_of!(STRING_OBJECT_ASSIGN_CLEAR_CALLS)).clone()
        };
        assert_eq!(
            clears,
            std::vec![
                core::ptr::addr_of_mut!(output[0].string) as usize,
                core::ptr::addr_of_mut!(output[1].string) as usize,
            ],
            "each source NULL payload reaches the existing assignment clear path"
        );
        assert_eq!(returned, unsafe { output_start.add(2) });
        assert_eq!(output[0].trailing_word, source[0].trailing_word);
        assert_eq!(output[1].trailing_word, source[1].trailing_word);
        assert_eq!(output[0].string.payload, 0x1111_1111usize as *mut u8);
        assert_eq!(output[1].string.payload, 0x2222_2222usize as *mut u8);
    }

    #[test]
    fn string_object_word_range_copy_empty_range_touches_nothing() {
        let output = 0x1234usize as *mut StringObjectWord;

        let returned = unsafe {
            string_object_word_range_copy(core::ptr::null(), core::ptr::null(), output)
        };

        assert_eq!(returned, output);
    }
    #[test]
    fn advance_string_object_word_cursor_uses_12_byte_wrapping_stride() {
        let cases = [
            (0x0800_1000u32, 0i32, 0x0800_1000u32),
            (0x0800_1000, 3, 0x0800_1024),
            (0x0000_0004, -1, 0xffff_fff8),
            (0xdead_beef, i32::MIN, 0xdead_beef),
        ];

        for (initial, element_count, expected) in cases {
            let mut cursor = initial;
            unsafe { advance_string_object_word_cursor(&mut cursor, element_count) };
            assert_eq!(cursor, expected, "count {element_count}");
        }
    }


    #[repr(C)]
    struct GuardedRecordRange {
        before: u32,
        records: [u32; 18],
        after: u32,
    }

    #[test]
    fn vector_copy_range_elem24_copies_records_and_returns_end() {
        let source = [
            0x0102_0304, 0x1112_1314, 0x2122_2324,
            0x3132_3334, 0x4142_4344, 0x5152_5354,
            0x6162_6364, 0x7172_7374, 0x8182_8384,
            0x9192_9394, 0xa1a2_a3a4, 0xb1b2_b3b4,
            0xc1c2_c3c4, 0xd1d2_d3d4, 0xe1e2_e3e4,
            0xf1f2_f3f4, 0x0506_0708, 0x1516_1718,
        ];
        let mut destination = GuardedRecordRange {
            before: 0xaaaa_aaaa,
            records: [0xdddd_dddd; 18],
            after: 0xbbbb_bbbb,
        };
        let first = source.as_ptr().cast::<u8>();
        let output = destination.records.as_mut_ptr().cast::<u8>();

        let returned = unsafe {
            vector_copy_range_elem24(first, first.add(72), output)
        };

        assert_eq!(destination.records, source, "three complete 24-byte records");
        assert_eq!(returned, unsafe { output.add(72) }, "output cursor advances per record");
        assert_eq!(destination.before, 0xaaaa_aaaa, "prefix guard");
        assert_eq!(destination.after, 0xbbbb_bbbb, "suffix guard");
    }

    #[test]
    fn vector_copy_range_elem24_empty_range_leaves_output_unchanged() {
        let source = [0x0102_0304u32; 6];
        let mut destination = [0xaaaa_aaaau32; 6];
        let first = source.as_ptr().cast::<u8>();
        let output = destination.as_mut_ptr().cast::<u8>();

        let returned = unsafe { vector_copy_range_elem24(first, first, output) };

        assert_eq!(returned, output);
        assert_eq!(destination, [0xaaaa_aaaa; 6]);
    }

    #[test]
    fn vector_copy_range_elem24_null_output_skips_one_record_without_reading_source() {
        let returned = unsafe {
            vector_copy_range_elem24(
                core::ptr::null(),
                24usize as *const u8,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(returned, 24usize as *mut u8, "skipped record still advances output");
    }

    #[test]
    fn vector_copy_range_u32_copies_words_and_returns_advanced_output() {
        let source = [0x0102_0304u32, 0x1112_1314, 0x2122_2324];
        let mut destination = [0xaaaa_aaaa, 0xbbbb_bbbb, 0xcccc_cccc, 0xdddd_dddd];
        let output = destination.as_mut_ptr();

        let returned = unsafe { vector_copy_range_u32(source.as_ptr(), source.as_ptr().add(3), output) };

        assert_eq!(&destination[..3], &source);
        assert_eq!(destination[3], 0xdddd_dddd, "range end is exclusive");
        assert_eq!(returned, unsafe { output.add(3) });
    }

    #[test]
    fn vector_copy_range_u32_empty_range_leaves_output_unchanged() {
        let source = [0x0102_0304u32];
        let mut destination = [0xaaaa_aaaa];
        let output = destination.as_mut_ptr();

        let returned = unsafe { vector_copy_range_u32(source.as_ptr(), source.as_ptr(), output) };

        assert_eq!(returned, output);
        assert_eq!(destination, [0xaaaa_aaaa]);
    }

    #[test]
    fn vector_copy_range_u32_null_output_skips_one_word_without_reading_source() {
        let returned = unsafe {
            vector_copy_range_u32(core::ptr::null(), 4usize as *const u32, core::ptr::null_mut())
        };

        assert_eq!(returned, 4usize as *mut u32, "skipped word still advances output");
    }

    #[test]
    fn vector_copy_range_pair_u32_copies_pairs_and_returns_advanced_output() {
        let source = [[0x0102_0304u32, 0x1112_1314], [0x2122_2324, 0x3132_3334]];
        let mut destination = [
            [0xaaaa_aaaa, 0xbbbb_bbbb],
            [0xcccc_cccc, 0xdddd_dddd],
            [0xeeee_eeee, 0xffff_ffff],
        ];
        let output = destination.as_mut_ptr();

        let returned = unsafe {
            vector_copy_range_pair_u32(source.as_ptr(), source.as_ptr().add(2), output)
        };

        assert_eq!(&destination[..2], &source);
        assert_eq!(destination[2], [0xeeee_eeee, 0xffff_ffff], "range end is exclusive");
        assert_eq!(returned, unsafe { output.add(2) });
    }

    #[test]
    fn vector_copy_range_pair_u32_empty_and_null_output_preserve_arm_cursor_rules() {
        let source = [[0x0102_0304u32, 0x1112_1314]];
        let mut destination = [[0xaaaa_aaaa, 0xbbbb_bbbb]];
        let output = destination.as_mut_ptr();

        let empty = unsafe { vector_copy_range_pair_u32(source.as_ptr(), source.as_ptr(), output) };
        let null_output = unsafe {
            vector_copy_range_pair_u32(
                core::ptr::null(),
                8usize as *const [u32; 2],
                core::ptr::null_mut(),
            )
        };

        assert_eq!(empty, output);
        assert_eq!(destination, [[0xaaaa_aaaa, 0xbbbb_bbbb]]);
        assert_eq!(null_output, 8usize as *mut [u32; 2]);
    }

    #[test]
    fn vector_copy_range_u32_alias_8f5c_copies_words_and_returns_advanced_output() {
        let source = [0x0f1e_2d3cu32, 0x4b5a_6978, 0x8796_a5b4];
        let mut destination = [0xaaaa_aaaa, 0xbbbb_bbbb, 0xcccc_cccc, 0xdddd_dddd];
        let output = destination.as_mut_ptr();

        let returned = unsafe {
            vector_copy_range_u32_alias_8f5c(source.as_ptr(), source.as_ptr().add(3), output)
        };

        assert_eq!(&destination[..3], &source);
        assert_eq!(destination[3], 0xdddd_dddd, "range end is exclusive");
        assert_eq!(returned, unsafe { output.add(3) });
    }

    #[test]
    fn vector_copy_range_u32_alias_8f5c_empty_range_leaves_output_unchanged() {
        let source = [0x0f1e_2d3cu32];
        let mut destination = [0xaaaa_aaaa];
        let output = destination.as_mut_ptr();

        let returned = unsafe {
            vector_copy_range_u32_alias_8f5c(source.as_ptr(), source.as_ptr(), output)
        };

        assert_eq!(returned, output);
        assert_eq!(destination, [0xaaaa_aaaa]);
    }

    #[test]
    fn vector_copy_range_u32_alias_8f5c_null_output_skips_one_word_without_reading_source() {
        let returned = unsafe {
            vector_copy_range_u32_alias_8f5c(
                core::ptr::null(),
                4usize as *const u32,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(returned, 4usize as *mut u32, "skipped word still advances output");
    }

    static COPY_CONSTRUCT_ELEM12_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct CopyConstructElem12Guard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for CopyConstructElem12Guard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(VECTOR_COPY_CONSTRUCT_ELEM12_OPS)
                    .write_volatile(DEFAULT_VECTOR_COPY_CONSTRUCT_ELEM12_OPS);
            }
        }
    }

    fn copy_construct_elem12_guard() -> CopyConstructElem12Guard {
        let lock = COPY_CONSTRUCT_ELEM12_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        CopyConstructElem12Guard { _lock: lock }
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Elem12CopyConstruct {
        vector: usize,
        output: usize,
        source: usize,
    }

    static mut ELEM12_COPY_CONSTRUCT_CALLS: Vec<Elem12CopyConstruct> = Vec::new();

    unsafe extern "C" fn recording_copy_construct_elem12(
        vector: *mut VectorStorage,
        output: *mut u8,
        source: *const u8,
    ) {
        (*core::ptr::addr_of_mut!(ELEM12_COPY_CONSTRUCT_CALLS)).push(Elem12CopyConstruct {
            vector: vector as usize,
            output: output as usize,
            source: source as usize,
        });
    }

    unsafe fn install_recording_copy_construct_elem12() {
        (*core::ptr::addr_of_mut!(ELEM12_COPY_CONSTRUCT_CALLS)).clear();
        core::ptr::addr_of_mut!(VECTOR_COPY_CONSTRUCT_ELEM12_OPS)
            .write_volatile(VectorCopyConstructElem12Ops {
                copy_construct: recording_copy_construct_elem12,
            });
    }

    fn elem12_copy_construct_calls() -> Vec<Elem12CopyConstruct> {
        unsafe { (*core::ptr::addr_of!(ELEM12_COPY_CONSTRUCT_CALLS)).clone() }
    }

    #[test]
    fn copy_construct_range_elem12_visits_each_element_and_returns_advanced_output() {
        let _guard = copy_construct_elem12_guard();
        unsafe { install_recording_copy_construct_elem12() };
        let source = [0x5au8; 3 * 0x0c];
        let mut destination = [0xa5u8; 3 * 0x0c + 0x0c];
        let mut vector = VectorStorage {
            begin: 0x1111usize as *mut u8,
            end: 0x2222usize as *mut u8,
            end_of_storage: 0x3333usize as *mut u8,
        };
        let first = source.as_ptr();
        let output = destination.as_mut_ptr();

        let returned = unsafe {
            vector_copy_construct_range_elem12(
                first,
                first.add(3 * 0x0c),
                output,
                core::ptr::addr_of_mut!(vector),
            )
        };

        assert_eq!(
            elem12_copy_construct_calls(),
            std::vec![
                Elem12CopyConstruct {
                    vector: core::ptr::addr_of_mut!(vector) as usize,
                    output: output as usize,
                    source: first as usize,
                },
                Elem12CopyConstruct {
                    vector: core::ptr::addr_of_mut!(vector) as usize,
                    output: unsafe { output.add(0x0c) } as usize,
                    source: unsafe { first.add(0x0c) } as usize,
                },
                Elem12CopyConstruct {
                    vector: core::ptr::addr_of_mut!(vector) as usize,
                    output: unsafe { output.add(2 * 0x0c) } as usize,
                    source: unsafe { first.add(2 * 0x0c) } as usize,
                },
            ],
            "one helper call per 0x0c-byte element, cursors striding together"
        );
        assert_eq!(returned, unsafe { output.add(3 * 0x0c) });
        assert!(
            destination.iter().all(|byte| *byte == 0xa5),
            "the loop itself never writes the destination (construction is the helper's)"
        );
    }

    #[test]
    fn copy_construct_range_elem12_empty_range_returns_output_without_calls() {
        let _guard = copy_construct_elem12_guard();
        unsafe { install_recording_copy_construct_elem12() };
        let source = [0x5au8; 0x0c];
        let mut destination = [0xa5u8; 0x0c];
        let output = destination.as_mut_ptr();

        let returned = unsafe {
            vector_copy_construct_range_elem12(
                source.as_ptr(),
                source.as_ptr(),
                output,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(returned, output);
        assert!(elem12_copy_construct_calls().is_empty());
    }

    #[test]
    fn copy_construct_range_elem12_null_output_still_dispatches_and_advances() {
        let _guard = copy_construct_elem12_guard();
        unsafe { install_recording_copy_construct_elem12() };
        // The original guards nothing: a NULL output cursor is handed to
        // the helper (whose own `movs r0, r1; bxeq lr` skips construction),
        // and the cursor still advances to 0x0c. `first`/`last` are dead
        // cursors here — the recording model never dereferences them.
        let returned = unsafe {
            vector_copy_construct_range_elem12(
                core::ptr::null(),
                0x0cusize as *const u8,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };

        assert_eq!(returned, 0x0cusize as *mut u8, "skipped element still advances output");
        assert_eq!(
            elem12_copy_construct_calls(),
            std::vec![Elem12CopyConstruct { vector: 0, output: 0, source: 0 }],
            "the NULL-output guard lives in the helper, not the loop"
        );
    }

    static COPY_CONSTRUCT_ELEM32_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct CopyConstructElem32Guard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for CopyConstructElem32Guard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(VECTOR_COPY_CONSTRUCT_ELEM32_OPS)
                    .write_volatile(DEFAULT_VECTOR_COPY_CONSTRUCT_ELEM32_OPS);
            }
        }
    }

    fn copy_construct_elem32_guard() -> CopyConstructElem32Guard {
        let lock = COPY_CONSTRUCT_ELEM32_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        CopyConstructElem32Guard { _lock: lock }
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Elem32CopyConstruct {
        vector: usize,
        output: usize,
        source: usize,
    }

    static mut ELEM32_COPY_CONSTRUCT_CALLS: Vec<Elem32CopyConstruct> = Vec::new();

    unsafe extern "C" fn recording_copy_construct_elem32(
        vector: *mut VectorStorage,
        output: *mut u8,
        source: *const u8,
    ) {
        (*core::ptr::addr_of_mut!(ELEM32_COPY_CONSTRUCT_CALLS)).push(Elem32CopyConstruct {
            vector: vector as usize,
            output: output as usize,
            source: source as usize,
        });
    }

    unsafe fn install_recording_copy_construct_elem32() {
        (*core::ptr::addr_of_mut!(ELEM32_COPY_CONSTRUCT_CALLS)).clear();
        core::ptr::addr_of_mut!(VECTOR_COPY_CONSTRUCT_ELEM32_OPS)
            .write_volatile(VectorCopyConstructElem32Ops {
                copy_construct: recording_copy_construct_elem32,
            });
    }

    fn elem32_copy_construct_calls() -> Vec<Elem32CopyConstruct> {
        unsafe { (*core::ptr::addr_of!(ELEM32_COPY_CONSTRUCT_CALLS)).clone() }
    }

    #[test]
    fn copy_construct_range_elem32_visits_each_element_and_returns_advanced_output() {
        let _guard = copy_construct_elem32_guard();
        unsafe { install_recording_copy_construct_elem32() };
        let source = [0x5au8; 3 * 0x20];
        let mut destination = [0xa5u8; 3 * 0x20 + 0x20];
        let mut vector = VectorStorage {
            begin: 0x1111usize as *mut u8,
            end: 0x2222usize as *mut u8,
            end_of_storage: 0x3333usize as *mut u8,
        };
        let first = source.as_ptr();
        let output = destination.as_mut_ptr();

        let returned = unsafe {
            vector_copy_construct_range_elem32(
                first,
                first.add(3 * 0x20),
                output,
                core::ptr::addr_of_mut!(vector),
            )
        };

        assert_eq!(
            elem32_copy_construct_calls(),
            std::vec![
                Elem32CopyConstruct {
                    vector: core::ptr::addr_of_mut!(vector) as usize,
                    output: output as usize,
                    source: first as usize,
                },
                Elem32CopyConstruct {
                    vector: core::ptr::addr_of_mut!(vector) as usize,
                    output: unsafe { output.add(0x20) } as usize,
                    source: unsafe { first.add(0x20) } as usize,
                },
                Elem32CopyConstruct {
                    vector: core::ptr::addr_of_mut!(vector) as usize,
                    output: unsafe { output.add(2 * 0x20) } as usize,
                    source: unsafe { first.add(2 * 0x20) } as usize,
                },
            ],
            "one helper call per 0x20-byte element, cursors striding together"
        );
        assert_eq!(returned, unsafe { output.add(3 * 0x20) });
        assert!(
            destination.iter().all(|byte| *byte == 0xa5),
            "the loop itself never writes the destination (construction is the helper's)"
        );
    }

    #[test]
    fn copy_construct_range_elem32_empty_range_returns_output_without_calls() {
        let _guard = copy_construct_elem32_guard();
        unsafe { install_recording_copy_construct_elem32() };
        let source = [0x5au8; 0x20];
        let mut destination = [0xa5u8; 0x20];
        let output = destination.as_mut_ptr();

        let returned = unsafe {
            vector_copy_construct_range_elem32(
                source.as_ptr(),
                source.as_ptr(),
                output,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(returned, output);
        assert!(elem32_copy_construct_calls().is_empty());
    }

    #[test]
    fn copy_construct_range_elem32_null_output_still_dispatches_and_advances() {
        let _guard = copy_construct_elem32_guard();
        unsafe { install_recording_copy_construct_elem32() };
        // The original guards nothing: a NULL output cursor is handed to
        // the helper (whose own `movs r0, r1; beq` skips construction),
        // and the cursor still advances to 0x20. `first`/`last` are dead
        // cursors here — the recording model never dereferences them.
        let returned = unsafe {
            vector_copy_construct_range_elem32(
                core::ptr::null(),
                0x20usize as *const u8,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };

        assert_eq!(returned, 0x20usize as *mut u8, "skipped element still advances output");
        assert_eq!(
            elem32_copy_construct_calls(),
            std::vec![Elem32CopyConstruct { vector: 0, output: 0, source: 0 }],
            "the NULL-output guard lives in the helper, not the loop"
        );
    }

    static COPY_CONSTRUCT_ELEM16_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct CopyConstructElem16Guard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for CopyConstructElem16Guard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(VECTOR_COPY_CONSTRUCT_ELEM16_OPS)
                    .write_volatile(DEFAULT_VECTOR_COPY_CONSTRUCT_ELEM16_OPS);
            }
        }
    }

    fn copy_construct_elem16_guard() -> CopyConstructElem16Guard {
        let lock = COPY_CONSTRUCT_ELEM16_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        CopyConstructElem16Guard { _lock: lock }
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Elem16CopyConstruct {
        vector: usize,
        output: usize,
        source: usize,
    }

    static mut ELEM16_COPY_CONSTRUCT_CALLS: Vec<Elem16CopyConstruct> = Vec::new();

    unsafe extern "C" fn recording_copy_construct_elem16(
        vector: *mut VectorStorage,
        output: *mut u8,
        source: *const u8,
    ) {
        (*core::ptr::addr_of_mut!(ELEM16_COPY_CONSTRUCT_CALLS)).push(Elem16CopyConstruct {
            vector: vector as usize,
            output: output as usize,
            source: source as usize,
        });
    }

    unsafe fn install_recording_copy_construct_elem16() {
        (*core::ptr::addr_of_mut!(ELEM16_COPY_CONSTRUCT_CALLS)).clear();
        core::ptr::addr_of_mut!(VECTOR_COPY_CONSTRUCT_ELEM16_OPS)
            .write_volatile(VectorCopyConstructElem16Ops {
                copy_construct: recording_copy_construct_elem16,
            });
    }

    fn elem16_copy_construct_calls() -> Vec<Elem16CopyConstruct> {
        unsafe { (*core::ptr::addr_of!(ELEM16_COPY_CONSTRUCT_CALLS)).clone() }
    }

    #[test]
    fn copy_construct_range_elem16_visits_each_element_and_returns_advanced_output() {
        let _guard = copy_construct_elem16_guard();
        unsafe { install_recording_copy_construct_elem16() };
        let source = [0x5au8; 3 * 0x10];
        let mut destination = [0xa5u8; 3 * 0x10 + 0x10];
        let mut vector = VectorStorage {
            begin: 0x1111usize as *mut u8,
            end: 0x2222usize as *mut u8,
            end_of_storage: 0x3333usize as *mut u8,
        };
        let first = source.as_ptr();
        let output = destination.as_mut_ptr();

        let returned = unsafe {
            vector_copy_construct_range_elem16(
                first,
                first.add(3 * 0x10),
                output,
                core::ptr::addr_of_mut!(vector),
            )
        };

        assert_eq!(
            elem16_copy_construct_calls(),
            std::vec![
                Elem16CopyConstruct {
                    vector: core::ptr::addr_of_mut!(vector) as usize,
                    output: output as usize,
                    source: first as usize,
                },
                Elem16CopyConstruct {
                    vector: core::ptr::addr_of_mut!(vector) as usize,
                    output: unsafe { output.add(0x10) } as usize,
                    source: unsafe { first.add(0x10) } as usize,
                },
                Elem16CopyConstruct {
                    vector: core::ptr::addr_of_mut!(vector) as usize,
                    output: unsafe { output.add(2 * 0x10) } as usize,
                    source: unsafe { first.add(2 * 0x10) } as usize,
                },
            ],
            "one helper call per 0x10-byte element, cursors striding together"
        );
        assert_eq!(returned, unsafe { output.add(3 * 0x10) });
        assert!(
            destination.iter().all(|byte| *byte == 0xa5),
            "the loop itself never writes the destination (construction is the helper's)"
        );
    }

    #[test]
    fn copy_construct_range_elem16_empty_range_returns_output_without_calls() {
        let _guard = copy_construct_elem16_guard();
        unsafe { install_recording_copy_construct_elem16() };
        let source = [0x5au8; 0x10];
        let mut destination = [0xa5u8; 0x10];
        let output = destination.as_mut_ptr();

        let returned = unsafe {
            vector_copy_construct_range_elem16(
                source.as_ptr(),
                source.as_ptr(),
                output,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(returned, output);
        assert!(elem16_copy_construct_calls().is_empty());
    }

    #[test]
    fn copy_construct_range_elem16_null_output_still_dispatches_and_advances() {
        let _guard = copy_construct_elem16_guard();
        unsafe { install_recording_copy_construct_elem16() };
        // The original guards nothing: a NULL output cursor is handed to
        // the helper (whose own `movs r0, r1; popeq` skips construction),
        // and the cursor still advances to 0x10. `first`/`last` are dead
        // cursors here — the recording model never dereferences them.
        let returned = unsafe {
            vector_copy_construct_range_elem16(
                core::ptr::null(),
                0x10usize as *const u8,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };

        assert_eq!(returned, 0x10usize as *mut u8, "skipped element still advances output");
        assert_eq!(
            elem16_copy_construct_calls(),
            std::vec![Elem16CopyConstruct { vector: 0, output: 0, source: 0 }],
            "the NULL-output guard lives in the helper, not the loop"
        );
    }
    #[test]
    fn copy_construct_range_string_pair_constructs_both_members_and_advances() {
        // Aligned, zero-payload words make both StringObject copy constructors
        // take their no-allocation path. The +8 cursor is the retailOS word
        // stride, not the host StringObject size.
        let source = [0usize; 4];
        let mut destination = [usize::MAX; 4];
        let output = destination.as_mut_ptr().cast::<u8>();

        let returned = unsafe {
            vector_copy_construct_range_string_pair(
                source.as_ptr().cast::<u8>(),
                unsafe { source.as_ptr().cast::<u8>().add(0x10) },
                output,
            )
        };

        assert_eq!(returned, unsafe { output.add(0x10) });
        assert_eq!(destination[0], &STRING_OBJECT_VTABLE as *const _ as usize);
        assert_eq!(destination[1], &STRING_OBJECT_VTABLE as *const _ as usize);
        assert_eq!(destination[2], 0, "the second constructor NULLs its payload");
    }

    #[test]
    fn copy_construct_range_string_pair_empty_and_null_output_preserve_raw_guards() {
        let source = [0usize; 2];
        let mut destination = [0usize; 2];
        let output = destination.as_mut_ptr().cast::<u8>();

        assert_eq!(
            unsafe {
                vector_copy_construct_range_string_pair(
                    source.as_ptr().cast::<u8>(),
                    source.as_ptr().cast::<u8>(),
                    output,
                )
            },
            output,
            "empty ranges do not dereference either cursor"
        );
        assert_eq!(
            unsafe {
                vector_copy_construct_range_string_pair(
                    core::ptr::null(),
                    0x10usize as *const u8,
                    core::ptr::null_mut(),
                )
            },
            0x10usize as *mut u8,
            "NULL output skips both constructors but advances by one pair"
        );
    }


    static COPY_CONSTRUCT_ELEM16_ALT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct CopyConstructElem16AltGuard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for CopyConstructElem16AltGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(VECTOR_COPY_CONSTRUCT_ELEM16_ALT_OPS)
                    .write_volatile(DEFAULT_VECTOR_COPY_CONSTRUCT_ELEM16_ALT_OPS);
            }
        }
    }

    fn copy_construct_elem16_alt_guard() -> CopyConstructElem16AltGuard {
        let lock = COPY_CONSTRUCT_ELEM16_ALT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        CopyConstructElem16AltGuard { _lock: lock }
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Elem16AltCopyConstruct {
        vector: usize,
        output: usize,
        source: usize,
    }

    static mut ELEM16_ALT_COPY_CONSTRUCT_CALLS: Vec<Elem16AltCopyConstruct> = Vec::new();

    unsafe extern "C" fn recording_copy_construct_elem16_alt(
        vector: *mut VectorStorage,
        output: *mut u8,
        source: *const u8,
    ) {
        (*core::ptr::addr_of_mut!(ELEM16_ALT_COPY_CONSTRUCT_CALLS)).push(Elem16AltCopyConstruct {
            vector: vector as usize,
            output: output as usize,
            source: source as usize,
        });
    }

    unsafe fn install_recording_copy_construct_elem16_alt() {
        (*core::ptr::addr_of_mut!(ELEM16_ALT_COPY_CONSTRUCT_CALLS)).clear();
        core::ptr::addr_of_mut!(VECTOR_COPY_CONSTRUCT_ELEM16_ALT_OPS)
            .write_volatile(VectorCopyConstructElem16AltOps {
                copy_construct: recording_copy_construct_elem16_alt,
            });
    }

    fn elem16_alt_copy_construct_calls() -> Vec<Elem16AltCopyConstruct> {
        unsafe { (*core::ptr::addr_of!(ELEM16_ALT_COPY_CONSTRUCT_CALLS)).clone() }
    }

    #[test]
    fn copy_construct_range_elem16_alt_visits_each_element_and_returns_advanced_output() {
        let _guard = copy_construct_elem16_alt_guard();
        unsafe { install_recording_copy_construct_elem16_alt() };
        let source = [0x5au8; 3 * 0x10];
        let mut destination = [0xa5u8; 3 * 0x10 + 0x10];
        let mut vector = VectorStorage {
            begin: 0x1111usize as *mut u8,
            end: 0x2222usize as *mut u8,
            end_of_storage: 0x3333usize as *mut u8,
        };
        let first = source.as_ptr();
        let output = destination.as_mut_ptr();

        let returned = unsafe {
            vector_copy_construct_range_elem16_alt(
                first,
                first.add(3 * 0x10),
                output,
                core::ptr::addr_of_mut!(vector),
            )
        };

        assert_eq!(
            elem16_alt_copy_construct_calls(),
            std::vec![
                Elem16AltCopyConstruct {
                    vector: core::ptr::addr_of_mut!(vector) as usize,
                    output: output as usize,
                    source: first as usize,
                },
                Elem16AltCopyConstruct {
                    vector: core::ptr::addr_of_mut!(vector) as usize,
                    output: unsafe { output.add(0x10) } as usize,
                    source: unsafe { first.add(0x10) } as usize,
                },
                Elem16AltCopyConstruct {
                    vector: core::ptr::addr_of_mut!(vector) as usize,
                    output: unsafe { output.add(2 * 0x10) } as usize,
                    source: unsafe { first.add(2 * 0x10) } as usize,
                },
            ],
            "one helper call per 0x10-byte element, cursors striding together"
        );
        assert_eq!(returned, unsafe { output.add(3 * 0x10) });
        assert!(
            destination.iter().all(|byte| *byte == 0xa5),
            "the loop itself never writes the destination (construction is the helper's)"
        );
    }

    #[test]
    fn copy_construct_range_elem16_alt_empty_range_returns_output_without_calls() {
        let _guard = copy_construct_elem16_alt_guard();
        unsafe { install_recording_copy_construct_elem16_alt() };
        let source = [0x5au8; 0x10];
        let mut destination = [0xa5u8; 0x10];
        let output = destination.as_mut_ptr();

        let returned = unsafe {
            vector_copy_construct_range_elem16_alt(
                source.as_ptr(),
                source.as_ptr(),
                output,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(returned, output);
        assert!(elem16_alt_copy_construct_calls().is_empty());
    }

    #[test]
    fn copy_construct_range_elem16_alt_null_output_still_dispatches_and_advances() {
        let _guard = copy_construct_elem16_alt_guard();
        unsafe { install_recording_copy_construct_elem16_alt() };
        // The original guards nothing: a NULL output cursor is handed to
        // the helper (whose own `movs r0, r1; popeq` skips construction),
        // and the cursor still advances to 0x10. `first`/`last` are dead
        // cursors here — the recording model never dereferences them.
        let returned = unsafe {
            vector_copy_construct_range_elem16_alt(
                core::ptr::null(),
                0x10usize as *const u8,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };

        assert_eq!(returned, 0x10usize as *mut u8, "skipped element still advances output");
        assert_eq!(
            elem16_alt_copy_construct_calls(),
            std::vec![Elem16AltCopyConstruct { vector: 0, output: 0, source: 0 }],
            "the NULL-output guard lives in the helper, not the loop"
        );
    }

    static COPY_CONSTRUCT_ELEM28_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct CopyConstructElem28Guard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for CopyConstructElem28Guard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(VECTOR_COPY_CONSTRUCT_ELEM28_OPS)
                    .write_volatile(DEFAULT_VECTOR_COPY_CONSTRUCT_ELEM28_OPS);
            }
        }
    }

    fn copy_construct_elem28_guard() -> CopyConstructElem28Guard {
        let lock = COPY_CONSTRUCT_ELEM28_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        CopyConstructElem28Guard { _lock: lock }
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Elem28CopyConstruct {
        vector: usize,
        output: usize,
        source: usize,
    }

    static mut ELEM28_COPY_CONSTRUCT_CALLS: Vec<Elem28CopyConstruct> = Vec::new();

    unsafe extern "C" fn recording_copy_construct_elem28(
        vector: *mut VectorStorage,
        output: *mut u8,
        source: *const u8,
    ) {
        (*core::ptr::addr_of_mut!(ELEM28_COPY_CONSTRUCT_CALLS)).push(Elem28CopyConstruct {
            vector: vector as usize,
            output: output as usize,
            source: source as usize,
        });
    }

    unsafe fn install_recording_copy_construct_elem28() {
        (*core::ptr::addr_of_mut!(ELEM28_COPY_CONSTRUCT_CALLS)).clear();
        core::ptr::addr_of_mut!(VECTOR_COPY_CONSTRUCT_ELEM28_OPS)
            .write_volatile(VectorCopyConstructElem28Ops {
                copy_construct: recording_copy_construct_elem28,
            });
    }

    fn elem28_copy_construct_calls() -> Vec<Elem28CopyConstruct> {
        unsafe { (*core::ptr::addr_of!(ELEM28_COPY_CONSTRUCT_CALLS)).clone() }
    }

    #[test]
    fn copy_construct_range_elem28_visits_each_element_and_returns_advanced_output() {
        let _guard = copy_construct_elem28_guard();
        unsafe { install_recording_copy_construct_elem28() };
        let source = [0x5au8; 3 * 0x1c];
        let mut destination = [0xa5u8; 3 * 0x1c + 0x1c];
        let mut vector = VectorStorage {
            begin: 0x1111usize as *mut u8,
            end: 0x2222usize as *mut u8,
            end_of_storage: 0x3333usize as *mut u8,
        };
        let first = source.as_ptr();
        let output = destination.as_mut_ptr();

        let returned = unsafe {
            vector_copy_construct_range_elem28(
                first,
                first.add(3 * 0x1c),
                output,
                core::ptr::addr_of_mut!(vector),
            )
        };

        assert_eq!(
            elem28_copy_construct_calls(),
            std::vec![
                Elem28CopyConstruct {
                    vector: core::ptr::addr_of_mut!(vector) as usize,
                    output: output as usize,
                    source: first as usize,
                },
                Elem28CopyConstruct {
                    vector: core::ptr::addr_of_mut!(vector) as usize,
                    output: unsafe { output.add(0x1c) } as usize,
                    source: unsafe { first.add(0x1c) } as usize,
                },
                Elem28CopyConstruct {
                    vector: core::ptr::addr_of_mut!(vector) as usize,
                    output: unsafe { output.add(2 * 0x1c) } as usize,
                    source: unsafe { first.add(2 * 0x1c) } as usize,
                },
            ],
            "one helper call per 0x1c-byte element, cursors striding together"
        );
        assert_eq!(returned, unsafe { output.add(3 * 0x1c) });
        assert!(
            destination.iter().all(|byte| *byte == 0xa5),
            "the loop itself never writes the destination (construction is the helper's)"
        );
    }

    #[test]
    fn copy_construct_range_elem28_empty_range_returns_output_without_calls() {
        let _guard = copy_construct_elem28_guard();
        unsafe { install_recording_copy_construct_elem28() };
        let source = [0x5au8; 0x1c];
        let mut destination = [0xa5u8; 0x1c];
        let output = destination.as_mut_ptr();

        let returned = unsafe {
            vector_copy_construct_range_elem28(
                source.as_ptr(),
                source.as_ptr(),
                output,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(returned, output);
        assert!(elem28_copy_construct_calls().is_empty());
    }

    #[test]
    fn copy_construct_range_elem28_null_output_still_dispatches_and_advances() {
        let _guard = copy_construct_elem28_guard();
        unsafe { install_recording_copy_construct_elem28() };
        // The original guards nothing: a NULL output cursor is handed to
        // the helper (whose own `movs r0, r1; popeq` skips construction),
        // and the cursor still advances to 0x1c. `first`/`last` are dead
        // cursors here — the recording model never dereferences them.
        let returned = unsafe {
            vector_copy_construct_range_elem28(
                core::ptr::null(),
                0x1cusize as *const u8,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };

        assert_eq!(returned, 0x1cusize as *mut u8, "skipped element still advances output");
        assert_eq!(
            elem28_copy_construct_calls(),
            std::vec![Elem28CopyConstruct { vector: 0, output: 0, source: 0 }],
            "the NULL-output guard lives in the helper, not the loop"
        );
    }

    static COPY_CONSTRUCT_ELEM20_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct CopyConstructElem20Guard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for CopyConstructElem20Guard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(VECTOR_COPY_CONSTRUCT_ELEM20_OPS)
                    .write_volatile(DEFAULT_VECTOR_COPY_CONSTRUCT_ELEM20_OPS);
            }
        }
    }

    fn copy_construct_elem20_guard() -> CopyConstructElem20Guard {
        let lock = COPY_CONSTRUCT_ELEM20_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        CopyConstructElem20Guard { _lock: lock }
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Elem20CopyConstruct {
        vector: usize,
        output: usize,
        source: usize,
    }

    static mut ELEM20_COPY_CONSTRUCT_CALLS: Vec<Elem20CopyConstruct> = Vec::new();

    unsafe extern "C" fn recording_copy_construct_elem20(
        vector: *mut VectorStorage,
        output: *mut u8,
        source: *const u8,
    ) {
        (*core::ptr::addr_of_mut!(ELEM20_COPY_CONSTRUCT_CALLS)).push(Elem20CopyConstruct {
            vector: vector as usize,
            output: output as usize,
            source: source as usize,
        });
    }

    unsafe fn install_recording_copy_construct_elem20() {
        (*core::ptr::addr_of_mut!(ELEM20_COPY_CONSTRUCT_CALLS)).clear();
        core::ptr::addr_of_mut!(VECTOR_COPY_CONSTRUCT_ELEM20_OPS)
            .write_volatile(VectorCopyConstructElem20Ops {
                copy_construct: recording_copy_construct_elem20,
            });
    }

    fn elem20_copy_construct_calls() -> Vec<Elem20CopyConstruct> {
        unsafe { (*core::ptr::addr_of!(ELEM20_COPY_CONSTRUCT_CALLS)).clone() }
    }

    #[test]
    fn copy_construct_range_elem20_visits_each_element_and_returns_advanced_output() {
        let _guard = copy_construct_elem20_guard();
        unsafe { install_recording_copy_construct_elem20() };
        let source = [0x5au8; 3 * 0x14];
        let mut destination = [0xa5u8; 3 * 0x14 + 0x14];
        let mut vector = VectorStorage {
            begin: 0x1111usize as *mut u8,
            end: 0x2222usize as *mut u8,
            end_of_storage: 0x3333usize as *mut u8,
        };
        let first = source.as_ptr();
        let output = destination.as_mut_ptr();

        let returned = unsafe {
            vector_copy_construct_range_elem20(
                first,
                first.add(3 * 0x14),
                output,
                core::ptr::addr_of_mut!(vector),
            )
        };

        assert_eq!(
            elem20_copy_construct_calls(),
            std::vec![
                Elem20CopyConstruct {
                    vector: core::ptr::addr_of_mut!(vector) as usize,
                    output: output as usize,
                    source: first as usize,
                },
                Elem20CopyConstruct {
                    vector: core::ptr::addr_of_mut!(vector) as usize,
                    output: unsafe { output.add(0x14) } as usize,
                    source: unsafe { first.add(0x14) } as usize,
                },
                Elem20CopyConstruct {
                    vector: core::ptr::addr_of_mut!(vector) as usize,
                    output: unsafe { output.add(2 * 0x14) } as usize,
                    source: unsafe { first.add(2 * 0x14) } as usize,
                },
            ],
            "one helper call per 0x14-byte element, cursors striding together"
        );
        assert_eq!(returned, unsafe { output.add(3 * 0x14) });
        assert!(
            destination.iter().all(|byte| *byte == 0xa5),
            "the loop itself never writes the destination (construction is the helper's)"
        );
    }

    #[test]
    fn copy_construct_range_elem20_empty_range_returns_output_without_calls() {
        let _guard = copy_construct_elem20_guard();
        unsafe { install_recording_copy_construct_elem20() };
        let source = [0x5au8; 0x14];
        let mut destination = [0xa5u8; 0x14];
        let output = destination.as_mut_ptr();

        let returned = unsafe {
            vector_copy_construct_range_elem20(
                source.as_ptr(),
                source.as_ptr(),
                output,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(returned, output);
        assert!(elem20_copy_construct_calls().is_empty());
    }

    #[test]
    fn copy_construct_range_elem20_null_output_still_dispatches_and_advances() {
        let _guard = copy_construct_elem20_guard();
        unsafe { install_recording_copy_construct_elem20() };
        // The original guards nothing: a NULL output cursor is handed to
        // the helper (whose own `movs r0, r1; beq` skips construction),
        // and the cursor still advances to 0x14. `first`/`last` are dead
        // cursors here — the recording model never dereferences them.
        let returned = unsafe {
            vector_copy_construct_range_elem20(
                core::ptr::null(),
                0x14usize as *const u8,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };

        assert_eq!(returned, 0x14usize as *mut u8, "skipped element still advances output");
        assert_eq!(
            elem20_copy_construct_calls(),
            std::vec![Elem20CopyConstruct { vector: 0, output: 0, source: 0 }],
            "the NULL-output guard lives in the helper, not the loop"
        );
    }
    #[test]
    fn vector_copy_range_record8_copies_fields_preserves_padding_and_returns_end() {
        let source = [
            VectorRecord8 { word: 0x0102_0304, byte: 0x11, padding: 0x12, halfword: 0x1314 },
            VectorRecord8 { word: 0x2122_2324, byte: 0x31, padding: 0x32, halfword: 0x3334 },
            VectorRecord8 { word: 0x4142_4344, byte: 0x51, padding: 0x52, halfword: 0x5354 },
        ];
        let mut destination = [
            VectorRecord8 { word: 0xaaaa_aaaa, byte: 0xaa, padding: 0xa1, halfword: 0xaaaa },
            VectorRecord8 { word: 0xbbbb_bbbb, byte: 0xbb, padding: 0xb2, halfword: 0xbbbb },
            VectorRecord8 { word: 0xcccc_cccc, byte: 0xcc, padding: 0xc3, halfword: 0xcccc },
            VectorRecord8 { word: 0xdddd_dddd, byte: 0xdd, padding: 0xd4, halfword: 0xdddd },
        ];
        let output = destination.as_mut_ptr();

        let returned = unsafe {
            vector_copy_range_record8(source.as_ptr(), source.as_ptr().add(3), output)
        };

        for index in 0..3 {
            assert_eq!(destination[index].word, source[index].word);
            assert_eq!(destination[index].byte, source[index].byte);
            assert_eq!(destination[index].halfword, source[index].halfword);
        }
        assert_eq!([destination[0].padding, destination[1].padding, destination[2].padding], [0xa1, 0xb2, 0xc3]);
        assert_eq!(destination[3].word, 0xdddd_dddd, "range end is exclusive");
        assert_eq!(returned, unsafe { output.add(3) });
    }

    #[test]
    fn vector_copy_range_record8_empty_range_leaves_output_unchanged() {
        let source = [VectorRecord8 { word: 1, byte: 2, padding: 3, halfword: 4 }];
        let mut destination = [VectorRecord8 { word: 5, byte: 6, padding: 7, halfword: 8 }];
        let output = destination.as_mut_ptr();

        let returned = unsafe { vector_copy_range_record8(source.as_ptr(), source.as_ptr(), output) };

        assert_eq!(returned, output);
        assert_eq!(destination[0].word, 5);
        assert_eq!(destination[0].byte, 6);
        assert_eq!(destination[0].padding, 7);
        assert_eq!(destination[0].halfword, 8);
    }

    #[test]
    fn vector_copy_range_record8_null_output_skips_one_record_without_reading_source() {
        let returned = unsafe {
            vector_copy_range_record8(
                core::ptr::null(),
                8usize as *const VectorRecord8,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(returned, 8usize as *mut VectorRecord8, "skipped record still advances output");
    }
    #[test]
    fn container_end_cursor_returns_the_opaque_end_word() {
        let owner = ContainerEndCursorOwner {
            unknown_0: 0x0102_0304,
            unknown_4: 0x1112_1314,
            unknown_8: 0x2122_2324,
            unknown_c: 0x3132_3334,
            end_cursor: 0xfedc_ba98,
        };

        assert_eq!(
            unsafe { container_end_cursor(&owner) },
            0xfedc_ba98,
            "the member loads only the owner word at +0x10"
        );
    }

    #[test]
    fn container_end_cursor_preserves_a_null_cursor_word() {
        let owner = ContainerEndCursorOwner {
            unknown_0: u32::MAX,
            unknown_4: u32::MAX,
            unknown_8: u32::MAX,
            unknown_c: u32::MAX,
            end_cursor: 0,
        };

        assert_eq!(unsafe { container_end_cursor(&owner) }, 0);
    }

    #[test]
    fn container_begin_cursor_returns_nested_cursor_word() {
        let Some(cursor_state) = crate::testing::try_map_u32_slab(
            crate::testing::hints::CONTAINER_BEGIN_CURSOR,
            core::mem::size_of::<ContainerCursorState>(),
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("cxx::templates"));
            return;
        };
        unsafe {
            cursor_state.cast::<ContainerCursorState>().write(ContainerCursorState {
                unknown_0: 0x0102_0304,
                unknown_4: 0x1112_1314,
                begin_cursor: 0xfedc_ba98,
            });
        }
        let owner = ContainerBeginCursorOwner {
            unknown_0: 0x2122_2324,
            unknown_4: 0x3132_3334,
            unknown_8: 0x4142_4344,
            unknown_c: 0x5152_5354,
            cursor_state: cursor_state as usize as u32,
        };

        assert_eq!(
            unsafe { container_begin_cursor(&owner) },
            0xfedc_ba98,
            "the member loads only cursor-state word +0x8"
        );
    }

    #[test]
    fn deque_pop_front_elem4_keeps_a_live_segment() {
        let mut segment = [0u32; 32];
        let base = segment.as_mut_ptr().cast::<u8>();
        let mut map = [base];
        let begin = DequeIter {
            cur: base.wrapping_add(12),
            seg_base: base,
            seg_end: base.wrapping_add(0x80),
            seg_slot: map.as_mut_ptr(),
        };
        let mut deque = BlockDeque {
            begin,
            end: DequeIter::NULL,
            count: 2,
            map: map.as_mut_ptr(),
            map_cap: 1,
        };
        let mut frees = Vec::new();

        unsafe {
            deque_pop_front_elem4_with(&mut deque, |ptr, count, elem_size| {
                frees.push((ptr, count, elem_size));
            });
        }

        assert_eq!(deque.count, 1);
        assert_eq!(deque.begin.cur, base.wrapping_add(16));
        assert_eq!(deque.begin.seg_base, base);
        assert_eq!(deque.begin.seg_end, base.wrapping_add(0x80));
        assert_eq!(deque.begin.seg_slot, map.as_mut_ptr());
        assert!(frees.is_empty(), "an unspent live segment is retained");
    }

    #[test]
    fn deque_pop_front_elem4_retires_spent_segment_and_reanchors() {
        let mut old_segment = [0u32; 32];
        let mut next_segment = [0u32; 32];
        let old_base = old_segment.as_mut_ptr().cast::<u8>();
        let next_base = next_segment.as_mut_ptr().cast::<u8>();
        let mut map = [old_base, next_base];
        let begin = DequeIter {
            cur: old_base.wrapping_add(0x7c),
            seg_base: old_base,
            seg_end: old_base.wrapping_add(0x80),
            seg_slot: map.as_mut_ptr(),
        };
        let mut deque = BlockDeque {
            begin,
            end: DequeIter::NULL,
            count: 2,
            map: map.as_mut_ptr(),
            map_cap: 2,
        };
        let mut frees = Vec::new();

        unsafe {
            deque_pop_front_elem4_with(&mut deque, |ptr, count, elem_size| {
                frees.push((ptr, count, elem_size));
            });
        }

        assert_eq!(frees, std::vec![(old_base, 0x20, 0)]);
        assert_eq!(deque.count, 1);
        assert_eq!(deque.begin.cur, next_base);
        assert_eq!(deque.begin.seg_base, next_base);
        assert_eq!(deque.begin.seg_end, next_base.wrapping_add(0x80));
        assert_eq!(deque.begin.seg_slot, unsafe { map.as_mut_ptr().add(1) });
        assert_eq!(deque.end.cur, core::ptr::null_mut(), "end is untouched");
    }

    #[test]
    fn deque_pop_front_elem4_last_element_resets_iterators_and_frees_map() {
        let mut segment = [0u32; 32];
        let base = segment.as_mut_ptr().cast::<u8>();
        let mut map = [base];
        let begin = DequeIter {
            cur: base.wrapping_add(0x7c),
            seg_base: base,
            seg_end: base.wrapping_add(0x80),
            seg_slot: map.as_mut_ptr(),
        };
        let mut deque = BlockDeque {
            begin,
            end: begin,
            count: 1,
            map: map.as_mut_ptr(),
            map_cap: 7,
        };
        let map_ptr = deque.map.cast::<u8>();
        let mut frees = Vec::new();

        unsafe {
            deque_pop_front_elem4_with(&mut deque, |ptr, count, elem_size| {
                frees.push((ptr, count, elem_size));
            });
        }

        assert_eq!(frees, std::vec![(base, 0x20, 0), (map_ptr, 7, 0)]);
        assert_eq!(deque.count, 0);
        assert!(deque.begin.cur.is_null());
        assert!(deque.begin.seg_base.is_null());
        assert!(deque.begin.seg_end.is_null());
        assert!(deque.begin.seg_slot.is_null());
        assert!(deque.end.cur.is_null());
        assert!(deque.end.seg_base.is_null());
        assert!(deque.end.seg_end.is_null());
        assert!(deque.end.seg_slot.is_null());
    }

    #[test]
    fn deque_drain_elem4_removes_all_elements_and_returns_its_argument() {
        let mut old_segment = [0u32; 32];
        let mut next_segment = [0u32; 32];
        let old_base = old_segment.as_mut_ptr().cast::<u8>();
        let next_base = next_segment.as_mut_ptr().cast::<u8>();
        let mut map = [old_base, next_base];
        let begin = DequeIter {
            cur: old_base.wrapping_add(0x7c),
            seg_base: old_base,
            seg_end: old_base.wrapping_add(0x80),
            seg_slot: map.as_mut_ptr(),
        };
        let end = DequeIter {
            cur: next_base.wrapping_add(4),
            seg_base: next_base,
            seg_end: next_base.wrapping_add(0x80),
            seg_slot: unsafe { map.as_mut_ptr().add(1) },
        };
        let mut deque = BlockDeque {
            begin,
            end,
            count: 2,
            map: map.as_mut_ptr(),
            map_cap: 2,
        };
        let map_ptr = deque.map.cast::<u8>();
        let mut frees = Vec::new();

        let returned = unsafe {
            deque_drain_elem4_with(&mut deque, |ptr, count, elem_size| {
                frees.push((ptr, count, elem_size));
            })
        };

        assert!(core::ptr::eq(returned, &mut deque));
        assert_eq!(frees, std::vec![(old_base, 0x20, 0), (next_base, 0x20, 0), (map_ptr, 2, 0)]);
        assert_eq!(deque.count, 0);
        assert!(deque.begin.cur.is_null() && deque.begin.seg_base.is_null());
        assert!(deque.begin.seg_end.is_null() && deque.begin.seg_slot.is_null());
        assert!(deque.end.cur.is_null() && deque.end.seg_base.is_null());
        assert!(deque.end.seg_end.is_null() && deque.end.seg_slot.is_null());
    }

    #[test]
    fn deque_iter_distance_elem4_counts_same_and_cross_segment_positions() {
        let same_left = DequeIter {
            cur: 0x100cusize as *mut u8,
            seg_base: 0x1000usize as *mut u8,
            seg_end: 0x1080usize as *mut u8,
            seg_slot: 0x2000usize as *mut *mut u8,
        };
        let same_right = DequeIter {
            cur: 0x1000usize as *mut u8,
            ..same_left
        };
        let later_segment = DequeIter {
            cur: 0x300cusize as *mut u8,
            seg_base: 0x3000usize as *mut u8,
            seg_end: 0x3080usize as *mut u8,
            seg_slot: 0x2008usize as *mut *mut u8,
        };
        let earlier_segment = DequeIter {
            cur: 0x4080usize as *mut u8,
            seg_base: 0x4000usize as *mut u8,
            seg_end: 0x4080usize as *mut u8,
            seg_slot: 0x2000usize as *mut *mut u8,
        };

        unsafe {
            assert_eq!(deque_iter_distance_elem4(&later_segment, &same_left), 64);
            assert_eq!(deque_iter_distance_elem4(&same_left, &later_segment), -64);
            assert_eq!(deque_iter_distance_elem4(&earlier_segment, &later_segment), -35);
        }
    }

    #[test]
    fn deque_iter_distance_elem4_alias_ad78_matches_same_and_cross_segment_positions() {
        let same_left = DequeIter {
            cur: 0x100cusize as *mut u8,
            seg_base: 0x1000usize as *mut u8,
            seg_end: 0x1080usize as *mut u8,
            seg_slot: 0x2000usize as *mut *mut u8,
        };
        let same_right = DequeIter {
            cur: 0x1000usize as *mut u8,
            ..same_left
        };
        let later_segment = DequeIter {
            cur: 0x300cusize as *mut u8,
            seg_base: 0x3000usize as *mut u8,
            seg_end: 0x3080usize as *mut u8,
            seg_slot: 0x2008usize as *mut *mut u8,
        };

        unsafe {
            assert_eq!(deque_iter_distance_elem4_alias_ad78(&same_left, &same_right), 3);
            assert_eq!(deque_iter_distance_elem4_alias_ad78(&later_segment, &same_left), 64);
            assert_eq!(deque_iter_distance_elem4_alias_ad78(&same_left, &later_segment), -64);
        }
    }


    #[test]
    fn deque_iter_equal_handles_identical_and_distinct_interior_positions() {
        let mut segment = [0u32; 32];
        let base = segment.as_mut_ptr().cast::<u8>();
        let mut slots = [base];
        let left = DequeIter {
            cur: unsafe { base.add(12) },
            seg_base: base,
            seg_end: unsafe { base.add(0x80) },
            seg_slot: slots.as_mut_ptr(),
        };
        let same_position = DequeIter {
            cur: left.cur,
            seg_base: base,
            seg_end: left.seg_end,
            seg_slot: slots.as_mut_ptr(),
        };
        let different_position = DequeIter {
            cur: unsafe { base.add(16) },
            seg_base: base,
            seg_end: left.seg_end,
            seg_slot: slots.as_mut_ptr(),
        };

        unsafe {
            assert_eq!(deque_iter_equal(&left, &same_position), 1);
            assert_eq!(deque_iter_equal(&left, &different_position), 0);
            assert_eq!(deque_iter_equal_elem4_alias_ab58(&left, &same_position), 1);
            assert_eq!(deque_iter_equal_elem4_alias_ab58(&left, &different_position), 0);
        }
    }

    #[test]
    fn deque_iter_equal_aliases_adjacent_segment_boundary_only() {
        let mut first_segment = [0u32; 32];
        let mut second_segment = [0u32; 32];
        let mut third_segment = [0u32; 32];
        let first_base = first_segment.as_mut_ptr().cast::<u8>();
        let second_base = second_segment.as_mut_ptr().cast::<u8>();
        let third_base = third_segment.as_mut_ptr().cast::<u8>();
        let mut slots = [first_base, second_base, third_base];
        let first_end = DequeIter {
            cur: unsafe { first_base.add(0x80) },
            seg_base: first_base,
            seg_end: unsafe { first_base.add(0x80) },
            seg_slot: slots.as_mut_ptr(),
        };
        let second_begin = DequeIter {
            cur: second_base,
            seg_base: second_base,
            seg_end: unsafe { second_base.add(0x80) },
            seg_slot: unsafe { slots.as_mut_ptr().add(1) },
        };
        let second_interior = DequeIter {
            cur: unsafe { second_base.add(4) },
            seg_base: second_base,
            seg_end: second_begin.seg_end,
            seg_slot: second_begin.seg_slot,
        };
        let third_begin = DequeIter {
            cur: third_base,
            seg_base: third_base,
            seg_end: unsafe { third_base.add(0x80) },
            seg_slot: unsafe { slots.as_mut_ptr().add(2) },
        };

        unsafe {
            assert_eq!(deque_iter_equal(&first_end, &second_begin), 1);
            assert_eq!(deque_iter_equal(&second_begin, &first_end), 1);
            assert_eq!(deque_iter_equal(&first_end, &second_interior), 0);
            assert_eq!(deque_iter_equal(&first_end, &third_begin), 0);
            assert_eq!(deque_iter_equal_elem4_alias_ab58(&first_end, &second_begin), 1);
            assert_eq!(deque_iter_equal_elem4_alias_ab58(&second_begin, &first_end), 1);
            assert_eq!(deque_iter_equal_elem4_alias_ab58(&first_end, &second_interior), 0);
            assert_eq!(deque_iter_equal_elem4_alias_ab58(&first_end, &third_begin), 0);
        }
    }
    #[test]
    fn vector_clear_elem4_discards_live_words_without_releasing_storage() {
        let mut elements = [0x0102_0304u32, 0x1112_1314, 0x2122_2324, 0x3132_3334];
        let begin = elements.as_mut_ptr().cast::<u8>();
        let capacity = unsafe { begin.add(core::mem::size_of_val(&elements)) };
        let mut vector = VectorStorage {
            begin,
            end: unsafe { begin.add(12) },
            end_of_storage: capacity,
        };

        unsafe { vector_clear_elem4(&mut vector) };

        assert_eq!(vector.begin, begin);
        assert_eq!(vector.end, begin);
        assert_eq!(vector.end_of_storage, capacity);
        assert_eq!(elements, [0x0102_0304, 0x1112_1314, 0x2122_2324, 0x3132_3334]);
    }

    #[test]
    fn vector_clear_elem4_keeps_an_empty_head_unchanged() {
        let mut elements = [0xaaaa_aaaau32; 2];
        let begin = elements.as_mut_ptr().cast::<u8>();
        let capacity = unsafe { begin.add(core::mem::size_of_val(&elements)) };
        let mut vector = VectorStorage {
            begin,
            end: begin,
            end_of_storage: capacity,
        };

        unsafe { vector_clear_elem4(&mut vector) };

        assert_eq!(vector.begin, begin);
        assert_eq!(vector.end, begin);
        assert_eq!(vector.end_of_storage, capacity);
        assert_eq!(elements, [0xaaaa_aaaa; 2]);
    }

    #[test]
    fn container_remove_element_uses_lookup_result_and_rereads_the_vtable() {
        static mut LOOKUP_CONTAINER: usize = 0;
        static mut LOOKUP_ELEMENT: usize = 0;
        static mut LOOKUP_CALLS: u32 = 0;
        static mut LOOKUP_RESULT: i32 = 0;
        static mut REMOVE_CONTAINER: usize = 0;
        static mut REMOVE_INDEX: i32 = 0;
        static mut REMOVE_CALLS: u32 = 0;
        static mut WRONG_SLOT_CALLS: u32 = 0;
        static mut REPLACEMENT_VTABLE: *const usize = core::ptr::null();

        #[repr(C)]
        struct Container {
            vtable: *const usize,
        }

        unsafe extern "C" fn wrong_lookup(_container: *mut u8, _element: *mut u8) -> i32 {
            WRONG_SLOT_CALLS += 1;
            i32::MIN
        }

        unsafe extern "C" fn record_lookup(container: *mut u8, element: *mut u8) -> i32 {
            LOOKUP_CONTAINER = container as usize;
            LOOKUP_ELEMENT = element as usize;
            LOOKUP_CALLS += 1;
            LOOKUP_RESULT
        }

        unsafe extern "C" fn replace_vtable_and_lookup(
            container: *mut u8,
            element: *mut u8,
        ) -> i32 {
            LOOKUP_CONTAINER = container as usize;
            LOOKUP_ELEMENT = element as usize;
            LOOKUP_CALLS += 1;
            (container as *mut *const usize).write(REPLACEMENT_VTABLE);
            LOOKUP_RESULT
        }

        unsafe extern "C" fn record_remove(container: *mut u8, index: i32) {
            REMOVE_CONTAINER = container as usize;
            REMOVE_INDEX = index;
            REMOVE_CALLS += 1;
        }

        unsafe extern "C" fn wrong_remove(_container: *mut u8, _index: i32) {
            WRONG_SLOT_CALLS += 1;
        }

        unsafe {
            LOOKUP_CONTAINER = 0;
            LOOKUP_ELEMENT = 0;
            LOOKUP_CALLS = 0;
            LOOKUP_RESULT = 23;
            REMOVE_CONTAINER = 0;
            REMOVE_INDEX = 0;
            REMOVE_CALLS = 0;
            WRONG_SLOT_CALLS = 0;

            let mut vtable = [wrong_lookup as usize; CONTAINER_ELEMENT_LOOKUP_SLOT + 1];
            vtable[CONTAINER_ELEMENT_LOOKUP_SLOT] = record_lookup as usize;
            vtable[CONTAINER_REMOVE_AT_SLOT] = record_remove as usize;
            let mut container = Container {
                vtable: vtable.as_ptr(),
            };
            let mut element = 0u8;
            let container_ptr = (&mut container as *mut Container).cast::<u8>();

            assert_eq!(container_remove_element(container_ptr, &mut element), 23);
            assert_eq!(LOOKUP_CALLS, 1);
            assert_eq!(LOOKUP_CONTAINER, container_ptr as usize);
            assert_eq!(LOOKUP_ELEMENT, core::ptr::addr_of_mut!(element) as usize);
            assert_eq!(REMOVE_CALLS, 1);
            assert_eq!(REMOVE_CONTAINER, container_ptr as usize);
            assert_eq!(REMOVE_INDEX, 23);
            assert_eq!(WRONG_SLOT_CALLS, 0, "only vtable slots +0x4c and +0x2c dispatch");

            LOOKUP_CALLS = 0;
            LOOKUP_RESULT = 7;
            REMOVE_CALLS = 0;
            WRONG_SLOT_CALLS = 0;
            let mut replacement = [wrong_lookup as usize; CONTAINER_ELEMENT_LOOKUP_SLOT + 1];
            replacement[CONTAINER_REMOVE_AT_SLOT] = record_remove as usize;
            REPLACEMENT_VTABLE = replacement.as_ptr();
            vtable[CONTAINER_ELEMENT_LOOKUP_SLOT] = replace_vtable_and_lookup as usize;
            vtable[CONTAINER_REMOVE_AT_SLOT] = wrong_remove as usize;
            container.vtable = vtable.as_ptr();

            assert_eq!(container_remove_element(container_ptr, &mut element), 7);
            assert_eq!(LOOKUP_CALLS, 1);
            assert_eq!(REMOVE_CALLS, 1, "the lookup's replacement vtable is re-read");
            assert_eq!(REMOVE_INDEX, 7);
            assert_eq!(WRONG_SLOT_CALLS, 0, "the old vtable's remove slot is not reused");

            LOOKUP_CALLS = 0;
            LOOKUP_RESULT = -1;
            REMOVE_CALLS = 0;
            WRONG_SLOT_CALLS = 0;
            vtable[CONTAINER_ELEMENT_LOOKUP_SLOT] = record_lookup as usize;
            vtable[CONTAINER_REMOVE_AT_SLOT] = wrong_remove as usize;
            container.vtable = vtable.as_ptr();

            assert_eq!(container_remove_element(container_ptr, &mut element), -1);
            assert_eq!(LOOKUP_CALLS, 1);
            assert_eq!(REMOVE_CALLS, 0, "-1 skips the remove dispatch");
            assert_eq!(WRONG_SLOT_CALLS, 0);
        }
    }

    fn body(refcount: i32) -> RefcountedBody {
        RefcountedBody {
            opaque0: 0,
            refcount,
            mutex: core::ptr::null_mut(),
        }
    }

    #[test]
    fn attach_range_attaches_every_body_and_returns_advanced_output() {
        unsafe {
            let mut bodies = [body(0), body(7), body(-3)];
            let mut slots: [*mut RefcountedBody; 3] = [
                &mut bodies[0],
                &mut bodies[1],
                &mut bodies[2],
            ];
            let mut out: [*mut RefcountedBody; 3] = [core::ptr::null_mut(); 3];
            let end = vector_copy_construct_range_attach(
                slots.as_ptr(),
                slots.as_ptr().add(3),
                out.as_mut_ptr(),
            );
            assert_eq!(end, out.as_mut_ptr().add(3));
            assert_eq!(out[0], &mut bodies[0] as *mut _);
            assert_eq!(out[1], &mut bodies[1] as *mut _);
            assert_eq!(out[2], &mut bodies[2] as *mut _);
            // Each attach bumps the (unguarded) refcount exactly once.
            assert_eq!(bodies[0].refcount, 1);
            assert_eq!(bodies[1].refcount, 8);
            assert_eq!(bodies[2].refcount, -2);
            // Source slots are read, never written.
            assert_eq!(slots[0], &mut bodies[0] as *mut _);
        }
    }

    #[test]
    fn attach_range_empty_range_returns_output_untouched() {
        unsafe {
            let mut b = body(5);
            let mut slot_cell: *mut RefcountedBody = &mut b;
            let slot: *const *mut RefcountedBody = &mut slot_cell;
            let mut out: [*mut RefcountedBody; 1] = [core::ptr::null_mut()];
            let end = vector_copy_construct_range_attach(slot, slot, out.as_mut_ptr());
            assert_eq!(end, out.as_mut_ptr());
            assert!(out[0].is_null());
            assert_eq!(b.refcount, 5);
        }
    }

    #[test]
    fn attach_range_single_element_advances_both_cursors_once() {
        unsafe {
            let mut b = body(41);
            let mut slot: *mut RefcountedBody = &mut b;
            let mut out: [*mut RefcountedBody; 2] = [core::ptr::null_mut(); 2];
            let end = vector_copy_construct_range_attach(
                &slot,
                (&slot as *const *mut RefcountedBody).add(1),
                out.as_mut_ptr(),
            );
            assert_eq!(end, out.as_mut_ptr().add(1));
            assert_eq!(out[0], &mut b as *mut _);
            assert!(out[1].is_null(), "second slot is past the range");
            assert_eq!(b.refcount, 42);
        }
    }
    #[test]
    fn attach_range_8c0c_attaches_and_returns_the_target_word_end() {
        unsafe {
            let mut bodies = [body(i32::MAX), body(-1)];
            let slots = [&mut bodies[0] as *mut _, &mut bodies[1] as *mut _];
            let mut out: [*mut RefcountedBody; 2] = [core::ptr::null_mut(); 2];
            let end = vector_copy_construct_range_attach_8c0c(
                slots.as_ptr(),
                slots.as_ptr().add(2),
                out.as_mut_ptr(),
            );
            assert_eq!(end, out.as_mut_ptr().add(2));
            assert_eq!(out, slots);
            assert_eq!(bodies[0].refcount, i32::MIN);
            assert_eq!(bodies[1].refcount, 0);
        }
    }

    /// One record with a NULL output: the `movs` guard skips the only
    /// attach, but the output cursor still advances by one slot (host
    /// stride is `size_of::<*mut RefcountedBody>()`). A second record
    /// would attach at 0x4/0x8, exactly like the original, so that path
    /// is not host-testable.
    #[test]
    fn attach_range_null_output_skips_only_attach_and_still_advances() {
        unsafe {
            let mut b = body(9);
            let mut slot: *mut RefcountedBody = &mut b;
            let end = vector_copy_construct_range_attach(
                &slot,
                (&slot as *const *mut RefcountedBody).add(1),
                core::ptr::null_mut(),
            );
            assert_eq!(end, (core::ptr::null_mut() as *mut *mut RefcountedBody).wrapping_add(1));
            assert_eq!(b.refcount, 9, "no attach happened");
        }
    }

    #[test]
    fn vector_copy_range_u8_copies_empty_and_nonempty_ranges() {
        unsafe {
            let source = [0x11u8, 0x22, 0x33];
            let mut destination = [0xaau8; 4];

            assert_eq!(
                vector_copy_range_u8(source.as_ptr(), source.as_ptr(), destination.as_mut_ptr()),
                destination.as_mut_ptr()
            );
            assert_eq!(destination, [0xaa; 4]);

            assert_eq!(
                vector_copy_range_u8(
                    source.as_ptr(),
                    source.as_ptr().add(source.len()),
                    destination.as_mut_ptr(),
                ),
                destination.as_mut_ptr().add(source.len())
            );
            assert_eq!(destination, [0x11, 0x22, 0x33, 0xaa]);
        }
    }

    #[test]
    fn vector_copy_range_u8_null_output_skips_source_read_and_advances() {
        unsafe {
            let first = 0x1 as *const u8;
            let last = first.wrapping_add(1);
            assert_eq!(
                vector_copy_range_u8(first, last, core::ptr::null_mut()),
                core::ptr::null_mut::<u8>().wrapping_add(1)
            );
        }
    }

    #[test]
    fn attach_range_null_body_is_stored_without_a_bump() {
        unsafe {
            let mut slot: *mut RefcountedBody = core::ptr::null_mut();
            let mut out: *mut RefcountedBody = 0xdeadbeef as *mut RefcountedBody;
            let end = vector_copy_construct_range_attach(
                &slot,
                (&slot as *const *mut RefcountedBody).add(1),
                &mut out,
            );
            assert_eq!(end, (&mut out as *mut *mut RefcountedBody).add(1));
            // The attach's store is unconditional: the NULL body lands
            // in the destination slot and no refcount is touched.
            assert!(out.is_null());
        }
    }
    #[test]
    fn deque_iter_assign_alias_a1b0_copies_words_forward_and_returns_destination() {
        unsafe {
            let src = [0x0102_0304u32, 0x1112_1314, 0x2122_2324, 0x3132_3334];
            let mut dst = [0xdead_beefu32; 4];
            assert_eq!(
                deque_iter_assign_alias_a1b0(dst.as_mut_ptr(), src.as_ptr()),
                dst.as_mut_ptr(),
            );
            assert_eq!(dst, src);

            let mut overlapping = [1u32, 2, 3, 4, 5];
            deque_iter_assign_alias_a1b0(overlapping.as_mut_ptr().add(1), overlapping.as_ptr());
            assert_eq!(overlapping, [1, 1, 1, 1, 1]);
        }
    }
    unsafe extern "C" fn delete_enabled_element_slot(
        container: *mut u8,
        index: usize,
    ) -> *mut *mut u8 {
        let fixture = container.cast::<DeleteEnabledFixture>();
        (*fixture).calls += 1;
        (*fixture).elements.as_mut_ptr().add(index)
    }

    #[repr(C)]
    struct DeleteEnabledFixture {
        container: ContainerDeleteEnabledElements,
        elements: [*mut u8; 3],
        calls: usize,
    }

    #[test]
    fn delete_enabled_elements_obeys_flag_and_signed_count() {
        unsafe {
            let vtable = [delete_enabled_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut fixture = DeleteEnabledFixture {
                container: ContainerDeleteEnabledElements {
                    vtable: vtable.as_ptr(),
                    count: 3,
                    _unknown_08: 0,
                    _unknown_0c: 0,
                    delete_enabled: 1,
                },
                elements: [core::ptr::null_mut(); 3],
                calls: 0,
            };

            container_delete_enabled_elements(&mut fixture.container);
            assert_eq!(fixture.calls, 3, "every index below count is retrieved");

            fixture.container.delete_enabled = 0;
            container_delete_enabled_elements(&mut fixture.container);
            fixture.container.delete_enabled = 1;
            fixture.container.count = -1;
            container_delete_enabled_elements(&mut fixture.container);
            assert_eq!(fixture.calls, 3, "disabled and nonpositive counts do not access elements");
        }
    }

    #[test]
    fn scoped_context_delete_enabled_elements_obeys_flag_and_signed_count() {
        unsafe {
            let vtable = [delete_enabled_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut fixture = DeleteEnabledFixture {
                container: ContainerDeleteEnabledElements {
                    vtable: vtable.as_ptr(),
                    count: 3,
                    _unknown_08: 0,
                    _unknown_0c: 0,
                    delete_enabled: 1,
                },
                elements: [core::ptr::null_mut(); 3],
                calls: 0,
            };

            scoped_context_container_delete_enabled_elements(&mut fixture.container);
            assert_eq!(fixture.calls, 3, "every index below count is retrieved");

            fixture.container.delete_enabled = 0;
            scoped_context_container_delete_enabled_elements(&mut fixture.container);
            fixture.container.delete_enabled = 1;
            fixture.container.count = -1;
            scoped_context_container_delete_enabled_elements(&mut fixture.container);
            assert_eq!(fixture.calls, 3, "disabled and nonpositive counts do not access elements");
        }
    }
    #[repr(C)]
    struct ReleaseEnabledFixture {
        container: ContainerReleaseEnabledElements,
        elements: [*mut u8; 3],
        accessor_calls: usize,
    }

    #[repr(C)]
    struct ReleaseEnabledElement {
        vtable: *const ContainerElementReleaseVtable,
        id: usize,
    }

    static RELEASE_ENABLED_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static mut RELEASED_ELEMENTS: [usize; 3] = [0; 3];
    static mut RELEASED_COUNT: usize = 0;

    unsafe extern "C" fn release_enabled_element(element: *mut u8) {
        let element = element.cast::<ReleaseEnabledElement>();
        RELEASED_ELEMENTS[RELEASED_COUNT] = (*element).id;
        RELEASED_COUNT += 1;
    }

    unsafe extern "C" fn release_enabled_element_slot(
        container: *mut u8,
        index: usize,
    ) -> *mut *mut u8 {
        let fixture = container.cast::<ReleaseEnabledFixture>();
        (*fixture).accessor_calls += 1;
        (*fixture).elements.as_mut_ptr().add(index)
    }

    #[test]
    fn release_enabled_elements_skips_nulls_and_honors_flag_and_count() {
        let _guard = RELEASE_ENABLED_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            RELEASED_COUNT = 0;
            let accessor_vtable = [release_enabled_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let release_vtable = ContainerElementReleaseVtable {
                _slot_00: 0,
                release: release_enabled_element,
            };
            let mut first = ReleaseEnabledElement { vtable: &release_vtable, id: 7 };
            let mut second = ReleaseEnabledElement { vtable: &release_vtable, id: 9 };
            let mut fixture = ReleaseEnabledFixture {
                container: ContainerReleaseEnabledElements {
                    vtable: accessor_vtable.as_ptr(),
                    count: 3,
                    _unknown_08_24: [0; 8],
                    release_enabled: 1,
                },
                elements: [
                    &mut first as *mut ReleaseEnabledElement as *mut u8,
                    core::ptr::null_mut(),
                    &mut second as *mut ReleaseEnabledElement as *mut u8,
                ],
                accessor_calls: 0,
            };

            container_release_enabled_elements(&mut fixture.container);
            assert_eq!(fixture.accessor_calls, 3);
            assert_eq!(RELEASED_COUNT, 2);
            assert_eq!(RELEASED_ELEMENTS[..2], [7, 9]);

            fixture.container.release_enabled = 0;
            container_release_enabled_elements(&mut fixture.container);
            fixture.container.release_enabled = 1;
            fixture.container.count = -1;
            container_release_enabled_elements(&mut fixture.container);
            assert_eq!(fixture.accessor_calls, 3);
            assert_eq!(RELEASED_COUNT, 2);
        }
    }
}
