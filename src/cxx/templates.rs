//! Out-of-line template members of the C++ block that the compiler
//! emitted once per instantiation instead of sharing.
//!
//! Whole families of byte-identical functions sit in
//! 0x083c0000-0x083dffff, differing only in address: the accessor in
//! [`crate::cxx::handle`] (22 copies), `deque_seg_capacity`
//! @ 0x083d9ec0 in [`crate::heap::block_deque`] (17 copies), and the
//! three ported here. Each family needs exactly one port; `names.yaml`
//! carries the address lists so a hook can point every copy at it.
//!
//! - [`deque_iter_assign`] — the 16-byte deque-iterator copy, 17
//!   byte-identical copies, 99 `bl` call sites. Each copy sits
//!   immediately after that instantiation's `deque_seg_capacity`
//!   (8 bytes + 36 bytes, adjacent), which is what identifies the pair
//!   as the deque template's out-of-line members.
//! - [`less_signed`] / [`less_unsigned`] / [`less_unsigned_byte`] —
//!   `std::less`-shaped comparators taking their operands by
//!   reference, 1, 12 and 2 copies, 45, 73 and 13 call sites.
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
//! - [`cxx_vector_find_equal`] — searches the COW-string-keyed records
//!   within the `{unknown, begin, end}` owner shape used by the UI data.
//! - [`vector_size_elem2`] / [`vector_size_elem4`] /
//!   [`vector_size_elem8`] / [`vector_size_elem16`] /
//!   [`vector_size_elem32`] —
//!   `vector<T>::size()`, one instantiation per element size; the five
//!   power-of-two shifts cover 29 functions and 292 call sites.
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
//! - [`vector_capacity`] / [`vector_capacity_elem12`] /
//!   [`vector_capacity_elem16`] / [`vector_capacity_elem24_copy_77ec`]
//!   / [`vector_capacity_elem40`] / [`vector_capacity_elem8`] /
//!   [`vector_capacity_elem4`] / [`vector_capacity_elem20`] —
//!   `vector<T>::capacity()` for 24-, 12-, 16-, 40-, 8-, 4- and
//!   20-byte elements,
//!   the end-of-storage sibling of the size family (divide-based for
//!   24/12/40/20, shift-based for 16/8/4; the 24-byte copy is a
//!   byte-identical second instantiation of the primary).
//!
//! Not to be confused with `deque_iter_copy` @ 0x083dd9e4 (already
//! ported in `heap/block_deque`): that one is the same four-word copy
//! with the **source in r2**, and it exists exactly once.

use crate::cxx::string::cxx_string_release;
use crate::cxx::string_object::{string_object_destroy, StringObject};
use crate::libc::memcmp::memcmp;
use crate::runtime::rt_div::__rt_sdiv;

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

/// container_element_at — original: `FUN_083d5efc` @ 0x083d5efc
/// (24 bytes; 13 `bl` call sites there, 154 across all 30
/// byte-identical copies — see `names.yaml` for the list; the copy @
/// 0x083d68dc is ported below as [`container_element_at_alias_68dc`]).
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


#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::string_object::{StringObjectOps, STRING_OBJECT_OPS, STRING_OBJECT_VTABLE};
    use crate::cxx::string_object::tests::STRING_OBJECT_OPS_TEST_LOCK;
    use crate::cxx::string::StringRep;
    use std::sync::MutexGuard;
    use std::vec::Vec;

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
}
