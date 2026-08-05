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
//! - [`less_signed`] / [`less_unsigned`] — `std::less`-shaped
//!   comparators taking their operands by reference, 1 and 12 copies,
//!   45 and 73 call sites.
//! - [`container_element_at`] — indexed element access through the
//!   container's virtual element-slot method, 30 copies, 154 call
//!   sites (the largest family in the block after the handle accessor).
//! - [`array_at_checked`] — bounds-checked lookup in a
//!   {base, count} pointer array, 2 copies, 43 call sites.
//! - [`pair_assign_guarded`] — the self-assignment-guarded two-word
//!   copy-assign of a pair-shaped value type, the only copy, 14 call
//!   sites.
//! - [`vector_size_elem4`] / [`vector_size_elem8`] /
//!   [`vector_size_elem16`] / [`vector_size_elem32`] —
//!   `vector<T>::size()`, one instantiation per element size; the four
//!   power-of-two shifts cover 28 functions and 276 call sites.
//! - [`vector_size_elem12`] / [`vector_size_elem24`] /
//!   [`vector_size_elem20`] / [`vector_size_elem28`] /
//!   [`vector_size_elem40`] — the
//!   non-power-of-two members of the size family, dividing the span by
//!   12, 24, 20, 28 or 40 through [`__rt_sdiv`] instead of shifting.
//! - [`vector_capacity`] / [`vector_capacity_elem12`] /
//!   [`vector_capacity_elem16`] / [`vector_capacity_elem24_copy_77ec`]
//!   / [`vector_capacity_elem40`] / [`vector_capacity_elem8`] /
//!   [`vector_capacity_elem4`] —
//!   `vector<T>::capacity()` for 24-, 12-, 16-, 40-, 8- and 4-byte
//!   elements,
//!   the end-of-storage sibling of the size family (divide-based for
//!   24/12/40, shift-based for 16/8/4; the 24-byte copy is a
//!   byte-identical second instantiation of the primary).
//!
//! Not to be confused with `deque_iter_copy` @ 0x083dd9e4 (already
//! ported in `heap/block_deque`): that one is the same four-word copy
//! with the **source in r2**, and it exists exactly once.

use crate::runtime::rt_div::__rt_sdiv;

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
/// byte-identical copies — see `names.yaml` for the list).
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


/// vector_size_elem8 — original: `FUN_083d7860` @ 0x083d7860
/// (16 bytes; 14 `bl` call sites there, 50 across 4 byte-identical
/// copies). [`vector_size_elem4`] with `>> 3`.
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
/// copies; only this one is ported, the other four stay identified in
/// `names.yaml`).
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
/// 0x083e5c60 — the last instantiation of the capacity family).
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

#[cfg(test)]
mod tests {
    use super::*;

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
            assert_eq!(vector_size_elem16(&reversed), -1);
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
}
