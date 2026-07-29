//! `ptr_vector_count` — original: `FUN_08184f84` @ 0x08184f84
//! (20 bytes; 17 `bl` call sites from 10 distinct callers,
//! binary-scanned).
//!
//! An ADS-inlined `std::vector<T*>::size()`. The vector lives at +0x14
//! of a 0x24-byte owner object built by `FUN_08184fd4` @ 0x08184fd4
//! (vtable at +0x00, the container hook at +0x14), and the compiler
//! open-coded the size as `(end - begin) >> 2` rather than calling the
//! out-of-line helper `FUN_083d78c4` its sibling accessor uses:
//!
//! ```text
//! ldr r1, [r0, #0x18]   ; end
//! ldr r0, [r0, #0x14]   ; begin
//! sub r0, r1, r0
//! asr r0, r0, #2        ; / sizeof(T*)
//! ```
//!
//! Every call site is a loop bound over the same owner — e.g.
//! @ 0x08185398 and @ 0x081856a0:
//!
//! ```c
//! count = ptr_vector_count(owner);
//! for (i = 0; i < count; i++) { item = FUN_08184f98(owner, i); ... }
//! ```
//!
//! where the checked accessor [`ptr_vector_at`] (`FUN_08184f98` @
//! 0x08184f98, ported below) reads `begin[i]` after bounds-checking
//! `i` against `FUN_083d78c4(owner + 0x14)` — the same size through
//! the out-of-line path — and returns NULL when out of range. That
//! helper turned out to be one of the 17 byte-identical copies of
//! [`vector_size_elem4`], already ported in `crate::cxx::templates`,
//! which is what unblocked the accessor.
//!
//! Faithful details:
//! - The shift is `asr`, not `lsr`. An inverted (`end < begin`) vector
//!   therefore yields a *negative* count, which the original produces
//!   too; the call sites compare it unsigned (`bhi`), so such a vector
//!   would run a near-4-billion-iteration loop. Reproduced, not
//!   "fixed".
//! - `begin` and `end` are read as **32-bit words**, not host pointers.
//!   On target they are the vector's two pointers; a 64-bit host cannot
//!   hold a real pointer in them, so this function is meaningful there
//!   only with synthetic 32-bit values — which is exactly what the tests
//!   use (the `heap/block_region.rs` link-word precedent).

/// Byte offset of the vector's `begin` pointer inside the owner.
const VECTOR_BEGIN: usize = 0x14;
/// Byte offset of the vector's `end` pointer inside the owner.
const VECTOR_END: usize = 0x18;

/// Element size the original divides by (`asr #2` — a `T*`).
pub const ELEMENT_SIZE: u32 = 4;

use crate::cxx::templates::{vector_size_elem4, VectorBounds};

/// ptr_vector_count — original: `FUN_08184f84` @ 0x08184f84 (20 bytes).
///
/// Returns the number of pointers in the vector embedded at +0x14 of
/// `owner`, as `(end - begin) >> 2` with an *arithmetic* shift.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ptr_vector_count(owner: *const u8) -> i32 {
    let begin = (owner.add(VECTOR_BEGIN) as *const i32).read_volatile();
    let end = (owner.add(VECTOR_END) as *const i32).read_volatile();
    end.wrapping_sub(begin) >> 2
}

/// ptr_vector_at — original: `FUN_08184f98` @ 0x08184f98 (60 bytes;
/// 28 `bl` call sites, binary-scanned).
///
/// Bounds-checked element accessor for the vector at `owner + 0x14`
/// that [`ptr_vector_count`] measures:
///
/// ```c
/// if (size(owner + 0x14) != 0 && index < size(owner + 0x14))
///     return ((void **)*(owner + 0x14))[index];
/// return NULL;
/// ```
///
/// where `size` is the out-of-line helper @ 0x083d78c4 — one of the
/// 17 byte-identical copies of [`vector_size_elem4`], called here
/// directly. The original calls it TWICE (once for the non-empty
/// test, once for the bound), keeping `owner` and `index` in
/// callee-saved registers across the calls rather than the result.
///
/// Faithful details:
/// - The non-empty test is an exact `!= 0` on the SIGNED size
///   (`cmp r0, #0` / `beq`), but the bound compare is UNSIGNED
///   (`cmp r0, r5` / `ldrhi`). An inverted vector's negative size
///   therefore passes the non-empty test and then satisfies
///   `index < size` for nearly every index, so `begin[index]` is
///   loaded anyway — reproduced, not "fixed".
/// - `begin` is loaded only on the in-range path (both loads are
///   predicated `hi`), so an empty vector with a garbage begin word
///   is never dereferenced.
///
/// # Safety
/// `owner` must point at a readable [`VectorBounds`] at +0x14; when
/// the checks pass, `begin[index]` must be a readable pointer slot.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ptr_vector_at(owner: *const u8, index: u32) -> *mut u8 {
    let vector = owner.add(VECTOR_BEGIN) as *const VectorBounds;
    if vector_size_elem4(vector) == 0 {
        return core::ptr::null_mut();
    }
    let size = vector_size_elem4(vector);
    if index < size as u32 {
        // `read_unaligned`: the vector head at owner+0x14 is 4-aligned,
        // which is not pointer-aligned on a 64-bit host.
        let begin = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).begin));
        return (begin as *const *mut u8)
            .offset(index as isize)
            .read();
    }
    core::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The owner object: byte-addressed, word-aligned.
    #[repr(align(4))]
    struct Owner([u8; 0x24]);

    impl Owner {
        /// A vector spanning `[begin, end)` as raw 32-bit words.
        fn spanning(begin: i32, end: i32) -> Self {
            let mut owner = Owner([0xa5; 0x24]);
            owner.0[VECTOR_BEGIN..VECTOR_BEGIN + 4].copy_from_slice(&begin.to_le_bytes());
            owner.0[VECTOR_END..VECTOR_END + 4].copy_from_slice(&end.to_le_bytes());
            owner
        }
        fn ptr(&self) -> *const u8 {
            self.0.as_ptr()
        }
    }

    /// The reference: an honest pointer-difference element count.
    fn reference(begin: i32, end: i32) -> i32 {
        end.wrapping_sub(begin) >> 2
    }

    #[test]
    fn an_empty_vector_counts_zero() {
        let owner = Owner::spanning(0, 0);
        assert_eq!(unsafe { ptr_vector_count(owner.ptr()) }, 0);

        let owner = Owner::spanning(0x2000_0000, 0x2000_0000);
        assert_eq!(unsafe { ptr_vector_count(owner.ptr()) }, 0);
    }

    #[test]
    fn the_count_is_the_span_divided_by_the_element_size() {
        for count in 0..64i32 {
            let begin = 0x2000_0000i32;
            let end = begin + count * ELEMENT_SIZE as i32;
            let owner = Owner::spanning(begin, end);
            assert_eq!(unsafe { ptr_vector_count(owner.ptr()) }, count, "count {count}");
        }
    }

    #[test]
    fn it_matches_the_reference_across_the_address_space() {
        for begin in [0i32, 4, 0x40, 0x0800_0000, 0x2000_0000, 0x7fff_fff0] {
            for span in [0i32, 4, 8, 0x40, 0x400, 0x4000] {
                let end = begin.wrapping_add(span);
                let owner = Owner::spanning(begin, end);
                assert_eq!(
                    unsafe { ptr_vector_count(owner.ptr()) },
                    reference(begin, end),
                    "begin {begin:#x} span {span:#x}"
                );
            }
        }
    }

    #[test]
    fn an_inverted_vector_yields_a_negative_count() {
        // `asr`, not `lsr` — the original's sign extension is kept.
        let owner = Owner::spanning(0x2000_0010, 0x2000_0000);
        assert_eq!(unsafe { ptr_vector_count(owner.ptr()) }, -4);
    }

    #[test]
    fn a_misaligned_span_truncates_toward_negative_infinity() {
        // `asr` rounds down, so a stray byte in a forward span is lost
        // and a backward span rounds away from zero — again the
        // original's arithmetic, verified against the reference.
        for span in [1i32, 3, 5, 7, -1, -3, -5] {
            let owner = Owner::spanning(0x1000, 0x1000 + span);
            assert_eq!(
                unsafe { ptr_vector_count(owner.ptr()) },
                reference(0x1000, 0x1000 + span),
                "span {span}"
            );
        }
    }

    #[test]
    fn nothing_outside_the_two_words_is_read() {
        // Every other byte is 0xa5; the count must still be exact.
        let owner = Owner::spanning(0x100, 0x120);
        assert_eq!(unsafe { ptr_vector_count(owner.ptr()) }, 8);
    }

    // ---- ptr_vector_at -------------------------------------------------

    /// The owner through the accessor's eyes: padding up to +0x14,
    /// then the vector head, laid out as raw bytes so the head sits at
    /// exactly +0x14 regardless of the host pointer width (a `repr(C)`
    /// struct would pad the two-pointer `VectorBounds` to +0x18 on a
    /// 64-bit host).
    const PTR: usize = core::mem::size_of::<*mut u8>();

    #[repr(align(8))]
    struct AtOwner([u8; VECTOR_BEGIN + 2 * PTR]);

    impl AtOwner {
        fn over(begin: *mut u8, end: *mut u8) -> Self {
            let mut owner = AtOwner([0xa5; VECTOR_BEGIN + 2 * PTR]);
            owner.0[VECTOR_BEGIN..VECTOR_BEGIN + PTR]
                .copy_from_slice(&(begin as usize).to_ne_bytes());
            owner.0[VECTOR_BEGIN + PTR..VECTOR_BEGIN + 2 * PTR]
                .copy_from_slice(&(end as usize).to_ne_bytes());
            owner
        }
        fn ptr(&self) -> *const u8 {
            self.0.as_ptr()
        }
        fn vector(&self) -> *const VectorBounds {
            unsafe { self.0.as_ptr().add(VECTOR_BEGIN) as *const VectorBounds }
        }
    }

    /// The reference C, transcribed:
    /// `size != 0 && index < size (unsigned) ? begin[index] : NULL`.
    unsafe fn at_reference(vector: *const VectorBounds, index: u32) -> *mut u8 {
        let begin = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).begin));
        let end = core::ptr::read_unaligned(core::ptr::addr_of!((*vector).end));
        let size = (end as isize - begin as isize) >> 2;
        if size == 0 || index >= size as u32 {
            return core::ptr::null_mut();
        }
        (begin as *const *mut u8)
            .offset(index as isize)
            .read()
    }

    #[test]
    fn at_returns_the_indexed_element() {
        unsafe {
            let mut elements = [1u8, 2, 3, 4];
            let mut slots: [*mut u8; 4] = [core::ptr::null_mut(); 4];
            for (slot, element) in slots.iter_mut().zip(elements.iter_mut()) {
                *slot = element;
            }
            let begin = slots.as_mut_ptr() as *mut u8;
            let owner = AtOwner::over(begin, begin.add(4 * ELEMENT_SIZE as usize));
            for index in 0..4u32 {
                assert_eq!(
                    ptr_vector_at(owner.ptr(), index),
                    slots[index as usize],
                    "index {index}"
                );
            }
            let _ = &mut slots;
        }
    }

    #[test]
    fn at_returns_null_at_and_past_the_end() {
        unsafe {
            let mut element = 1u8;
            let mut slots: [*mut u8; 2] = [&mut element, &mut element];
            let begin = slots.as_mut_ptr() as *mut u8;
            let owner = AtOwner::over(begin, begin.add(2 * ELEMENT_SIZE as usize));
            let owner = owner.ptr();
            assert!(ptr_vector_at(owner, 2).is_null(), "count is exclusive");
            assert!(ptr_vector_at(owner, 3).is_null());
            assert!(ptr_vector_at(owner, u32::MAX).is_null());
        }
    }

    /// An empty vector never loads `begin` — the original's loads are
    /// predicated on the bound — so a dangling begin word is harmless.
    #[test]
    fn at_returns_null_for_an_empty_vector_without_touching_begin() {
        unsafe {
            let dangling = 0x5555 as *mut u8;
            let owner = AtOwner::over(dangling, dangling);
            assert!(ptr_vector_at(owner.ptr(), 0).is_null());
        }
    }

    #[test]
    fn at_matches_the_reference() {
        unsafe {
            let mut elements = [0u8; 8];
            let mut slots: [*mut u8; 8] = [core::ptr::null_mut(); 8];
            for (slot, element) in slots.iter_mut().zip(elements.iter_mut()) {
                *slot = element;
            }
            for count in 1..=8usize {
                let begin = slots.as_mut_ptr() as *mut u8;
                let owner = AtOwner::over(begin, begin.add(count * ELEMENT_SIZE as usize));
                for index in 0..(count as u32 + 2) {
                    assert_eq!(
                        ptr_vector_at(owner.ptr(), index),
                        at_reference(owner.vector(), index),
                        "count {count} index {index}"
                    );
                }
            }
            let _ = &mut slots;
        }
    }

    /// The quirk both checks conspire to produce: an inverted vector's
    /// negative size is `!= 0` (signed test) and larger than any index
    /// (unsigned test), so `begin[index]` is loaded regardless.
    #[test]
    fn an_inverted_vector_passes_both_checks() {
        unsafe {
            let mut elements = [0xaau8, 0xbb];
            let mut slots: [*mut u8; 2] = [core::ptr::null_mut(); 2];
            for (slot, element) in slots.iter_mut().zip(elements.iter_mut()) {
                *slot = element;
            }
            let begin = slots.as_mut_ptr() as *mut u8;
            let owner = AtOwner::over(begin, begin.sub(2 * ELEMENT_SIZE as usize));
            let owner_ptr = owner.ptr();
            assert_eq!(ptr_vector_at(owner_ptr, 0), slots[0]);
            assert_eq!(ptr_vector_at(owner_ptr, 1), slots[1]);
            assert_eq!(ptr_vector_at(owner_ptr, 0), at_reference(owner.vector(), 0));
            assert_eq!(ptr_vector_at(owner_ptr, 1), at_reference(owner.vector(), 1));
            let _ = &mut slots;
        }
    }
}
