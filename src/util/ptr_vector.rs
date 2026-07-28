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
//! where the checked accessor `FUN_08184f98` @ 0x08184f98 reads
//! `begin[i]` after bounds-checking `i` against `FUN_083d78c4(owner +
//! 0x14)` — the same size through the out-of-line path — and returns
//! NULL when out of range. That accessor is left unported: its bounds
//! helper is at 0x083d78c4, outside this sweep.
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
}
