//! `vector_halfword_clear` — original: `FUN_083e6cd0` @ **0x083e6cd0**.
//!
//! Raw A32 extent: 84 bytes, `0x083e6cd0..0x083e6d24`, ending in
//! `pop {r4,pc}` before the next function's independent push. Whole-image
//! aligned-word decoding finds one incoming plain BL at `0x0816f3a8`,
//! zero predicated incoming BLs, and zero outgoing plain or predicated BLs.
//!
//! Clears a two-byte-element vector without destroying elements or freeing
//! storage. The copy loop starts with identical source and limit pointers;
//! the subsequent halfword cursor walk has no side effects. For valid vector
//! bounds, subtracting the even byte span from end sets end to begin.
//!
//! Deliberate deviations: omit the unreachable copy and inert cursor walk.
//! Require valid, ordered halfword bounds rather than emulate malformed
//! bounds that can loop forever. Existing `VectorBounds` uses native host
//! pointers and retains the firmware's adjacent four-byte fields on ARM.

use crate::cxx::templates::VectorBounds;

/// Clears a halfword vector, retaining its allocation and element bytes.
///
/// Original: 0x083e6cd0, 84 bytes; one incoming BL, zero outgoing BLs.
///
/// # Safety
/// `vector` must be a writable vector head with equal bounds or ordered,
/// halfword-aligned bounds into the same allocation. No concurrent mutation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_halfword_clear(vector: *mut VectorBounds) {
    let begin = unsafe { (*vector).begin };
    if begin != unsafe { (*vector).end } {
        unsafe { (*vector).end = begin };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct VectorWithCapacity {
        bounds: VectorBounds,
        capacity_end: *mut u8,
    }

    #[test]
    fn null_empty_bounds_do_not_require_storage() {
        let mut bounds = VectorBounds {
            begin: core::ptr::null_mut(), end: core::ptr::null_mut(),
        };
        unsafe { vector_halfword_clear(&mut bounds) };
        assert!(bounds.begin.is_null());
        assert!(bounds.end.is_null());
    }

    #[test]
    fn clear_preserves_halfwords_capacity_and_is_idempotent() {
        let original = [0x1234u16, 0, 0xffff, 0x8000, 0xabcd];
        for len in 0..=original.len() {
            let mut storage = original;
            let begin = storage.as_mut_ptr().cast::<u8>();
            let capacity_end = unsafe { begin.add(core::mem::size_of_val(&storage)) };
            let mut vector = VectorWithCapacity {
                bounds: VectorBounds { begin, end: unsafe { begin.add(len * 2) } },
                capacity_end,
            };
            unsafe { vector_halfword_clear(&mut vector.bounds) };
            assert_eq!(vector.bounds.begin, begin);
            assert_eq!(vector.bounds.end, begin);
            assert_eq!(vector.capacity_end, capacity_end);
            assert_eq!(storage, original);
            unsafe { vector_halfword_clear(&mut vector.bounds) };
            assert_eq!(vector.bounds.end, begin);
            assert_eq!(vector.capacity_end, capacity_end);
            assert_eq!(storage, original);
        }
    }
}
