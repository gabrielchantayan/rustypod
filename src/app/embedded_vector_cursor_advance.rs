//! Advance an embedded four-byte-element vector cursor.
//!
//! Original: `FUN_0821afac` @ 0x0821afac, **64 bytes**, ending at
//! 0x0821afec (the next function's push). Raw ARM verifies two plain BLs
//! to 0x083d76e8 and no predicated BLs; two inbound plain BLs, none
//! predicated. Increment the unsigned cursor only when below the count,
//! then re-read the count: return 1 if still below it, otherwise reset
//! the cursor and return 0. Reversed spans retain the callee's arithmetic
//! shift result, interpreted as unsigned by this function's HI/LS tests.
//!
//! Deliberate deviations: none in behavior. Native pointer fields permit
//! host fixtures; target offsets remain vector +0x0c and cursor +0x18.
//! The opaque element/domain identity is not assumed. Ghidra's void
//! signature is corrected using the explicit movls/movhi return in r0.

use crate::cxx::templates::{vector_size_elem4_alias_76e8, VectorBounds};

#[repr(C)]
pub struct EmbeddedVectorCursor {
    pub prefix: [u32; 3],
    pub vector: VectorBounds,
    pub capacity_end: *mut u8,
    pub cursor: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [(); 0x0c] = [(); core::mem::offset_of!(EmbeddedVectorCursor, vector)];
#[cfg(target_pointer_width = "32")]
const _: [(); 0x18] = [(); core::mem::offset_of!(EmbeddedVectorCursor, cursor)];

/// Advance the cursor; return whether an entry remains before wrapping.
///
/// # Safety
/// `owner` must point to a readable and writable `EmbeddedVectorCursor`.
/// Vector bounds are inspected but elements are not dereferenced.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn embedded_vector_cursor_advance(owner: *mut EmbeddedVectorCursor) -> u32 {
    let vector = core::ptr::addr_of!((*owner).vector);
    let count = vector_size_elem4_alias_76e8(vector) as u32;
    if (*owner).cursor < count {
        (*owner).cursor = (*owner).cursor.wrapping_add(1);
    }
    let count = vector_size_elem4_alias_76e8(vector) as u32;
    if (*owner).cursor >= count {
        (*owner).cursor = 0;
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advances_wraps_and_rejects_out_of_range_cursors() {
        let mut storage = [0u32; 8];
        let begin = storage.as_mut_ptr().cast::<u8>();
        for count in 0..=8u32 {
            for initial in [0, 1, count.saturating_sub(1), count, count + 1, u32::MAX] {
                let mut owner = EmbeddedVectorCursor {
                    prefix: [0xa5a5a5a5; 3],
                    vector: VectorBounds { begin, end: unsafe { begin.add(count as usize * 4) } },
                    capacity_end: unsafe { begin.add(32) },
                    cursor: initial,
                };
                let next = if initial < count { initial + 1 } else { initial };
                let expected = if next < count { (1, next) } else { (0, 0) };
                let result = unsafe { embedded_vector_cursor_advance(&mut owner) };
                assert_eq!((result, owner.cursor), expected, "count={count}, initial={initial}");
                assert_eq!(owner.prefix, [0xa5a5a5a5; 3]);
                assert_eq!(owner.vector.begin, begin);
                assert_eq!(owner.vector.end, unsafe { begin.add(count as usize * 4) });
                assert_eq!(owner.capacity_end, unsafe { begin.add(32) });
            }
        }
    }

    #[test]
    fn reversed_unaligned_span_uses_unsigned_arithmetic_shift_count() {
        let mut storage = [0u8; 32];
        let end = storage.as_mut_ptr();
        let mut owner = EmbeddedVectorCursor {
            prefix: [0; 3],
            vector: VectorBounds { begin: unsafe { end.add(15) }, end },
            capacity_end: end,
            cursor: 0,
        };
        assert_eq!(unsafe { embedded_vector_cursor_advance(&mut owner) }, 1);
        assert_eq!(owner.cursor, 1);
        owner.cursor = 0xffff_fffa;
        assert_eq!(unsafe { embedded_vector_cursor_advance(&mut owner) }, 1);
        assert_eq!(owner.cursor, 0xffff_fffb);
        assert_eq!(unsafe { embedded_vector_cursor_advance(&mut owner) }, 0);
        assert_eq!(owner.cursor, 0);
    }
}
