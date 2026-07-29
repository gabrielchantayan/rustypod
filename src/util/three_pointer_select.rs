//! three_pointer_select — original: `FUN_083d5eb4` @ 0x083d5eb4 (36
//! bytes; 14 `bl` call sites, all clustered in the jump table @
//! 0x080c7b40..0x080c7bdc, i.e. the body of one large switch).
//!
//! Reads three pointers from a 12-byte object (`+0`, `+4`, `+8`) and
//! returns the u32 stored at one of them, selected by unsigned pointer
//! comparisons:
//!
//! ```text
//! a = this[0]; b = this[1];
//! if (a < b) return *b;
//! c = this[2];
//! return (a <= c) ? *a : *c;
//! ```
//!
//! Note the odd first arm: `a < b` dereferences `b`, not `a`. All three
//! compares are the unsigned ARM conditions `cc`/`ls`/`hi`, so the
//! pointers are ordered as raw addresses. The shape suggests an
//! iterator clamp or a three-way begin/cur/end accessor, but the owning
//! container is not identified — the function is ported on its
//! observable behavior only and keeps the descriptive name.
//!
//! A byte-identical copy, `FUN_083d5ed8` @ 0x083d5ed8 (8 more `bl`
//! sites), hooks this same symbol — verified byte-equal against
//! osos.dec. The original:
//!
//! ```text
//! ldmia r0, {r1, r2}
//! cmp   r1, r2
//! ldrcc r0, [r2, #0x0]
//! bxcc  lr
//! ldr   r0, [r0, #0x8]
//! cmp   r1, r0
//! ldrls r0, [r1, #0x0]
//! ldrhi r0, [r0, #0x0]
//! bx    lr
//! ```

/// The 12-byte object the original reads: three word pointers.
/// `#[repr(C)]` keeps the field offsets (`+0`, `+4`, `+8`) exact on the
/// 32-bit target.
#[repr(C)]
pub struct ThreePointers {
    pub first: *const u32,
    pub second: *const u32,
    pub third: *const u32,
}

/// three_pointer_select — original: `FUN_083d5eb4` @ 0x083d5eb4 (36
/// bytes).
///
/// Selects and dereferences one of the object's three pointers by
/// unsigned address ordering: `first < second` yields `*second`;
/// otherwise `first <= third` yields `*first`, else `*third`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn three_pointer_select(triple: *const ThreePointers) -> u32 {
    let a = (*triple).first;
    let b = (*triple).second;
    if a < b {
        return *b;
    }
    let c = (*triple).third;
    if a <= c {
        *a
    } else {
        *c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a triple pointing into `cells` (a single array, so the
    /// address ordering of the indices is known: lower index = lower
    /// address) and run the original's algorithm as the reference.
    fn reference(a: *const u32, b: *const u32, c: *const u32) -> u32 {
        if a < b {
            unsafe { *b }
        } else if a <= c {
            unsafe { *a }
        } else {
            unsafe { *c }
        }
    }

    fn select(triple: &ThreePointers) -> u32 {
        unsafe { three_pointer_select(triple) }
    }

    #[test]
    fn first_less_than_second_dereferences_second() {
        let cells = [0x1111_1111u32, 0x2222_2222, 0x3333_3333];
        // a = &cells[0] < b = &cells[1]: the odd first arm returns *b.
        let triple = ThreePointers {
            first: &cells[0],
            second: &cells[1],
            third: &cells[2],
        };
        assert_eq!(select(&triple), cells[1]);
    }

    #[test]
    fn first_not_less_and_first_at_most_third_dereferences_first() {
        let cells = [0xaaaa_aaaau32, 0xbbbb_bbbb, 0xcccc_cccc];
        // a = &cells[1] >= b = &cells[0], a <= c = &cells[2]: *a.
        let triple = ThreePointers {
            first: &cells[1],
            second: &cells[0],
            third: &cells[2],
        };
        assert_eq!(select(&triple), cells[1]);
    }

    #[test]
    fn first_not_less_and_first_above_third_dereferences_third() {
        let cells = [0xdead_beefu32, 0x0bad_f00d, 0xcafe_babe];
        // a = &cells[2] >= b = &cells[0], a > c = &cells[1]: *c.
        let triple = ThreePointers {
            first: &cells[2],
            second: &cells[0],
            third: &cells[1],
        };
        assert_eq!(select(&triple), cells[1]);
    }

    #[test]
    fn equal_first_second_falls_through_to_the_second_compare() {
        let cells = [0x1234_5678u32, 0x9abc_def0];
        // a == b is NOT a < b: falls through; a <= c = &cells[1] → *a.
        let triple = ThreePointers {
            first: &cells[0],
            second: &cells[0],
            third: &cells[1],
        };
        assert_eq!(select(&triple), cells[0]);
    }

    #[test]
    fn first_equal_to_third_takes_the_first_deref() {
        let cells = [0x5555_5555u32, 0x6666_6666];
        // a = &cells[1] >= b = &cells[0], a == c: `ls` is true → *a.
        let triple = ThreePointers {
            first: &cells[1],
            second: &cells[0],
            third: &cells[1],
        };
        assert_eq!(select(&triple), cells[1]);
    }

    #[test]
    fn the_return_value_is_a_dereference_not_the_pointer() {
        let cells = [0u32, 0xffff_ffff, 0x8000_0000];
        let triple = ThreePointers {
            first: &cells[0],
            second: &cells[1],
            third: &cells[2],
        };
        assert_eq!(select(&triple), 0xffff_ffff);
    }

    #[test]
    fn exhaustive_index_permutation_parity() {
        // Every choice of distinct (a, b, c) indices plus the equality
        // corners, checked against the reference algorithm.
        let cells = [0x1000_0001u32, 0x2000_0002, 0x3000_0003];
        for ia in 0..3 {
            for ib in 0..3 {
                for ic in 0..3 {
                    let (a, b, c) = (&cells[ia] as *const u32, &cells[ib], &cells[ic]);
                    let triple = ThreePointers { first: a, second: b, third: c };
                    assert_eq!(select(&triple), reference(a, b, c), "({ia}, {ib}, {ic})");
                }
            }
        }
    }
}
