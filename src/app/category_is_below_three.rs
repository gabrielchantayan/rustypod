//! `category_is_below_three` — original: `FUN_08161258` @ 0x08161258
//! (24 bytes).
//!
//! The leaf predicate ignores its first ABI argument and recognizes only
//! category values 0, 1, and 2. It compares `r1` separately with each value,
//! returning one on equality and zero otherwise. Its two direct callers use
//! that category as an index into a context-owned table at `context + 0x04`;
//! no more specific category meaning is recoverable.
//!
//! Sources: `ipod-decomp/decomp/c/014/08161258_FUN_08161258.c` and the
//! `cmp r1,#0; cmpne r1,#1; cmpne r1,#2; moveq/movne; bx lr` sequence at
//! 0x08161258 in `ipod-decomp/decomp/osos.asm`.

/// category_is_below_three — original: `FUN_08161258` @ 0x08161258 (24
/// bytes).
///
/// Returns one when `category` is 0, 1, or 2, and zero otherwise. `context`
/// occupies `r0` in the retail ABI but is not read by the original routine.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn category_is_below_three(_context: u32, category: u32) -> u32 {
    (category < 3) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_exactly_the_first_three_categories() {
        for (category, expected) in [(0u32, 1), (1, 1), (2, 1), (3, 0), (u32::MAX, 0)] {
            assert_eq!(category_is_below_three(0, category), expected, "{category:#x}");
        }
    }

    #[test]
    fn first_abi_argument_is_ignored() {
        for context in [0u32, 0x1234_5678, u32::MAX] {
            assert_eq!(category_is_below_three(context, 2), 1, "{context:#x}");
            assert_eq!(category_is_below_three(context, 3), 0, "{context:#x}");
        }
    }
}
