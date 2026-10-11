//! Fixed index limit — `thunk_FUN_080865e0` at **0x0805413c**.
//!
//! True extent: 4 bytes, [0x0805413c, 0x08054140); the next function
//! starts with `stmdb sp!, {r3,r4,r5,lr}`. Raw word 0xea00c927 branches
//! to 0x080865e0, whose 8-byte body is `mov r0,#23; bx lr`.
//! Two inbound plain BLs (0x081722a8, 0x081790f4), zero predicated BLs;
//! zero outbound BLs. Caller 0x081790e0 compares an index against the
//! low halfword of the result before dispatching event 0x6063.
//!
//! Deliberate deviation: inline the verified constant-return target rather
//! than retaining a firmware branch seam. The incoming context word is
//! ignored, including zero and invalid addresses, just as in stock ARM.

/// Returns the exclusive fixed index limit, independently of the context word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
#[link_section = ".text.ui_fixed_index_limit"]
pub extern "C" fn ui_fixed_index_limit(_context: u32) -> u32 {
    23
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_null_unaligned_and_extreme_context_words() {
        for context in [0, 1, 3, 0x08000000, 0x22000000, 0x80000000, u32::MAX] {
            // Raw MOV r0,#0x17 overwrites the complete incoming r0 word.
            assert_eq!(ui_fixed_index_limit(context), 0x17);
        }
    }
}
