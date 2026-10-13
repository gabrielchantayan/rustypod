//! Disabled scanf inf/nan matcher — `FUN_083ed1c0` @ 0x083ed1c0.
//! True size: 4 bytes (0x083ed1c0..0x083ed1c4); raw word 0xe1a0f00e
//! is `mov pc, lr`. The next function begins with `tst r12, #0x100000`.
//! Verified incoming calls: one plain BL @ 0x08036454, zero predicated
//! BLs; zero outgoing calls. The caller dispatches i/I/n/N with r0 = -3
//! and compares the unchanged result against -3 before decimal fallback.
//! Algorithm: return the supplied no-match result without accessing input,
//! output, conversion state, or stack arguments. This is the complete retail
//! implementation, not a placeholder for an inf/nan parser.
//! Deliberate deviations: omit the unused r1-r3 and stack arguments. LLVM
//! folds this export into `no_op_u32` (also `preserve_word`/`tracker_trace`).
//! The shared 12-byte body pushes fp/lr, sets fp, then pops fp/pc; r0 is
//! unchanged. `match.py` cannot find the alias label, so codegen was compared
//! using `no_op_u32` after verifying the export's section, offset and size.

/// Returns the caller's literal-matching failure result unchanged.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn scanf_special_literal(no_match: i32) -> i32 {
    no_match
}

#[cfg(test)]
mod tests {
    use super::scanf_special_literal;

    #[test]
    fn preserves_failure_sentinel_and_all_register_bits() {
        for result in [-3, -2, -1, 0, 1, i32::MIN, i32::MAX, 0x5555aaaa] {
            assert_eq!(scanf_special_literal(result), result);
        }
    }
}
