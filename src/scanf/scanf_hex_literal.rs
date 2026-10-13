//! Disabled scanf hex-float matcher — `FUN_083ed1bc` @ 0x083ed1bc.
//! True size: 4 bytes (0x083ed1bc..0x083ed1c0); raw word 0xe1a0f00e
//! is `mov pc, lr`. The next real function is the inf/nan matcher.
//! Verified incoming calls: one plain BL @ 0x080364dc, zero predicated
//! BLs; zero outgoing calls. After exactly one leading zero, the float
//! engine dispatches x/X with r0 = -3 and checks the returned sentinel.
//! Algorithm: preserve r0 without accessing input, output, conversion
//! state, or stack arguments. Hex-float matching is disabled in retailOS;
//! this is the complete implementation, not a placeholder parser.
//! Deliberate deviations: omit unused r1-r3 and stack arguments. LLVM folds
//! this export into `no_op_u32` (same section, offset, and 12-byte size).
//! Its push fp/lr, mov fp/sp, pop fp/pc preserves r0. `match.py` cannot
//! locate the alias label; comparison through `no_op_u32` confirms that
//! frame setup/teardown is the only structural difference.

/// Returns the caller's hex-literal matching failure result unchanged.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn scanf_hex_literal(no_match: i32) -> i32 {
    no_match
}

#[cfg(test)]
mod tests {
    use super::scanf_hex_literal;

    #[test]
    fn preserves_failure_sentinel_and_register_bits() {
        for result in [-3, -2, -1, 0, 1, i32::MIN, i32::MAX, 0x5555aaaa] {
            assert_eq!(scanf_hex_literal(result), result);
        }
    }
}
