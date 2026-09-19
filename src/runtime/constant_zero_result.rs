//! Constant-zero result — `FUN_0802ec98` @ 0x0802ec98 (8 bytes).
//!
//! Raw `osos.dec` words establish the 8-byte extent 0x0802ec98..0x0802eca0:
//! `mov r0, #0; mov pc, lr`. The next independent function begins at
//! 0x0802eca0 with `stmdb sp!, {r4, lr}`. Four plain direct `bl` instructions
//! target this leaf; no predicated direct `bl` instructions do. The leaf reads
//! neither ABI argument registers nor memory and always returns zero.
//!
//! Deliberate deviation: `mov pc, lr` preserves every register except r0,
//! while this ABI function guarantees only the observable zero r0 result.

/// Returns a zero-valued 32-bit ABI result without reading arguments or memory.
///
/// Original: `FUN_0802ec98` @ 0x0802ec98 (8 bytes).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn constant_zero_result() -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_zero_word() {
        assert_eq!(constant_zero_result(), 0);
    }

    #[test]
    fn repeated_calls_are_stateless() {
        assert_eq!([constant_zero_result(), constant_zero_result()], [0, 0]);
    }
}
