//! `cxx_return_constant_0x52` — original: `FUN_08261da0` @ 0x08261da0
//! (8 bytes; four plain BL callers, zero predicated BL callers).
//!
//! Source: `ipod-decomp/decomp/c/025/08261da0_FUN_08261da0.c`.
//!
//! Leaf helper returning the literal status value `0x52`. Raw ARM is
//! `mov r0,#0x52; bx lr`; it neither reads its incoming argument registers nor
//! accesses memory. Deliberate deviation: the Rust ABI exposes no ignored
//! parameters, while target callers may retain values in r0-r3.

/// Returns the retailOS literal status value `0x52`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn cxx_return_constant_0x52() -> u32 {
    0x52
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_the_encoded_literal() {
        assert_eq!(cxx_return_constant_0x52(), 0x52);
    }
}
