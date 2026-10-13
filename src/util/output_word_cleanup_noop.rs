//! `output_word_cleanup_noop` — `FUN_080284dc` @ **0x080284dc**.
//!
//! True extent: 36 bytes to independently called entry 0x08028500.
//! Reachable size: four bytes, raw A32 `0xe12fff1e` (`bx lr`); the eight
//! subsequent identical words are unreachable from this entry.
//! Whole-image aligned raw decoding finds two plain incoming BLs at
//! 0x082ea264 and 0x082ea444, zero predicated BLs, zero outgoing calls,
//! and no aligned DATA words equal to the entry address.
//!
//! Algorithm: return the saved output word unchanged without accessing memory.
//! Both callers in 0x082e9b54 load stack +0x158 into r0 during output cleanup,
//! then discard r0. The output's concrete type and ownership are unknown;
//! no destructor or virtual-dispatch identity is asserted.
//! Deliberate deviations: expose the preserved r0 as u32 rather than Ghidra's
//! void signature; omit unreachable words. Naked target assembly preserves
//! the original register-transparent body and a distinct exported BL target.

#[cfg(target_os = "none")]
#[unsafe(naked)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn output_word_cleanup_noop(_word: u32) -> u32 {
    core::arch::naked_asm!("bx lr");
}

#[cfg(not(target_os = "none"))]
#[inline(never)]
pub extern "C" fn output_word_cleanup_noop(word: u32) -> u32 {
    word
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_boundary_and_each_register_bit() {
        for word in [0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_fffe, u32::MAX] {
            assert_eq!(output_word_cleanup_noop(word), word);
        }
        for bit in 0..32 {
            let word = 1u32 << bit;
            assert_eq!(output_word_cleanup_noop(word), word);
            assert_eq!(output_word_cleanup_noop(!word), !word);
        }
    }
}
