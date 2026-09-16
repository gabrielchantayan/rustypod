//! Single-word hash mixer — `FUN_08056a68` @ **0x08056a68**
//! (**168 bytes** total: 148-byte instruction body `0x08056a68..0x08056af8`
//! plus a five-word literal pool `0x08056afc..0x08056b10`; the separately
//! linked successor `FUN_08056b10` starts at `0x08056b10`. Ghidra's 148
//! covers instructions only). Raw decoding of every ARM B/BL immediate in
//! `osos.dec` found **five direct `bl` call sites**: four unconditional at
//! `0x081c1a0c`, `0x081c390c`, `0x081e5ef4`, `0x08206d98`, plus the
//! predicated `blne` at `0x081048f0`.
//!
//! # Algorithm
//!
//! The body is a compiler-obfuscated state machine: a jump table
//! (`addls pc,pc,r0,lsl #2`) keyed on a state word walking the literal
//! constants `0xc80f077e..0xc80f0782`. Tracing the states in order shows a
//! straight-line computation with exactly one `bl`:
//!
//! ```text
//! mixed = FUN_08343050(word);   // the only call
//! mixed = 0x8e92610f * mixed;   // mul r1, r8, r0
//! mixed = 0x05bc6def * mixed;   // mul r1, r11, r1
//! return mixed;                 // r4 -> r0
//! ```
//!
//! All multiplies are 32-bit `mul` (wrap mod 2^32). The two multipliers are
//! modular inverses: `0x8e92610f * 0x05bc6def == 1 (mod 2^32)`, so the
//! multiplies cancel exactly and the function is a bit-exact alias of
//! `FUN_08343050` — the multiply pair is pure obfuscation. Callers feed
//! pointer words (e.g. the object field at `+0x24` in `FUN_081c19d4`, which
//! zeroes the field afterwards), so this is a handle/handle-cookie mixer.
//!
//! # Deliberate deviations
//!
//! The callee `FUN_08343050` has no established Rust port or identity (it is
//! itself an obfuscated state machine calling `FUN_0835450c`), so it is a
//! volatile host seam; device builds call its verified retailOS entry. The
//! state-machine dance collapses to the straight-line code above — the
//! intermediate states have no observable effect. Because the multiplier
//! pair cancels, LLVM intentionally folds the device body to a tail call
//! (`bx`) to `0x08343050`; the fold is semantically exact, and match.py's
//! structural diff against the obfuscated original is expected.

use core::ptr;

/// First 32-bit multiplier applied to the callee result.
pub const HASH_WORD_FIRST_MULTIPLIER: u32 = 0x8e92_610f;
/// Second 32-bit multiplier applied to the callee result.
pub const HASH_WORD_SECOND_MULTIPLIER: u32 = 0x05bc_6def;

/// ABI of the unported base mixer at `FUN_08343050`.
pub type HashWordBase = unsafe extern "C" fn(u32) -> u32;

const HASH_WORD_BASE_ADDRESS: usize = 0x0834_3050;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_hash_word_base(_word: u32) -> u32 {
    panic!("hash_word requires installed host HASH_WORD_BASE")
}

/// Host execution model for the unported base mixer.
#[cfg(not(target_os = "none"))]
pub static mut HASH_WORD_BASE: HashWordBase = missing_hash_word_base;

#[inline(always)]
unsafe fn mix_base(word: u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let base: HashWordBase = unsafe { core::mem::transmute(HASH_WORD_BASE_ADDRESS) };
        unsafe { base(word) }
    }

    #[cfg(not(target_os = "none"))]
    {
        let base = unsafe { ptr::read_volatile(ptr::addr_of!(HASH_WORD_BASE)) };
        unsafe { base(word) }
    }
}

/// hash_word — original: `FUN_08056a68` @ 0x08056a68 (168 bytes incl. literal
/// pool; five direct `bl` call sites, four unconditional and one `blne`,
/// binary-verified from `osos.dec`).
///
/// Hashes `word` through the retail base mixer `FUN_08343050` and applies the
/// two 32-bit wrapping multipliers [`HASH_WORD_FIRST_MULTIPLIER`] and
/// [`HASH_WORD_SECOND_MULTIPLIER`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hash_word(word: u32) -> u32 {
    let mixed = unsafe { mix_base(word) };
    let mixed = HASH_WORD_FIRST_MULTIPLIER.wrapping_mul(mixed);
    HASH_WORD_SECOND_MULTIPLIER.wrapping_mul(mixed)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;
    use std::vec;
    use std::vec::Vec;

    static HASH_WORD_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Deterministic stand-in for the unported base mixer (splitmix32-style),
    /// also recording the argument it was called with.
    static BASE_CALLS: Mutex<Vec<u32>> = Mutex::new(Vec::new());

    unsafe extern "C" fn recording_base(word: u32) -> u32 {
        BASE_CALLS.lock().push(word);
        let mut x = word.wrapping_add(0x9e37_79b9);
        x ^= x >> 16;
        x = x.wrapping_mul(0x21f0_aaad);
        x ^= x >> 15;
        x
    }

    struct InstallBase;
    impl InstallBase {
        fn new() -> Self {
            unsafe { HASH_WORD_BASE = recording_base };
            *BASE_CALLS.lock() = Vec::new();
            InstallBase
        }
    }
    impl Drop for InstallBase {
        fn drop(&mut self) {
            unsafe { HASH_WORD_BASE = missing_hash_word_base };
        }
    }

    fn reference(word: u32) -> u32 {
        let mut x = word.wrapping_add(0x9e37_79b9);
        x ^= x >> 16;
        x = x.wrapping_mul(0x21f0_aaad);
        x ^= x >> 15;
        x = x.wrapping_mul(HASH_WORD_FIRST_MULTIPLIER);
        x.wrapping_mul(HASH_WORD_SECOND_MULTIPLIER)
    }

    #[test]
    fn calls_base_once_with_the_exact_input() {
        let _lock = HASH_WORD_TEST_LOCK.lock();
        let _base = InstallBase::new();
        unsafe { hash_word(0xdead_beef) };
        assert_eq!(*BASE_CALLS.lock(), vec![0xdead_beef]);
    }

    #[test]
    fn matches_reference_on_edge_words() {
        let _lock = HASH_WORD_TEST_LOCK.lock();
        let _base = InstallBase::new();
        for &word in &[
            0x0000_0000,
            0x0000_0001,
            0x7fff_ffff,
            0x8000_0000,
            0xffff_ffff,
            0xc80f_0781, // the state base literal itself
            0x05bc_6def,
            0x8e92_610f,
        ] {
            assert_eq!(unsafe { hash_word(word) }, reference(word), "word {word:#010x}");
        }
        // Carry/wrap-heavy sweep: every result must equal the two wrapping
        // multiplies applied to the base output, bit-pattern for bit-pattern.
        let mut state = 0x1234_5678u32;
        for _ in 0..10_000 {
            state = state.wrapping_mul(0x001d_9cd5).wrapping_add(0x9e37_79b9);
            assert_eq!(unsafe { hash_word(state) }, reference(state), "word {state:#010x}");
        }
    }

    #[test]
    fn multipliers_are_exact_modular_inverses() {
        // The two multiply stages cancel: the original function returns the
        // callee result unchanged. This is why LLVM folds the device body to
        // a plain tail call; any port that keeps only one stage must diverge.
        let combined = HASH_WORD_FIRST_MULTIPLIER.wrapping_mul(HASH_WORD_SECOND_MULTIPLIER);
        assert_eq!(combined, 1);
        let _lock = HASH_WORD_TEST_LOCK.lock();
        let _base = InstallBase::new();
        assert_eq!(unsafe { hash_word(0) }, reference(0));
    }
}
