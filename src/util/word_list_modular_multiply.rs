//! `word_list_modular_multiply_assign` — original: `FUN_082ceabc` @
//! 0x082ceabc (80 bytes; 27 `bl` call sites, all unconditional — verified
//! by decoding every ARM B/BL word in osos.dec, not Ghidra xrefs).
//!
//! Multiplies `multiplicand` by `accumulator` into a 10-word stack-local
//! [`WordList`], reduces that temporary through `modulus` with reduction mode
//! zero, then copies the reduced words back into `accumulator`. The temporary
//! has exactly the retail constructor's `{ count = 0, capacity = 10,
//! entries = this + 8 }` shape. Its limbs are deliberately left uninitialized:
//! `FUN_082d9c34` clears and fills the active product range before the
//! reduction sees it, just as it does after the retail stack allocation.
//!
//! Deliberate deviation: the 20-byte capacity-ten constructor
//! `FUN_082d81c8` is reproduced inline rather than becoming a second exported
//! port. The multiply core `FUN_082d9c34` and reducer `FUN_082cdb04` remain
//! unported, so [`WORD_LIST_MODULAR_MULTIPLY_OPS`] reaches their firmware
//! addresses on device and requires host-test replacements. `word_list_copy`
//! is already ported and is called directly.

use core::ptr::addr_of_mut;

use crate::util::word_list::{word_list_copy, WordList};

/// Opaque reduction configuration consumed by `FUN_082cdb04`.
///
/// The port forwards this object unchanged. Its field layout belongs to the
/// still-unported reduction core, so callers must supply the retail layout.
#[repr(C)]
pub struct ModularReductionContext {
    _opaque: [u8; 0],
}

/// Exact ABI of the schoolbook word-list product core `FUN_082d9c34`.
pub type WordListMultiplyCore = unsafe extern "C" fn(
    multiplicand: *const WordList,
    multiplier: *const WordList,
    product: *mut WordList,
);

/// Exact ABI of the in-place word-list reduction core `FUN_082cdb04`.
pub type WordListReduceCore = unsafe extern "C" fn(
    value: *mut WordList,
    modulus: *const ModularReductionContext,
    mode: u32,
);

/// Unported dependencies of [`word_list_modular_multiply_assign`].
#[derive(Clone, Copy)]
pub struct WordListModularMultiplyOps {
    pub multiply: WordListMultiplyCore,
    pub reduce: WordListReduceCore,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_word_list_multiply(
    multiplicand: *const WordList,
    multiplier: *const WordList,
    product: *mut WordList,
) {
    let multiply: WordListMultiplyCore = unsafe { core::mem::transmute(0x082d_9c34usize) };
    unsafe { multiply(multiplicand, multiplier, product) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_word_list_multiply(
    _multiplicand: *const WordList,
    _multiplier: *const WordList,
    _product: *mut WordList,
) {
    panic!("word_list_modular_multiply_assign requires multiply core 0x082d9c34")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_word_list_reduce(
    value: *mut WordList,
    modulus: *const ModularReductionContext,
    mode: u32,
) {
    let reduce: WordListReduceCore = unsafe { core::mem::transmute(0x082c_db04usize) };
    unsafe { reduce(value, modulus, mode) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_word_list_reduce(
    _value: *mut WordList,
    _modulus: *const ModularReductionContext,
    _mode: u32,
) {
    panic!("word_list_modular_multiply_assign requires reduction core 0x082cdb04")
}

#[cfg(target_os = "none")]
const DEFAULT_WORD_LIST_MODULAR_MULTIPLY_OPS: WordListModularMultiplyOps = WordListModularMultiplyOps {
    multiply: firmware_word_list_multiply,
    reduce: firmware_word_list_reduce,
};
#[cfg(not(target_os = "none"))]
const DEFAULT_WORD_LIST_MODULAR_MULTIPLY_OPS: WordListModularMultiplyOps = WordListModularMultiplyOps {
    multiply: missing_word_list_multiply,
    reduce: missing_word_list_reduce,
};

/// Target defaults invoke the two still-unported retail cores. Host tests
/// replace both slots with reference models.
pub static mut WORD_LIST_MODULAR_MULTIPLY_OPS: WordListModularMultiplyOps =
    DEFAULT_WORD_LIST_MODULAR_MULTIPLY_OPS;

/// word_list_modular_multiply_assign — original: `FUN_082ceabc` @ 0x082ceabc
/// (80 bytes).
///
/// # Safety
/// `multiplicand` and `accumulator` must point to valid word lists. The
/// accumulator's storage must be writable for the reduced result. `modulus`
/// must have the layout required by the retail multiplication and reduction
/// cores.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_list_modular_multiply_assign(
    multiplicand: *const WordList,
    accumulator: *mut WordList,
    modulus: *const ModularReductionContext,
) {
    let mut temporary_entries = core::mem::MaybeUninit::<[u32; 10]>::uninit();
    let mut temporary = WordList {
        count: 0,
        capacity: 10,
        entries: temporary_entries.as_mut_ptr().cast(),
    };
    let ops = unsafe { addr_of_mut!(WORD_LIST_MODULAR_MULTIPLY_OPS).read_volatile() };

    unsafe {
        (ops.multiply)(multiplicand, accumulator, &mut temporary);
        (ops.reduce)(&mut temporary, modulus, 0);
        word_list_copy(&temporary, accumulator);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::addr_of_mut;
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut TRACE: [u8; 2] = [0; 2];
    static mut TRACE_LEN: usize = 0;

    fn list(entries: &mut [u32], count: u16) -> WordList {
        WordList {
            count,
            capacity: entries.len() as u16,
            entries: entries.as_mut_ptr(),
        }
    }

    unsafe fn list_value(list: *const WordList) -> u64 {
        let mut value = 0u64;
        let mut index = (*list).count as usize;
        while index != 0 {
            index -= 1;
            value = (value << 32) | (*list).entries.add(index).read() as u64;
        }
        value
    }

    unsafe extern "C" fn reference_multiply(
        multiplicand: *const WordList,
        multiplier: *const WordList,
        product: *mut WordList,
    ) {
        unsafe {
            assert_eq!((*product).count, 0, "capacity-ten temporary starts empty");
            assert_eq!((*product).capacity, 10, "retail temporary capacity");
            let value = list_value(multiplicand) * list_value(multiplier);
            (*product).entries.write(value as u32);
            (*product).entries.add(1).write((value >> 32) as u32);
            (*product).count = if value >> 32 != 0 { 2 } else if value != 0 { 1 } else { 0 };
            TRACE[TRACE_LEN] = 1;
            TRACE_LEN += 1;
        }
    }

    unsafe extern "C" fn reference_reduce(
        value: *mut WordList,
        modulus: *const ModularReductionContext,
        mode: u32,
    ) {
        unsafe {
            assert_eq!(mode, 0, "retail caller always selects reduction mode zero");
            let modulus = (modulus as *const u32).read() as u64;
            let reduced = list_value(value) % modulus;
            (*value).entries.write(reduced as u32);
            (*value).entries.add(1).write((reduced >> 32) as u32);
            (*value).count = if reduced >> 32 != 0 { 2 } else if reduced != 0 { 1 } else { 0 };
            TRACE[TRACE_LEN] = 2;
            TRACE_LEN += 1;
        }
    }

    struct RestoreOps(WordListModularMultiplyOps);

    impl Drop for RestoreOps {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(WORD_LIST_MODULAR_MULTIPLY_OPS).write_volatile(self.0) };
        }
    }

    fn invoke(multiplicand_words: &mut [u32], multiplicand_count: u16, accumulator_words: &mut [u32], accumulator_count: u16, modulus: u32) -> (WordList, [u8; 2], usize) {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let multiplicand = list(multiplicand_words, multiplicand_count);
        let mut accumulator = list(accumulator_words, accumulator_count);
        let original_entries = accumulator.entries;
        let original_capacity = accumulator.capacity;
        let mut modulus_word = modulus;
        let old_ops = unsafe { addr_of_mut!(WORD_LIST_MODULAR_MULTIPLY_OPS).read_volatile() };
        let _restore = RestoreOps(old_ops);
        unsafe {
            TRACE = [0; 2];
            TRACE_LEN = 0;
            addr_of_mut!(WORD_LIST_MODULAR_MULTIPLY_OPS).write_volatile(WordListModularMultiplyOps {
                multiply: reference_multiply,
                reduce: reference_reduce,
            });
            word_list_modular_multiply_assign(
                &multiplicand,
                &mut accumulator,
                (&mut modulus_word as *mut u32).cast(),
            );
        }
        assert_eq!(accumulator.entries, original_entries, "copy keeps accumulator buffer");
        assert_eq!(accumulator.capacity, original_capacity, "copy keeps accumulator capacity");
        let trace = unsafe { TRACE };
        let trace_len = unsafe { TRACE_LEN };
        (accumulator, trace, trace_len)
    }

    #[test]
    fn multiplies_then_reduces_and_assigns_the_accumulator() {
        let mut multiplicand_words = [7u32, 0];
        let mut accumulator_words = [9u32, 0, 0, 0];

        let (accumulator, trace, trace_len) = invoke(
            &mut multiplicand_words,
            1,
            &mut accumulator_words,
            1,
            11,
        );

        assert_eq!(trace_len, 2);
        assert_eq!(trace, [1, 2], "multiply precedes mode-zero reduction");
        assert_eq!(accumulator.count, 1);
        assert_eq!(accumulator_words[0], 8, "7 * 9 mod 11");
        assert_eq!(&accumulator_words[1..], &[0; 3], "copy leaves words past reduced count untouched");
    }

    #[test]
    fn preserves_high_product_bits_until_reduction() {
        let mut multiplicand_words = [u32::MAX, 0];
        let mut accumulator_words = [2u32, 0, 0];

        let (accumulator, trace, trace_len) = invoke(
            &mut multiplicand_words,
            1,
            &mut accumulator_words,
            1,
            65_521,
        );

        assert_eq!(trace_len, 2);
        assert_eq!(trace, [1, 2]);
        assert_eq!(accumulator.count, 1);
        assert_eq!(accumulator_words[0], ((u32::MAX as u64 * 2) % 65_521) as u32);
        assert_eq!(&accumulator_words[1..], &[0; 2]);
    }
}
