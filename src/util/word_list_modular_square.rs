//! `word_list_modular_square_assign` — original: `FUN_082cf7bc` @
//! 0x082cf7bc (72 bytes; 12 `bl` call sites, all unconditional — verified
//! by decoding every ARM B/BL word in osos.dec, not Ghidra xrefs).
//!
//! Squares `accumulator` into a 10-word stack-local [`WordList`], reduces
//! that temporary through `modulus` with reduction mode zero, then copies the
//! reduced words back into `accumulator`. The temporary has exactly the retail
//! constructor's `{ count = 0, capacity = 10, entries = this + 8 }` shape.
//! Its limbs are deliberately left uninitialized: `FUN_082d24a4` fills the
//! active square range before the reduction sees it, just as it does after the
//! retail stack allocation.
//!
//! Deliberate deviation: the 20-byte capacity-ten constructor
//! `FUN_082d81c8` is reproduced inline rather than becoming a second exported
//! port. The square core `FUN_082d24a4` and reducer `FUN_082cdb04` remain
//! unported, so [`WORD_LIST_MODULAR_SQUARE_OPS`] reaches their firmware
//! addresses on device and requires host-test replacements. `word_list_copy`
//! is already ported and is called directly.

use core::ptr::addr_of_mut;

use crate::util::word_list::{word_list_copy, WordList};
use crate::util::word_list_modular_multiply::{ModularReductionContext, WordListReduceCore};

/// Exact ABI of the schoolbook word-list squaring core `FUN_082d24a4`.
pub type WordListSquareCore = unsafe extern "C" fn(
    value: *const WordList,
    square: *mut WordList,
);

/// Unported dependencies of [`word_list_modular_square_assign`].
#[derive(Clone, Copy)]
pub struct WordListModularSquareOps {
    pub square: WordListSquareCore,
    pub reduce: WordListReduceCore,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_word_list_square(
    value: *const WordList,
    square: *mut WordList,
) {
    let square_core: WordListSquareCore = unsafe { core::mem::transmute(0x082d_24a4usize) };
    unsafe { square_core(value, square) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_word_list_square(
    _value: *const WordList,
    _square: *mut WordList,
) {
    panic!("word_list_modular_square_assign requires square core 0x082d24a4")
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
    panic!("word_list_modular_square_assign requires reduction core 0x082cdb04")
}

#[cfg(target_os = "none")]
const DEFAULT_WORD_LIST_MODULAR_SQUARE_OPS: WordListModularSquareOps = WordListModularSquareOps {
    square: firmware_word_list_square,
    reduce: firmware_word_list_reduce,
};
#[cfg(not(target_os = "none"))]
const DEFAULT_WORD_LIST_MODULAR_SQUARE_OPS: WordListModularSquareOps = WordListModularSquareOps {
    square: missing_word_list_square,
    reduce: missing_word_list_reduce,
};

/// Target defaults invoke the two still-unported retail cores. Host tests
/// replace both slots with reference models.
pub static mut WORD_LIST_MODULAR_SQUARE_OPS: WordListModularSquareOps =
    DEFAULT_WORD_LIST_MODULAR_SQUARE_OPS;

/// word_list_modular_square_assign — original: `FUN_082cf7bc` @ 0x082cf7bc
/// (72 bytes).
///
/// # Safety
/// `accumulator` must point to a valid word list. Its storage must be writable
/// for the reduced result. `modulus` must have the layout required by the
/// retail squaring and reduction cores.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_list_modular_square_assign(
    accumulator: *mut WordList,
    modulus: *const ModularReductionContext,
) {
    let mut temporary_entries = core::mem::MaybeUninit::<[u32; 10]>::uninit();
    let mut temporary = WordList {
        count: 0,
        capacity: 10,
        entries: temporary_entries.as_mut_ptr().cast(),
    };
    let ops = unsafe { addr_of_mut!(WORD_LIST_MODULAR_SQUARE_OPS).read_volatile() };

    unsafe {
        (ops.square)(accumulator, &mut temporary);
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

    unsafe fn list_value(list: *const WordList) -> u128 {
        let mut value = 0u128;
        let mut index = (*list).count as usize;
        while index != 0 {
            index -= 1;
            value = (value << 32) | (*list).entries.add(index).read() as u128;
        }
        value
    }

    unsafe fn store_value(list: *mut WordList, value: u128) {
        let mut value = value;
        let mut count = 0u16;
        while value != 0 {
            (*list).entries.add(count as usize).write(value as u32);
            value >>= 32;
            count += 1;
        }
        (*list).count = count;
    }

    unsafe extern "C" fn reference_square(value: *const WordList, square: *mut WordList) {
        unsafe {
            assert_eq!((*square).count, 0, "capacity-ten temporary starts empty");
            assert_eq!((*square).capacity, 10, "retail temporary capacity");
            store_value(square, list_value(value) * list_value(value));
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
            let modulus = (modulus as *const u32).read() as u128;
            store_value(value, list_value(value) % modulus);
            TRACE[TRACE_LEN] = 2;
            TRACE_LEN += 1;
        }
    }

    struct RestoreOps(WordListModularSquareOps);

    impl Drop for RestoreOps {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(WORD_LIST_MODULAR_SQUARE_OPS).write_volatile(self.0) };
        }
    }

    fn invoke(accumulator_words: &mut [u32], accumulator_count: u16, modulus: u32) -> (WordList, [u8; 2], usize) {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut accumulator = list(accumulator_words, accumulator_count);
        let original_entries = accumulator.entries;
        let original_capacity = accumulator.capacity;
        let mut modulus_word = modulus;
        let old_ops = unsafe { addr_of_mut!(WORD_LIST_MODULAR_SQUARE_OPS).read_volatile() };
        let _restore = RestoreOps(old_ops);
        unsafe {
            TRACE = [0; 2];
            TRACE_LEN = 0;
            addr_of_mut!(WORD_LIST_MODULAR_SQUARE_OPS).write_volatile(WordListModularSquareOps {
                square: reference_square,
                reduce: reference_reduce,
            });
            word_list_modular_square_assign(
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
    fn squares_then_reduces_and_assigns_the_accumulator() {
        let mut accumulator_words = [9u32, 0, 0, 0];

        let (accumulator, trace, trace_len) = invoke(&mut accumulator_words, 1, 11);

        assert_eq!(trace_len, 2);
        assert_eq!(trace, [1, 2], "square precedes mode-zero reduction");
        assert_eq!(accumulator.count, 1);
        assert_eq!(accumulator_words[0], 4, "9 squared mod 11");
        assert_eq!(&accumulator_words[1..], &[0; 3], "copy leaves words past reduced count untouched");
    }

    #[test]
    fn preserves_high_square_bits_until_reduction() {
        let mut accumulator_words = [u32::MAX, 0, 0];

        let (accumulator, trace, trace_len) = invoke(&mut accumulator_words, 1, 65_521);

        assert_eq!(trace_len, 2);
        assert_eq!(trace, [1, 2]);
        assert_eq!(accumulator.count, 1);
        assert_eq!(accumulator_words[0], ((u32::MAX as u128 * u32::MAX as u128) % 65_521) as u32);
        assert_eq!(&accumulator_words[1..], &[0; 2]);
    }

    #[test]
    fn reduces_a_two_word_value_and_represents_zero_with_count_zero() {
        let mut accumulator_words = [u32::MAX, 1, 0, 0];

        let (accumulator, trace, trace_len) = invoke(&mut accumulator_words, 2, 1);

        assert_eq!(trace_len, 2);
        assert_eq!(trace, [1, 2]);
        assert_eq!(accumulator.count, 0);
        assert_eq!(&accumulator_words, &[u32::MAX, 1, 0, 0], "zero-length copy preserves destination words");
    }
}
