//! `word_list_modular_add_assign` — original: `FUN_082cdac8` @
//! 0x082cdac8 (36 bytes; 11 `bl` call sites, all unconditional — verified
//! by decoding every ARM B/BL word in osos.dec, not Ghidra xrefs).
//!
//! Adds `addend` into `accumulator` through the in-place word-list addition
//! core, then tail-calls the reduction core with reduction mode zero. The
//! accumulator retains its own entry buffer and capacity; both cores mutate
//! only its contents and count.
//!
//! Deliberate deviation: the unported addition core `FUN_082daec8` and
//! reduction core `FUN_082cdb04` are reached through a volatile operation
//! table. Target defaults transmute their exact retail addresses; host tests
//! install reference cores to verify the otherwise opaque dependencies.

use core::ptr::addr_of_mut;

use crate::util::word_list::WordList;
use crate::util::word_list_modular_multiply::{ModularReductionContext, WordListReduceCore};

/// Exact ABI of the in-place word-list addition core `FUN_082daec8`.
pub type WordListAddAssignCore = unsafe extern "C" fn(
    addend: *const WordList,
    accumulator: *mut WordList,
);

/// Unported dependencies of [`word_list_modular_add_assign`].
#[derive(Clone, Copy)]
pub struct WordListModularAddOps {
    pub add_assign: WordListAddAssignCore,
    pub reduce: WordListReduceCore,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_word_list_add_assign(
    addend: *const WordList,
    accumulator: *mut WordList,
) {
    let add_assign: WordListAddAssignCore = unsafe { core::mem::transmute(0x082d_aec8usize) };
    unsafe { add_assign(addend, accumulator) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_word_list_add_assign(
    _addend: *const WordList,
    _accumulator: *mut WordList,
) {
    panic!("word_list_modular_add_assign requires addition core 0x082daec8")
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
    panic!("word_list_modular_add_assign requires reduction core 0x082cdb04")
}

#[cfg(target_os = "none")]
const DEFAULT_WORD_LIST_MODULAR_ADD_OPS: WordListModularAddOps = WordListModularAddOps {
    add_assign: firmware_word_list_add_assign,
    reduce: firmware_word_list_reduce,
};
#[cfg(not(target_os = "none"))]
const DEFAULT_WORD_LIST_MODULAR_ADD_OPS: WordListModularAddOps = WordListModularAddOps {
    add_assign: missing_word_list_add_assign,
    reduce: missing_word_list_reduce,
};

/// Target defaults invoke the two still-unported retail cores. Host tests
/// replace both slots with reference models.
pub static mut WORD_LIST_MODULAR_ADD_OPS: WordListModularAddOps =
    DEFAULT_WORD_LIST_MODULAR_ADD_OPS;

/// Serializes host tests that replace this module's operation table.
#[cfg(test)]
pub(crate) mod test_sync {
    extern crate std;

    use std::sync::Mutex;

    pub static WORD_LIST_MODULAR_ADD_OPS_TEST_LOCK: Mutex<()> = Mutex::new(());
}

/// word_list_modular_add_assign — original: `FUN_082cdac8` @ 0x082cdac8
/// (36 bytes).
///
/// # Safety
/// `addend` and `accumulator` must point to valid word lists. The accumulator
/// storage must be writable for the sum and reduced result. `modulus` must
/// have the layout required by the retail addition and reduction cores.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_list_modular_add_assign(
    addend: *const WordList,
    accumulator: *mut WordList,
    modulus: *const ModularReductionContext,
) {
    let add_assign = unsafe { addr_of_mut!(WORD_LIST_MODULAR_ADD_OPS.add_assign).read_volatile() };
    unsafe { add_assign(addend, accumulator) };
    let reduce = unsafe { addr_of_mut!(WORD_LIST_MODULAR_ADD_OPS.reduce).read_volatile() };
    unsafe { reduce(accumulator, modulus, 0) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use super::test_sync::WORD_LIST_MODULAR_ADD_OPS_TEST_LOCK as OPS_LOCK;
    use core::ptr::addr_of_mut;
    static mut TRACE: [u8; 2] = [0; 2];
    static mut TRACE_LEN: usize = 0;
    static mut VALUE_BEFORE_REDUCTION: u128 = 0;

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

    unsafe extern "C" fn reference_add_assign(addend: *const WordList, accumulator: *mut WordList) {
        unsafe {
            store_value(accumulator, list_value(addend) + list_value(accumulator));
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
            VALUE_BEFORE_REDUCTION = list_value(value);
            let modulus = (modulus as *const u32).read() as u128;
            store_value(value, list_value(value) % modulus);
            TRACE[TRACE_LEN] = 2;
            TRACE_LEN += 1;
        }
    }

    struct RestoreOps(WordListModularAddOps);

    impl Drop for RestoreOps {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(WORD_LIST_MODULAR_ADD_OPS).write_volatile(self.0) };
        }
    }

    fn invoke(
        addend_words: &mut [u32],
        addend_count: u16,
        accumulator_words: &mut [u32],
        accumulator_count: u16,
        modulus: u32,
    ) -> (WordList, [u8; 2], usize, u128) {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let addend = list(addend_words, addend_count);
        let mut accumulator = list(accumulator_words, accumulator_count);
        let original_entries = accumulator.entries;
        let original_capacity = accumulator.capacity;
        let mut modulus_word = modulus;
        let old_ops = unsafe { addr_of_mut!(WORD_LIST_MODULAR_ADD_OPS).read_volatile() };
        let _restore = RestoreOps(old_ops);
        unsafe {
            TRACE = [0; 2];
            TRACE_LEN = 0;
            VALUE_BEFORE_REDUCTION = 0;
            addr_of_mut!(WORD_LIST_MODULAR_ADD_OPS).write_volatile(WordListModularAddOps {
                add_assign: reference_add_assign,
                reduce: reference_reduce,
            });
            word_list_modular_add_assign(
                &addend,
                &mut accumulator,
                (&mut modulus_word as *mut u32).cast(),
            );
        }
        assert_eq!(accumulator.entries, original_entries, "addition keeps accumulator buffer");
        assert_eq!(accumulator.capacity, original_capacity, "addition keeps accumulator capacity");
        let trace = unsafe { TRACE };
        let trace_len = unsafe { TRACE_LEN };
        let value_before_reduction = unsafe { VALUE_BEFORE_REDUCTION };
        (accumulator, trace, trace_len, value_before_reduction)
    }

    #[test]
    fn adds_then_reduces_the_accumulator() {
        let mut addend_words = [48u32, 0];
        let mut accumulator_words = [79u32, 0];

        let (accumulator, trace, trace_len, value_before_reduction) =
            invoke(&mut addend_words, 1, &mut accumulator_words, 1, 97);

        assert_eq!(trace_len, 2);
        assert_eq!(trace, [1, 2], "addition precedes mode-zero reduction");
        assert_eq!(value_before_reduction, 127);
        assert_eq!(accumulator.count, 1);
        assert_eq!(accumulator_words, [30, 0]);
    }

    #[test]
    fn carries_into_a_high_limb_before_reduction() {
        let mut addend_words = [1u32, 0, 0];
        let mut accumulator_words = [u32::MAX, 0, 0];

        let (accumulator, trace, trace_len, value_before_reduction) =
            invoke(&mut addend_words, 1, &mut accumulator_words, 1, 65_521);

        assert_eq!(trace_len, 2);
        assert_eq!(trace, [1, 2]);
        assert_eq!(value_before_reduction, 1u128 << 32);
        assert_eq!(accumulator.count, 1);
        assert_eq!(accumulator_words[0], ((1u128 << 32) % 65_521) as u32);
        assert_eq!(&accumulator_words[1..], &[1, 0], "reduction leaves inactive high limbs untouched");
    }

    #[test]
    fn represents_a_zero_remainder_with_count_zero() {
        let mut addend_words = [10u32, 0];
        let mut accumulator_words = [87u32, 0];

        let (accumulator, trace, trace_len, value_before_reduction) =
            invoke(&mut addend_words, 1, &mut accumulator_words, 1, 97);

        assert_eq!(trace_len, 2);
        assert_eq!(trace, [1, 2]);
        assert_eq!(value_before_reduction, 97);
        assert_eq!(accumulator.count, 0);
        assert_eq!(accumulator_words, [97, 0], "zero-length result retains backing words");
    }
}
