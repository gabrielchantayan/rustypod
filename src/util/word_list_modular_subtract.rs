//! `word_list_modular_subtract_assign` — original: `FUN_082cf804` @
//! 0x082cf804 (76 bytes; 9 `bl` call sites, all unconditional — verified by
//! decoding every ARM B/BL word in osos.dec, not Ghidra xrefs).
//!
//! Subtracts `subtrahend` from `minuend` modulo `modulus`: initializes a
//! six-word inline temporary, copies `subtrahend` into it, negates that copy
//! through the unported modular-negation core, then adds it into `minuend`.
//! The result is written in place to `minuend`, whose entry buffer and
//! capacity are retained by the existing modular-add port.
//!
//! Deliberate deviation: the unported negation core `FUN_082ceb0c` is reached
//! through a volatile operation table. On a 64-bit host the temporary's
//! element storage follows the larger Rust `WordList` header, so its pointer
//! is repaired immediately after the faithfully invoked retail constructor;
//! target ARM layout needs no repair.

use core::mem::MaybeUninit;
use core::ptr::{addr_of_mut, null_mut};

use crate::util::word_list::{word_list_init, WordList, WORD_LIST_INLINE_CAPACITY};
use crate::util::word_list_modular_add::word_list_modular_add_assign;
use crate::util::word_list_modular_multiply::ModularReductionContext;

/// Exact ABI of the in-place modular-negation core `FUN_082ceb0c`.
pub type WordListModularNegateAssignCore = unsafe extern "C" fn(
    value: *mut WordList,
    modulus: *const ModularReductionContext,
);

/// Unported dependency of [`word_list_modular_subtract_assign`].
#[derive(Clone, Copy)]
pub struct WordListModularSubtractOps {
    pub negate_assign: WordListModularNegateAssignCore,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_word_list_negate_assign(
    value: *mut WordList,
    modulus: *const ModularReductionContext,
) {
    let negate_assign: WordListModularNegateAssignCore = unsafe { core::mem::transmute(0x082c_eb0cusize) };
    unsafe { negate_assign(value, modulus) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_word_list_negate_assign(
    _value: *mut WordList,
    _modulus: *const ModularReductionContext,
) {
    panic!("word_list_modular_subtract_assign requires negation core 0x082ceb0c")
}

#[cfg(target_os = "none")]
const DEFAULT_WORD_LIST_MODULAR_SUBTRACT_OPS: WordListModularSubtractOps = WordListModularSubtractOps {
    negate_assign: firmware_word_list_negate_assign,
};
#[cfg(not(target_os = "none"))]
const DEFAULT_WORD_LIST_MODULAR_SUBTRACT_OPS: WordListModularSubtractOps = WordListModularSubtractOps {
    negate_assign: missing_word_list_negate_assign,
};

/// Target defaults invoke the still-unported retail negation core. Host tests
/// replace this slot with a reference model.
pub static mut WORD_LIST_MODULAR_SUBTRACT_OPS: WordListModularSubtractOps =
    DEFAULT_WORD_LIST_MODULAR_SUBTRACT_OPS;

/// Target-layout temporary: on ARM, `entries` begins exactly eight bytes after
/// the [`WordList`] header, as required by `word_list_init`.
#[repr(C)]
struct InlineWordList {
    list: WordList,
    entries: MaybeUninit<[u32; WORD_LIST_INLINE_CAPACITY as usize]>,
}

/// word_list_modular_subtract_assign — original: `FUN_082cf804` @ 0x082cf804
/// (76 bytes).
///
/// # Safety
/// `subtrahend` and `minuend` must point to valid word lists. `minuend`'s
/// element storage must be writable for the reduced result. `modulus` must
/// have the layout required by the retail negation, addition, and reduction
/// cores.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_list_modular_subtract_assign(
    subtrahend: *const WordList,
    minuend: *mut WordList,
    modulus: *const ModularReductionContext,
) {
    let mut temporary = InlineWordList {
        list: WordList {
            count: 0,
            capacity: 0,
            entries: null_mut(),
        },
        entries: MaybeUninit::uninit(),
    };

    unsafe { word_list_init(addr_of_mut!(temporary.list)) };
    #[cfg(not(target_os = "none"))]
    {
        temporary.list.entries = temporary.entries.as_mut_ptr().cast();
    }

    unsafe {
        crate::util::word_list::word_list_copy(subtrahend, addr_of_mut!(temporary.list));
        let ops = addr_of_mut!(WORD_LIST_MODULAR_SUBTRACT_OPS).read_volatile();
        (ops.negate_assign)(addr_of_mut!(temporary.list), modulus);
        word_list_modular_add_assign(addr_of_mut!(temporary.list), minuend, modulus);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::addr_of_mut;
    use crate::util::word_list_modular_add::{
        test_sync::WORD_LIST_MODULAR_ADD_OPS_TEST_LOCK, WordListModularAddOps,
        WORD_LIST_MODULAR_ADD_OPS,
    };
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut TRACE: [u8; 3] = [0; 3];
    static mut TRACE_LEN: usize = 0;
    static mut NEGATED_INPUT: u128 = 0;
    static mut NEGATED_CAPACITY: u16 = 0;

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

    unsafe fn store_value(list: *mut WordList, mut value: u128) {
        let mut count = 0u16;
        while value != 0 {
            (*list).entries.add(count as usize).write(value as u32);
            value >>= 32;
            count += 1;
        }
        (*list).count = count;
    }

    unsafe fn record(event: u8) {
        TRACE[TRACE_LEN] = event;
        TRACE_LEN += 1;
    }

    unsafe extern "C" fn reference_negate_assign(
        value: *mut WordList,
        modulus: *const ModularReductionContext,
    ) {
        unsafe {
            NEGATED_INPUT = list_value(value);
            NEGATED_CAPACITY = (*value).capacity;
            let modulus = (modulus as *const u32).read() as u128;
            store_value(value, (modulus - (NEGATED_INPUT % modulus)) % modulus);
            record(1);
        }
    }

    unsafe extern "C" fn reference_add_assign(addend: *const WordList, accumulator: *mut WordList) {
        unsafe {
            store_value(accumulator, list_value(addend) + list_value(accumulator));
            record(2);
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
            record(3);
        }
    }

    struct RestoreSubtractOps(WordListModularSubtractOps);

    impl Drop for RestoreSubtractOps {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(WORD_LIST_MODULAR_SUBTRACT_OPS).write_volatile(self.0) };
        }
    }

    struct RestoreAddOps(WordListModularAddOps);

    impl Drop for RestoreAddOps {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(WORD_LIST_MODULAR_ADD_OPS).write_volatile(self.0) };
        }
    }

    fn invoke(
        subtrahend_words: &mut [u32],
        subtrahend_count: u16,
        minuend_words: &mut [u32],
        minuend_count: u16,
        modulus: u32,
    ) -> WordList {
        let _subtract_guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _add_guard = WORD_LIST_MODULAR_ADD_OPS_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let subtrahend = list(subtrahend_words, subtrahend_count);
        let mut minuend = list(minuend_words, minuend_count);
        let original_entries = minuend.entries;
        let original_capacity = minuend.capacity;
        let mut modulus_word = modulus;
        let old_subtract_ops = unsafe { addr_of_mut!(WORD_LIST_MODULAR_SUBTRACT_OPS).read_volatile() };
        let _restore_subtract = RestoreSubtractOps(old_subtract_ops);
        let old_add_ops = unsafe { addr_of_mut!(WORD_LIST_MODULAR_ADD_OPS).read_volatile() };
        let _restore_add = RestoreAddOps(old_add_ops);
        unsafe {
            TRACE = [0; 3];
            TRACE_LEN = 0;
            NEGATED_INPUT = 0;
            NEGATED_CAPACITY = 0;
            addr_of_mut!(WORD_LIST_MODULAR_SUBTRACT_OPS).write_volatile(WordListModularSubtractOps {
                negate_assign: reference_negate_assign,
            });
            addr_of_mut!(WORD_LIST_MODULAR_ADD_OPS).write_volatile(WordListModularAddOps {
                add_assign: reference_add_assign,
                reduce: reference_reduce,
            });
            word_list_modular_subtract_assign(
                &subtrahend,
                &mut minuend,
                (&mut modulus_word as *mut u32).cast(),
            );
        }
        assert_eq!(minuend.entries, original_entries, "subtraction keeps minuend buffer");
        assert_eq!(minuend.capacity, original_capacity, "subtraction keeps minuend capacity");
        minuend
    }

    #[test]
    fn subtracts_through_a_copied_capacity_six_temporary() {
        let mut subtrahend_words = [48u32, 0];
        let mut minuend_words = [30u32, 0];

        let minuend = invoke(&mut subtrahend_words, 1, &mut minuend_words, 1, 97);

        assert_eq!(unsafe { TRACE_LEN }, 3);
        assert_eq!(unsafe { TRACE }, [1, 2, 3], "copy, negate, add, then reduce");
        assert_eq!(unsafe { NEGATED_INPUT }, 48, "negation receives the copied subtrahend");
        assert_eq!(unsafe { NEGATED_CAPACITY }, 6, "retail constructor supplies six inline words");
        assert_eq!(subtrahend_words, [48, 0], "subtrahend is not mutated");
        assert_eq!(minuend.count, 1);
        assert_eq!(minuend_words, [79, 0]);
    }

    #[test]
    fn wraps_a_modular_borrow() {
        let mut subtrahend_words = [5u32, 0];
        let mut minuend_words = [3u32, 0];

        let minuend = invoke(&mut subtrahend_words, 1, &mut minuend_words, 1, 97);

        assert_eq!(unsafe { TRACE }, [1, 2, 3]);
        assert_eq!(minuend.count, 1);
        assert_eq!(minuend_words, [95, 0]);
    }

    #[test]
    fn retains_backing_word_for_a_zero_difference() {
        let mut subtrahend_words = [61u32, 0];
        let mut minuend_words = [61u32, 0];

        let minuend = invoke(&mut subtrahend_words, 1, &mut minuend_words, 1, 97);

        assert_eq!(unsafe { TRACE }, [1, 2, 3]);
        assert_eq!(minuend.count, 0);
        assert_eq!(minuend_words, [97, 0], "zero-length remainder keeps its backing word");
    }
}
