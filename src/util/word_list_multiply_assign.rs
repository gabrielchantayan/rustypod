//! `word_list_multiply_assign` — original: `FUN_082d9bf8` @ 0x082d9bf8
//! (60 bytes; three unconditional plain `bl` instructions, no predicated
//! `bl` — verified by decoding osos.dec words).
//!
//! Builds a ten-word stack-local [`WordList`], invokes the schoolbook product
//! core for `multiplicand` and `accumulator`, then copies that product back to
//! `accumulator`. The temporary's header is `{ count = 0, capacity = 10,
//! entries = temporary + 8 }`; its word storage is deliberately uninitialized
//! because the product core clears its active output range.
//!
//! Deliberate deviation: the unported product core at 0x082d9c34 is a
//! volatile operation-table seam. Device builds use its firmware address;
//! host tests install a reference core. The target's 8-byte `WordList` header
//! and the host's native-width pointer layout make calling the target
//! constructor directly inappropriate on host, so this port initializes the
//! equivalent three header fields directly.

use core::ptr::addr_of_mut;

use crate::util::word_list::{word_list_copy, WordList, WORD_LIST_INLINE_CAPACITY_10};

/// ABI of the schoolbook product core `FUN_082d9c34`.
pub type WordListMultiplyCore = unsafe extern "C" fn(
    multiplicand: *const WordList,
    multiplier: *const WordList,
    product: *mut WordList,
);

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
    panic!("word_list_multiply_assign requires multiply core 0x082d9c34")
}

#[cfg(target_os = "none")]
const DEFAULT_WORD_LIST_MULTIPLY_CORE: WordListMultiplyCore = firmware_word_list_multiply;
#[cfg(not(target_os = "none"))]
const DEFAULT_WORD_LIST_MULTIPLY_CORE: WordListMultiplyCore = missing_word_list_multiply;

/// Target default invokes the unported retail product core; host tests replace it.
pub static mut WORD_LIST_MULTIPLY_CORE: WordListMultiplyCore = DEFAULT_WORD_LIST_MULTIPLY_CORE;

/// word_list_multiply_assign — original: `FUN_082d9bf8` @ 0x082d9bf8 (60 bytes).
///
/// # Safety
/// `multiplicand` and `accumulator` must be valid word-list headers. The
/// accumulator's entries buffer must accept the product produced by the core.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_list_multiply_assign(
    multiplicand: *const WordList,
    accumulator: *mut WordList,
) {
    let mut temporary_entries = core::mem::MaybeUninit::<[u32; 10]>::uninit();
    let mut temporary = WordList {
        count: 0,
        capacity: WORD_LIST_INLINE_CAPACITY_10,
        entries: temporary_entries.as_mut_ptr().cast(),
    };
    let multiply = unsafe { addr_of_mut!(WORD_LIST_MULTIPLY_CORE).read_volatile() };

    unsafe {
        multiply(multiplicand, accumulator, &mut temporary);
        word_list_copy(&temporary, accumulator);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::addr_of_mut;
    use std::sync::Mutex;

    static CORE_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u8 = 0;

    unsafe extern "C" fn reference_multiply(
        multiplicand: *const WordList,
        multiplier: *const WordList,
        product: *mut WordList,
    ) {
        unsafe {
            assert_eq!((*product).count, 0);
            assert_eq!((*product).capacity, 10);
            assert_eq!((*product).entries as usize % core::mem::align_of::<u32>(), 0);
            let count = (*multiplicand).count.min((*multiplier).count);
            for index in 0..count as usize {
                (*product).entries.add(index).write(
                    (*multiplicand).entries.add(index).read().wrapping_mul(
                        (*multiplier).entries.add(index).read(),
                    ),
                );
            }
            (*product).count = count;
            CALLS += 1;
        }
    }

    struct RestoreCore(WordListMultiplyCore);

    impl Drop for RestoreCore {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(WORD_LIST_MULTIPLY_CORE).write_volatile(self.0) };
        }
    }

    #[test]
    fn replaces_accumulator_with_product_and_preserves_its_storage() {
        let _lock = CORE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let multiplicand_words = [3u32, 5, 99];
        let mut accumulator_words = [7u32, 11, 13, 17];
        let multiplicand = WordList { count: 2, capacity: 3, entries: multiplicand_words.as_ptr() as *mut u32 };
        let mut accumulator = WordList { count: 2, capacity: 4, entries: accumulator_words.as_mut_ptr() };
        let entries = accumulator.entries;
        let capacity = accumulator.capacity;
        let old = unsafe { addr_of_mut!(WORD_LIST_MULTIPLY_CORE).read_volatile() };
        let _restore = RestoreCore(old);
        unsafe {
            CALLS = 0;
            addr_of_mut!(WORD_LIST_MULTIPLY_CORE).write_volatile(reference_multiply);
            word_list_multiply_assign(&multiplicand, &mut accumulator);
        }
        assert_eq!(unsafe { CALLS }, 1);
        assert_eq!(accumulator.entries, entries);
        assert_eq!(accumulator.capacity, capacity);
        assert_eq!(accumulator.count, 2);
        assert_eq!(accumulator_words, [21, 55, 13, 17]);
    }

    #[test]
    fn supports_empty_operands_without_touching_accumulator_words() {
        let _lock = CORE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let multiplicand_words = [1u32];
        let mut accumulator_words = [0xfeed_beefu32, 2];
        let multiplicand = WordList { count: 0, capacity: 1, entries: multiplicand_words.as_ptr() as *mut u32 };
        let mut accumulator = WordList { count: 0, capacity: 2, entries: accumulator_words.as_mut_ptr() };
        let old = unsafe { addr_of_mut!(WORD_LIST_MULTIPLY_CORE).read_volatile() };
        let _restore = RestoreCore(old);
        unsafe {
            addr_of_mut!(WORD_LIST_MULTIPLY_CORE).write_volatile(reference_multiply);
            word_list_multiply_assign(&multiplicand, &mut accumulator);
        }
        assert_eq!(accumulator.count, 0);
        assert_eq!(accumulator_words, [0xfeed_beef, 2]);
    }
}
