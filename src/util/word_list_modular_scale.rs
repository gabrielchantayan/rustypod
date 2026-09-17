//! `word_list_modular_scale_assign` — original: `FUN_082cf798` @
//! 0x082cf798 (36 bytes; 4 plain `bl` call sites, zero predicated, verified
//! from `osos.dec` ARM words rather than Ghidra xrefs).
//!
//! Multiplies every active little-endian limb of `value` by `scalar`, appends
//! a nonzero carry limb, then tail-dispatches the result to the mode-zero
//! modular reduction core. The next real function starts at `0x082cf7bc`.
//!
//! Deliberate deviation: `FUN_082d4c50` is reproduced inline rather than
//! introduced as a separate export. The unported reduction core
//! `FUN_082cdb04` is reached through a volatile operation-table seam; target
//! builds call its exact retail address and host tests install a model.

use core::ptr::addr_of_mut;

use crate::util::word_list::WordList;
use crate::util::word_list_modular_multiply::{ModularReductionContext, WordListReduceCore};

/// Unported reduction dependency of [`word_list_modular_scale_assign`].
#[derive(Clone, Copy)]
pub struct WordListModularScaleOps {
    pub reduce: WordListReduceCore,
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
    panic!("word_list_modular_scale_assign requires reduction core 0x082cdb04")
}

#[cfg(target_os = "none")]
const DEFAULT_WORD_LIST_MODULAR_SCALE_OPS: WordListModularScaleOps = WordListModularScaleOps {
    reduce: firmware_word_list_reduce,
};
#[cfg(not(target_os = "none"))]
const DEFAULT_WORD_LIST_MODULAR_SCALE_OPS: WordListModularScaleOps = WordListModularScaleOps {
    reduce: missing_word_list_reduce,
};

/// Target defaults invoke the still-unported retail reduction core. Host tests
/// replace this slot with a reference model.
pub static mut WORD_LIST_MODULAR_SCALE_OPS: WordListModularScaleOps =
    DEFAULT_WORD_LIST_MODULAR_SCALE_OPS;

/// Serializes host tests that replace this module's operation table.
#[cfg(test)]
pub(crate) mod test_sync {
    extern crate std;

    use std::sync::Mutex;

    pub static WORD_LIST_MODULAR_SCALE_OPS_TEST_LOCK: Mutex<()> = Mutex::new(());
}

/// word_list_modular_scale_assign — original: `FUN_082cf798` @ 0x082cf798
/// (36 bytes).
///
/// # Safety
/// `value` must be a valid writable word list with room for a carry limb when
/// its multiplication produces one. `modulus` must have the layout expected by
/// the retail reduction core.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_list_modular_scale_assign(
    scalar: u32,
    value: *mut WordList,
    modulus: *const ModularReductionContext,
) {
    let count = unsafe { (*value).count };
    let mut carry = 0u32;
    let mut index = 0u16;
    while index < count {
        let product = unsafe { (*value).entries.add(index as usize).read() as u64 * scalar as u64 + carry as u64 };
        unsafe { (*value).entries.add(index as usize).write(product as u32) };
        carry = (product >> 32) as u32;
        index += 1;
    }
    if carry != 0 {
        unsafe { (*value).entries.add(count as usize).write(carry) };
        unsafe { (*value).count = count + 1 };
    } else {
        unsafe { (*value).count = count };
    }
    let reduce = unsafe { addr_of_mut!(WORD_LIST_MODULAR_SCALE_OPS.reduce).read_volatile() };
    unsafe { reduce(value, modulus, 0) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use super::test_sync::WORD_LIST_MODULAR_SCALE_OPS_TEST_LOCK as OPS_LOCK;
    use core::ptr::addr_of_mut;

    static mut TRACE: [u8; 1] = [0; 1];
    static mut BEFORE_REDUCTION: [u32; 3] = [0; 3];
    static mut BEFORE_COUNT: u16 = 0;

    unsafe extern "C" fn reference_reduce(
        value: *mut WordList,
        _modulus: *const ModularReductionContext,
        mode: u32,
    ) {
        unsafe {
            assert_eq!(mode, 0);
            BEFORE_COUNT = (*value).count;
            let mut index = 0usize;
            while index < BEFORE_COUNT as usize {
                BEFORE_REDUCTION[index] = (*value).entries.add(index).read();
                index += 1;
            }
            (*value).count = 0;
            TRACE[0] = 1;
        }
    }

    struct RestoreOps(WordListModularScaleOps);
    impl Drop for RestoreOps {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(WORD_LIST_MODULAR_SCALE_OPS).write_volatile(self.0) };
        }
    }

    fn invoke(words: &mut [u32; 3], count: u16, scalar: u32) -> WordList {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut value = WordList { count, capacity: 3, entries: words.as_mut_ptr() };
        let original_entries = value.entries;
        let original_capacity = value.capacity;
        let old_ops = unsafe { addr_of_mut!(WORD_LIST_MODULAR_SCALE_OPS).read_volatile() };
        let _restore = RestoreOps(old_ops);
        unsafe {
            TRACE = [0; 1];
            BEFORE_REDUCTION = [0; 3];
            BEFORE_COUNT = 0;
            addr_of_mut!(WORD_LIST_MODULAR_SCALE_OPS).write_volatile(WordListModularScaleOps { reduce: reference_reduce });
            word_list_modular_scale_assign(scalar, &mut value, core::ptr::null());
        }
        assert_eq!(value.entries, original_entries);
        assert_eq!(value.capacity, original_capacity);
        value
    }

    #[test]
    fn scales_all_limbs_then_reduces() {
        let mut words = [0x8000_0001, 2, 0];
        let value = invoke(&mut words, 2, 3);
        unsafe {
            assert_eq!(TRACE, [1]);
            assert_eq!(BEFORE_COUNT, 2);
            assert_eq!(BEFORE_REDUCTION, [0x8000_0003, 7, 0]);
        }
        assert_eq!(value.count, 0);
    }

    #[test]
    fn appends_carry_before_mode_zero_reduction() {
        let mut words = [u32::MAX, 0, 0];
        let value = invoke(&mut words, 1, 2);
        unsafe {
            assert_eq!(TRACE, [1]);
            assert_eq!(BEFORE_COUNT, 2);
            assert_eq!(BEFORE_REDUCTION, [0xffff_fffe, 1, 0]);
        }
        assert_eq!(value.count, 0);
    }

    #[test]
    fn zero_scalar_preserves_active_count_until_reduction() {
        let mut words = [9, 4, 0];
        let value = invoke(&mut words, 2, 0);
        unsafe {
            assert_eq!(TRACE, [1]);
            assert_eq!(BEFORE_COUNT, 2);
            assert_eq!(BEFORE_REDUCTION, [0, 0, 0]);
        }
        assert_eq!(value.count, 0);
    }
}
