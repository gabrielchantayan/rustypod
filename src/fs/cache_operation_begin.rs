//! Cache-operation accounting and list-head lookup.
//!
//! `cache_operation_begin` is retailOS `FUN_082e015c` at load address
//! `0x082e015c`. Its 28-byte instruction body is followed by its two 4-byte
//! resident-address literals, so the true image extent is
//! `0x082e015c..0x082e017f`; `sub r1,r0,#0x61` at `0x082e0180` begins the next
//! Whole-image ARM decoding finds two inbound direct plain `bl` calls
//! (`0x082dfe10` and `0x082e17b8`) and no predicated `bl` calls.
//!
//! # Algorithm
//!
//! Adds the numeric value of `contribution` to resident word `0x08a0a748`,
//! then returns the pointer stored in resident word `0x08a0a728`. The raw body
//! has no NULL guards and no outbound calls. Deliberate deviation: none.

use core::ptr;

use super::path_component_split::add_accumulator_contribution;

/// Resident pointer to the cache-operation list head.
const CACHE_OPERATION_LIST_HEAD_ADDRESS: *mut *mut u8 = 0x08a0_a728 as *mut *mut u8;

#[cfg(not(target_os = "none"))]
static mut HOST_CACHE_OPERATION_LIST_HEAD: *mut u8 = ptr::null_mut();

#[inline(always)]
unsafe fn cache_operation_list_head() -> *mut u8 {
    #[cfg(target_os = "none")]
    let list_head = CACHE_OPERATION_LIST_HEAD_ADDRESS;
    #[cfg(not(target_os = "none"))]
    let list_head = ptr::addr_of_mut!(HOST_CACHE_OPERATION_LIST_HEAD);

    ptr::read_volatile(list_head)
}

/// Begins a cache operation, accounts for `contribution`, and returns its list head.
///
/// Original: `FUN_082e015c` at `0x082e015c`, 28 instruction bytes plus an
/// 8-byte literal pool, with two verified inbound plain `bl` calls and no
/// predicated forms.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cache_operation_begin(contribution: *mut u8) -> *mut u8 {
    add_accumulator_contribution(contribution);
    cache_operation_list_head()
}

#[cfg(test)]
unsafe fn set_cache_operation_list_head(list_head: *mut u8) {
    ptr::write_volatile(ptr::addr_of_mut!(HOST_CACHE_OPERATION_LIST_HEAD), list_head);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::path_component_split::{
        path_component_accumulator, reset_path_component_accumulator,
        PATH_COMPONENT_ACCUMULATOR_TEST_LOCK,
    };

    #[test]
    fn accounts_numeric_pointer_contribution_and_returns_list_head() {
        let _guard = PATH_COMPONENT_ACCUMULATOR_TEST_LOCK.lock();
        let mut entry = [0u8; 20];

        unsafe {
            reset_path_component_accumulator();
            set_cache_operation_list_head(entry.as_mut_ptr());

            assert_eq!(cache_operation_begin(0x34usize as *mut u8), entry.as_mut_ptr());
            assert_eq!(path_component_accumulator(), 0xf347_b090);

            assert_eq!(cache_operation_begin(0usize as *mut u8), entry.as_mut_ptr());
            assert_eq!(path_component_accumulator(), 0xf347_b090);
            set_cache_operation_list_head(ptr::null_mut());
        }
    }

    #[test]
    fn wraps_accounting_and_preserves_null_list_head() {
        let _guard = PATH_COMPONENT_ACCUMULATOR_TEST_LOCK.lock();

        unsafe {
            reset_path_component_accumulator();
            set_cache_operation_list_head(ptr::null_mut());

            assert_eq!(cache_operation_begin(usize::MAX as *mut u8), ptr::null_mut());
            assert_eq!(path_component_accumulator(), 0xf347_b05b);
        }
    }
}
