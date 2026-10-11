//! `callback_table_status` — `FUN_080621e8` @ **0x080621e8**.
//!
//! True extent: 36 bytes, `0x080621e8..0x0806220c`; the next function
//! starts with `ldr r0,[pc]` at 0x0806220c. Raw words verify one outgoing
//! unconditional BL (0x080621ec to callback_table_get), zero predicated BLs,
//! and two incoming plain BLs (0x08062268, 0x0808b2e8), zero predicated.
//!
//! Algorithm: obtain the cached callback table, return zero if it or slot
//! +0x14 is null, otherwise dispatch that slot and return its status unchanged.
//! Both callers test the result against zero before choosing their next path.
//!
//! Deliberate deviations: host fixtures use native-width slots. Rust expresses
//! the conditional tail BX as a call/return; the callback's incidental r0
//! value (its own address) is preserved, without assigning it a semantic role.

use crate::app::callback_table::callback_table_get;

const STATUS_WORD: usize = 5;
type StatusCallback = unsafe extern "C" fn(usize) -> u32;

#[cfg(not(target_os = "none"))]
#[repr(C)]
struct HostCallbackTable {
    unresolved: [usize; STATUS_WORD],
    status: Option<StatusCallback>,
}

/// Returns zero for a missing status callback, otherwise its complete result.
///
/// # Safety
/// The getter must return null or a table readable through word +0x14. A
/// non-null status slot must be callable with the retailOS ABI and return u32.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn callback_table_status() -> u32 {
    let table = unsafe { callback_table_get() };
    if table.is_null() {
        return 0;
    }
    #[cfg(target_os = "none")]
    let callback = {
        let address = unsafe { core::ptr::read_volatile(table.cast::<u32>().add(STATUS_WORD)) };
        if address == 0 {
            return 0;
        }
        unsafe { core::mem::transmute::<usize, StatusCallback>(address as usize) }
    };
    #[cfg(not(target_os = "none"))]
    let callback = match unsafe { (*table.cast::<HostCallbackTable>()).status } {
        Some(callback) => callback,
        None => return 0,
    };
    unsafe { callback(callback as usize) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::callback_table::tests::{
        reset_callback_table_for_test, CALLBACK_TABLE_TEST_LOCK,
    };

    static mut READY: bool = false;

    unsafe extern "C" fn readiness(address: usize) -> u32 {
        assert_eq!(address, readiness as *const () as usize);
        if unsafe { READY } { 0x8000_0001 } else { 0 }
    }

    #[test]
    fn missing_table_and_missing_slot_return_zero() {
        let _lock = CALLBACK_TABLE_TEST_LOCK.lock();
        unsafe {
            reset_callback_table_for_test(core::ptr::null_mut());
            assert_eq!(callback_table_status(), 0);
            let mut table = HostCallbackTable { unresolved: [usize::MAX; STATUS_WORD], status: None };
            reset_callback_table_for_test((&mut table as *mut HostCallbackTable).cast());
            assert_eq!(callback_table_status(), 0);
            reset_callback_table_for_test(core::ptr::null_mut());
        }
    }

    #[test]
    fn cached_table_observes_readiness_transitions_without_booleanizing_status() {
        let _lock = CALLBACK_TABLE_TEST_LOCK.lock();
        let mut table = HostCallbackTable { unresolved: [0; STATUS_WORD], status: Some(readiness) };
        unsafe {
            reset_callback_table_for_test((&mut table as *mut HostCallbackTable).cast());
            READY = false;
            assert_eq!(callback_table_status(), 0);
            READY = true;
            assert_eq!(callback_table_status(), 0x8000_0001);
            READY = false;
            assert_eq!(callback_table_status(), 0);
            reset_callback_table_for_test(core::ptr::null_mut());
        }
    }
}
