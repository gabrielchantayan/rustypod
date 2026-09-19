//! `callback_table_get` — original: `FUN_0806212c` @ **0x0806212c**.
//!
//! Raw ARM establishes a 36-byte instruction extent,
//! `0x0806212c..0x08062150`; the one-word literal pool at `0x08062150`
//! contains the cache address, and `0x08062154` starts the next function.
//! The accessor has one unconditional direct `bl`, to `FUN_080620a0` at
//! `0x080620a0`, and no predicated BL forms. It has four inbound plain BL
//! callers (`0x080620c0`, `0x08062104`, `0x080621bc`, and `0x080621ec`) and
//! no inbound predicated BL callers.
//!
//! Algorithm: return the callback-table pointer cached at `0x08a0ea7c`; when
//! that word is null, obtain the stock table pointer through the adjacent
//! accessor and cache it before returning it. Callers dispatch through table
//! words +4, +12, +16, and +20.
//!
//! Deliberate deviations: `FUN_080620a0` has no verified semantic identity in
//! `names.yaml`; target builds call its fixed address, while host builds expose
//! a replaceable source seam for behavioral tests.

const FIRMWARE_CALLBACK_TABLE_CACHE: usize = 0x08a0_ea7c;
const FIRMWARE_CALLBACK_TABLE_SOURCE: usize = 0x0806_20a0;

pub type CallbackTableSource = unsafe extern "C" fn() -> *mut u8;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe extern "C" fn firmware_callback_table_source() -> *mut u8 {
    let source: CallbackTableSource = unsafe { core::mem::transmute(FIRMWARE_CALLBACK_TABLE_SOURCE) };
    unsafe { source() }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_callback_table_source() -> *mut u8 {
    panic!("callback_table_get requires source 0x080620a0")
}

#[cfg(target_os = "none")]
pub static mut CALLBACK_TABLE_SOURCE: CallbackTableSource = firmware_callback_table_source;

#[cfg(not(target_os = "none"))]
pub static mut CALLBACK_TABLE_SOURCE: CallbackTableSource = missing_callback_table_source;

#[cfg(not(target_os = "none"))]
static mut HOST_CALLBACK_TABLE_CACHE: *mut u8 = core::ptr::null_mut();

#[inline(always)]
unsafe fn callback_table_source() -> CallbackTableSource {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CALLBACK_TABLE_SOURCE)) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn callback_table_cache() -> *mut *mut u8 {
    FIRMWARE_CALLBACK_TABLE_CACHE as *mut *mut u8
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn callback_table_cache() -> *mut *mut u8 {
    core::ptr::addr_of_mut!(HOST_CALLBACK_TABLE_CACHE)
}

/// Returns the lazily cached retailOS callback table.
///
/// # Safety
///
/// On target, the cache word at `0x08a0ea7c` and the adjacent stock accessor
/// must be valid. The returned pointer owns the callback-table layout.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn callback_table_get() -> *mut u8 {
    let cache = unsafe { callback_table_cache() };
    let value = unsafe { core::ptr::read_volatile(cache) };
    if !value.is_null() {
        return value;
    }
    let value = unsafe { callback_table_source()() };
    unsafe { core::ptr::write_volatile(cache, value) };
    value
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;

    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    pub(crate) static CALLBACK_TABLE_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static SOURCE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static mut SOURCE_VALUE: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_source() -> *mut u8 {
        SOURCE_CALLS.fetch_add(1, Ordering::SeqCst);
        unsafe { SOURCE_VALUE }
    }

    pub(crate) unsafe fn reset_callback_table_for_test(source_value: *mut u8) {
        unsafe {
            HOST_CALLBACK_TABLE_CACHE = core::ptr::null_mut();
            SOURCE_VALUE = source_value;
            CALLBACK_TABLE_SOURCE = recording_source;
        }
        SOURCE_CALLS.store(0, Ordering::SeqCst);
    }

    unsafe fn reset(source_value: *mut u8) {
        unsafe { reset_callback_table_for_test(source_value) };
    }

    #[test]
    fn caches_nonnull_source_result() {
        let _lock = CALLBACK_TABLE_TEST_LOCK.lock();
        let mut table = [0u8; 24];
        unsafe { reset(table.as_mut_ptr()) };

        assert_eq!(unsafe { callback_table_get() }, table.as_mut_ptr());
        assert_eq!(unsafe { callback_table_get() }, table.as_mut_ptr());
        assert_eq!(SOURCE_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn null_source_result_is_retried() {
        let _lock = CALLBACK_TABLE_TEST_LOCK.lock();
        unsafe { reset(core::ptr::null_mut()) };

        assert!(unsafe { callback_table_get() }.is_null());
        assert!(unsafe { callback_table_get() }.is_null());
        assert_eq!(SOURCE_CALLS.load(Ordering::SeqCst), 2);
    }
}
