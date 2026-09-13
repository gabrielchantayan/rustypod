//! `storage_device_get` — original: `FUN_081f1b2c` @ **0x081f1b2c**.
//!
//! Raw ARM has 26 instruction words through `0x081f1b90`, followed by two
//! literal-pool words at `0x081f1b94` and `0x081f1b98`; the separately linked
//! next function starts at `0x081f1b9c`. The true extent is therefore **112
//! bytes**, rather than Ghidra's 104 instruction bytes.
//!
//! Decoding every aligned ARM `B`/`BL` immediate in `osos.dec` finds exactly
//! **six** inbound direct calls, all unconditional `bl`: `0x08064a68`,
//! `0x08064b80`, `0x08076400`, `0x080c685c`, `0x082bcaa0`, and `0x08393044`.
//! There are no predicated `bl` forms or direct tail branches. One data-table
//! word at `0x0899bd48` also holds this entry address; the table's type is not
//! verified, so this port makes no further dispatch claim.
//!
//! # Algorithm
//!
//! First lazily allocate 12 bytes, initialize it as a `CondVar`, and cache it
//! in the global word at `0x089d03b0`. This happens even for an invalid index.
//! Indices 0 and 1 select the two cache words at `0x089d03b4`; a missing entry
//! allocates 32 bytes through `operator_new`, constructs the storage device
//! with `(allocation, index, condvar)`, caches the constructor's result, and
//! returns it. Every allocation result is used without a NULL guard, exactly
//! like the retail body.
//!
//! # Deliberate deviation
//!
//! The storage-device constructor `FUN_0814e2dc` remains unported. Firmware
//! builds call it directly; host builds use the replaceable
//! [`STORAGE_DEVICE_CONSTRUCT`] boundary, whose default returns the supplied
//! allocation unchanged. Host pointer widths make `CondVar` larger than the
//! target's 12 bytes, so host fixtures must provide storage for the Rust
//! `CondVar` layout even though the retail allocation request remains 12.

use crate::heap::veneers::operator_new;
use crate::kernel::condvar::{condvar_init, CondVar};
#[cfg(not(target_os = "none"))]
use core::ptr;
use core::ptr::null_mut;

const CONDITION_BYTES: usize = 12;
const STORAGE_DEVICE_BYTES: usize = 32;
const STORAGE_DEVICE_COUNT: u32 = 2;

#[cfg(target_os = "none")]
const RETAIL_STORAGE_DEVICE_CONDITION_SLOT: usize = 0x089d_03b0;
#[cfg(target_os = "none")]
const RETAIL_STORAGE_DEVICE_CACHE: usize = 0x089d_03b4;

#[cfg(not(target_os = "none"))]
static mut STORAGE_DEVICE_CONDITION: *mut CondVar = null_mut();
#[cfg(not(target_os = "none"))]
static mut STORAGE_DEVICE_CACHE: [*mut u8; STORAGE_DEVICE_COUNT as usize] = [null_mut(); STORAGE_DEVICE_COUNT as usize];

/// ABI of the unported `FUN_0814e2dc` storage-device constructor.
pub type StorageDeviceConstruct = unsafe extern "C" fn(*mut u8, u32, *mut CondVar) -> *mut u8;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn storage_device_construct(
    allocation: *mut u8,
    index: u32,
    condition: *mut CondVar,
) -> *mut u8 {
    let construct: StorageDeviceConstruct = core::mem::transmute(0x0814_e2dcusize);
    construct(allocation, index, condition)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn default_storage_device_construct(
    allocation: *mut u8,
    _index: u32,
    _condition: *mut CondVar,
) -> *mut u8 {
    allocation
}

/// Host replacement for the unported storage-device constructor. Firmware
/// builds call `FUN_0814e2dc` directly.
#[cfg(not(target_os = "none"))]
pub static mut STORAGE_DEVICE_CONSTRUCT: StorageDeviceConstruct = default_storage_device_construct;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn storage_device_construct(
    allocation: *mut u8,
    index: u32,
    condition: *mut CondVar,
) -> *mut u8 {
    STORAGE_DEVICE_CONSTRUCT(allocation, index, condition)
}

#[inline(always)]
unsafe fn condition_slot() -> *mut *mut CondVar {
    #[cfg(target_os = "none")]
    {
        RETAIL_STORAGE_DEVICE_CONDITION_SLOT as *mut *mut CondVar
    }
    #[cfg(not(target_os = "none"))]
    {
        ptr::addr_of_mut!(STORAGE_DEVICE_CONDITION)
    }
}

#[inline(always)]
unsafe fn storage_device_slot(index: u32) -> *mut *mut u8 {
    #[cfg(target_os = "none")]
    {
        (RETAIL_STORAGE_DEVICE_CACHE as *mut *mut u8).add(index as usize)
    }
    #[cfg(not(target_os = "none"))]
    {
        ptr::addr_of_mut!(STORAGE_DEVICE_CACHE).cast::<*mut u8>().add(index as usize)
    }
}

/// Returns the cached storage device for `index` (0 or 1), constructing it on
/// first use. Other indices return NULL, after the singleton condition
/// variable's lazy initialization has run.
///
/// Original: `FUN_081f1b2c` @ `0x081f1b2c` (112 bytes including literal pool;
/// six unconditional direct `bl` callers).
///
/// # Safety
/// When either cache is cold, `operator_new` must return writable storage for
/// the requested target byte count; retailOS dereferences both allocation
/// results unconditionally. The active storage-device constructor must accept
/// that allocation and condition variable and return a cacheable device
/// pointer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.storage_device_get")]
pub unsafe extern "C" fn storage_device_get(index: u32) -> *mut u8 {
    let condition = condition_slot();
    if (*condition).is_null() {
        let allocated = operator_new(CONDITION_BYTES).cast::<CondVar>();
        condvar_init(allocated);
        condition.write(allocated);
    }

    if index >= STORAGE_DEVICE_COUNT {
        return null_mut();
    }

    let device = storage_device_slot(index);
    if (*device).is_null() {
        let allocated = operator_new(STORAGE_DEVICE_BYTES);
        let constructed = storage_device_construct(allocated, index, *condition);
        device.write(constructed);
    }
    device.read()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{alloc_log, mock_heap, set_alloc_ret};
    use crate::kernel::condvar::ListHead;
    use std::sync::{Mutex, MutexGuard};

    static STORAGE_DEVICE_LOCK: Mutex<()> = Mutex::new(());
    static mut CONSTRUCT_CALLS: usize = 0;
    static mut CONSTRUCT_ARGUMENTS: [(usize, u32, usize); STORAGE_DEVICE_COUNT as usize] = [(0, 0, 0); STORAGE_DEVICE_COUNT as usize];
    static mut CONSTRUCT_RESULTS: [*mut u8; STORAGE_DEVICE_COUNT as usize] = [null_mut(); STORAGE_DEVICE_COUNT as usize];

    unsafe extern "C" fn record_storage_device_construct(
        allocation: *mut u8,
        index: u32,
        condition: *mut CondVar,
    ) -> *mut u8 {
        CONSTRUCT_ARGUMENTS[CONSTRUCT_CALLS] = (allocation as usize, index, condition as usize);
        CONSTRUCT_CALLS += 1;
        CONSTRUCT_RESULTS[index as usize]
    }

    struct InstalledStorageDeviceTest {
        _storage_lock: MutexGuard<'static, ()>,
        _heap_lock: MutexGuard<'static, ()>,
    }

    impl Drop for InstalledStorageDeviceTest {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(STORAGE_DEVICE_CONDITION).write(null_mut());
                ptr::addr_of_mut!(STORAGE_DEVICE_CACHE).write([null_mut(); STORAGE_DEVICE_COUNT as usize]);
                STORAGE_DEVICE_CONSTRUCT = default_storage_device_construct;
            }
        }
    }

    fn install(allocation: *mut u8) -> InstalledStorageDeviceTest {
        let storage_lock = STORAGE_DEVICE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let heap_lock = mock_heap();
        unsafe {
            ptr::addr_of_mut!(STORAGE_DEVICE_CONDITION).write(null_mut());
            ptr::addr_of_mut!(STORAGE_DEVICE_CACHE).write([null_mut(); STORAGE_DEVICE_COUNT as usize]);
            CONSTRUCT_CALLS = 0;
            CONSTRUCT_ARGUMENTS = [(0, 0, 0); STORAGE_DEVICE_COUNT as usize];
            CONSTRUCT_RESULTS = [null_mut(); STORAGE_DEVICE_COUNT as usize];
            STORAGE_DEVICE_CONSTRUCT = record_storage_device_construct;
        }
        set_alloc_ret(allocation);
        InstalledStorageDeviceTest { _storage_lock: storage_lock, _heap_lock: heap_lock }
    }

    fn condvar_storage() -> CondVar {
        CondVar {
            lock_obj: null_mut(),
            waiters: ListHead { head: null_mut(), tail: null_mut() },
        }
    }

    #[test]
    fn invalid_index_initializes_only_the_condition_singleton() {
        let mut condition = condvar_storage();
        let _installed = install(ptr::addr_of_mut!(condition).cast());

        unsafe {
            assert!(storage_device_get(u32::MAX).is_null());
            assert_eq!(alloc_log(), (1, CONDITION_BYTES, 2));
            assert_eq!(STORAGE_DEVICE_CONDITION, ptr::addr_of_mut!(condition));
            assert_eq!(CONSTRUCT_CALLS, 0, "out-of-range index does not construct a device");
            assert_eq!(STORAGE_DEVICE_CACHE, [null_mut(); STORAGE_DEVICE_COUNT as usize]);
        }
    }

    #[test]
    fn each_valid_index_constructs_once_and_returns_its_cached_result() {
        static mut DEVICE_ZERO: [u8; STORAGE_DEVICE_BYTES] = [0; STORAGE_DEVICE_BYTES];
        static mut DEVICE_ONE: [u8; STORAGE_DEVICE_BYTES] = [0; STORAGE_DEVICE_BYTES];

        let mut condition = condvar_storage();
        let _installed = install(ptr::addr_of_mut!(condition).cast());
        unsafe {
            CONSTRUCT_RESULTS[0] = ptr::addr_of_mut!(DEVICE_ZERO).cast();
            CONSTRUCT_RESULTS[1] = ptr::addr_of_mut!(DEVICE_ONE).cast();

            assert_eq!(storage_device_get(0), ptr::addr_of_mut!(DEVICE_ZERO).cast());
            assert_eq!(alloc_log(), (2, STORAGE_DEVICE_BYTES, 2));
            assert_eq!(CONSTRUCT_CALLS, 1);
            assert_eq!(CONSTRUCT_ARGUMENTS[0], (
                ptr::addr_of_mut!(condition).cast::<u8>() as usize,
                0,
                ptr::addr_of_mut!(condition) as usize,
            ));

            assert_eq!(storage_device_get(0), ptr::addr_of_mut!(DEVICE_ZERO).cast());
            assert_eq!(CONSTRUCT_CALLS, 1, "cache hit suppresses a second allocation and constructor call");
            assert_eq!(alloc_log(), (2, STORAGE_DEVICE_BYTES, 2));

            assert_eq!(storage_device_get(1), ptr::addr_of_mut!(DEVICE_ONE).cast());
            assert_eq!(CONSTRUCT_CALLS, 2);
            assert_eq!(CONSTRUCT_ARGUMENTS[1].1, 1);
            assert_eq!(CONSTRUCT_ARGUMENTS[1].2, ptr::addr_of_mut!(condition) as usize);
            assert_eq!(alloc_log(), (3, STORAGE_DEVICE_BYTES, 2));
        }
    }
}
