//! `storage_device_operations_get` — original: `FUN_082bcb40` @
//! **0x082bcb40**. Raw ARM runs through `pop {r4,pc}` at `0x082bcb58`,
//! followed by its two literal-pool words at `0x082bcb5c` and `0x082bcb60`;
//! the separately entered next function starts at `0x082bcb64`. Its true
//! extent is therefore **36 bytes** (Ghidra reports only the 28 instruction
//! bytes).
//!
//! Decoding every ARM `B`/`BL` immediate in `osos.dec` finds exactly **nine**
//! inbound direct calls, all unconditional `bl`: `0x080c88b8`, `0x080d9938`,
//! `0x080dd2ec`, `0x080e3b18`, `0x082bd074`, `0x082bd0d8`, `0x082bd17c`,
//! `0x082bd238`, and `0x082bd33c`. There are no predicated callers or tail
//! branches.
//!
//! # Algorithm
//!
//! Read the lazy-initialization flag at `0x08a09f70`. When it is exactly zero,
//! invoke the storage-operation table initializer at `0x082bca98`; then return
//! the fixed four-word operation table at `0x08ae54f0`. The result never
//! depends on the initializer's return value.
//!
//! # Deliberate deviation
//!
//! Host builds model the two runtime-RAM objects with crate statics and replace
//! the unported initializer with a deterministic dispatch seam. Firmware builds
//! use the original RAM addresses and call the original initializer directly.

#[cfg(not(target_os = "none"))]
use core::ptr;

/// RetailOS's lazy-initialization flag, loaded through the literal at
/// `0x082bcb5c`.
#[cfg(target_os = "none")]
const RETAIL_STORAGE_DEVICE_OPERATIONS_GUARD: usize = 0x08a0_9f70;
/// RetailOS's four-word operation table, returned through the literal at
/// `0x082bcb60`.
#[cfg(target_os = "none")]
const RETAIL_STORAGE_DEVICE_OPERATIONS: usize = 0x08ae_54f0;
/// The direct `bleq` target reached when the initialization flag is zero.
#[cfg(target_os = "none")]
const RETAIL_STORAGE_DEVICE_OPERATIONS_INITIALIZE: usize = 0x082b_ca98;

/// Firmware-layout table returned by the getter. Its four entries are
/// initialized by the retail initializer; the getter observes no entry itself.
#[cfg(not(target_os = "none"))]
pub static mut STORAGE_DEVICE_OPERATIONS: [u32; 4] = [0; 4];

/// Host model of the firmware flag at `0x08a09f70`.
#[cfg(not(target_os = "none"))]
pub static mut STORAGE_DEVICE_OPERATIONS_GUARD: u32 = 0;

/// ABI of the unported storage-operation table initializer at `0x082bca98`.
#[cfg(not(target_os = "none"))]
pub type StorageDeviceOperationsInitialize = unsafe extern "C" fn();

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn default_storage_device_operations_initialize() {
    ptr::addr_of_mut!(STORAGE_DEVICE_OPERATIONS_GUARD).write_volatile(1);
}

/// Host replacement for the unported initializer. Firmware builds always call
/// the retail entry directly.
#[cfg(not(target_os = "none"))]
pub static mut STORAGE_DEVICE_OPERATIONS_INITIALIZE: StorageDeviceOperationsInitialize =
    default_storage_device_operations_initialize;

#[inline(always)]
unsafe fn storage_device_operations_guard() -> *mut u32 {
    #[cfg(target_os = "none")]
    {
        RETAIL_STORAGE_DEVICE_OPERATIONS_GUARD as *mut u32
    }
    #[cfg(not(target_os = "none"))]
    {
        ptr::addr_of_mut!(STORAGE_DEVICE_OPERATIONS_GUARD)
    }
}

#[inline(always)]
unsafe fn storage_device_operations() -> *mut u32 {
    #[cfg(target_os = "none")]
    {
        RETAIL_STORAGE_DEVICE_OPERATIONS as *mut u32
    }
    #[cfg(not(target_os = "none"))]
    {
        ptr::addr_of_mut!(STORAGE_DEVICE_OPERATIONS).cast::<u32>()
    }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn initialize_storage_device_operations() {
    let initialize: unsafe extern "C" fn() = core::mem::transmute(
        RETAIL_STORAGE_DEVICE_OPERATIONS_INITIALIZE,
    );
    initialize();
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn initialize_storage_device_operations() {
    let initialize = ptr::read_volatile(ptr::addr_of!(STORAGE_DEVICE_OPERATIONS_INITIALIZE));
    initialize();
}

/// `storage_device_operations_get` — original: `FUN_082bcb40` @
/// `0x082bcb40` (36 bytes including its two literal-pool words; nine direct,
/// unconditional `bl` call sites).
///
/// Initializes the fixed storage-device operation table only while its guard
/// word is zero, then returns the table address. Any nonzero guard suppresses
/// the call, including values without bit zero set.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn storage_device_operations_get() -> *mut u32 {
    let guard = storage_device_operations_guard();
    if guard.read_volatile() == 0 {
        initialize_storage_device_operations();
    }
    storage_device_operations()
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static STORAGE_DEVICE_OPERATIONS_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut INITIALIZER_CALLS: u32 = 0;

    unsafe extern "C" fn recording_initialize() {
        INITIALIZER_CALLS += 1;
        STORAGE_DEVICE_OPERATIONS[0] = 0x080c_8b68;
        STORAGE_DEVICE_OPERATIONS[1] = 0x080c_c700;
        STORAGE_DEVICE_OPERATIONS[2] = 0x080c_ea0c;
        STORAGE_DEVICE_OPERATIONS[3] = 0x080c_17e0;
        STORAGE_DEVICE_OPERATIONS_GUARD = 1;
    }

    unsafe fn reset() {
        STORAGE_DEVICE_OPERATIONS = [0; 4];
        STORAGE_DEVICE_OPERATIONS_GUARD = 0;
        STORAGE_DEVICE_OPERATIONS_INITIALIZE = recording_initialize;
        INITIALIZER_CALLS = 0;
    }

    unsafe fn restore() {
        STORAGE_DEVICE_OPERATIONS_INITIALIZE = default_storage_device_operations_initialize;
    }

    #[test]
    fn initializes_once_when_guard_is_zero_and_returns_fixed_table() {
        let _guard = STORAGE_DEVICE_OPERATIONS_TEST_LOCK.lock();
        unsafe {
            reset();
            let first = storage_device_operations_get();
            let second = storage_device_operations_get();

            assert_eq!(first, ptr::addr_of_mut!(STORAGE_DEVICE_OPERATIONS).cast::<u32>());
            assert_eq!(second, first);
            assert_eq!(INITIALIZER_CALLS, 1);
            assert_eq!(STORAGE_DEVICE_OPERATIONS_GUARD, 1);
            assert_eq!(STORAGE_DEVICE_OPERATIONS, [0x080c_8b68, 0x080c_c700, 0x080c_ea0c, 0x080c_17e0]);
            restore();
        }
    }

    #[test]
    fn any_nonzero_guard_skips_initializer() {
        let _guard = STORAGE_DEVICE_OPERATIONS_TEST_LOCK.lock();
        unsafe {
            reset();
            STORAGE_DEVICE_OPERATIONS_GUARD = 0x8000_0000;
            STORAGE_DEVICE_OPERATIONS = [0xfeed_beef; 4];

            let table = storage_device_operations_get();

            assert_eq!(table, ptr::addr_of_mut!(STORAGE_DEVICE_OPERATIONS).cast::<u32>());
            assert_eq!(INITIALIZER_CALLS, 0);
            assert_eq!(STORAGE_DEVICE_OPERATIONS, [0xfeed_beef; 4]);
            restore();
        }
    }
}
