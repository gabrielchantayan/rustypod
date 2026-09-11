//! Fixed settings-item accessor.
//!
//! Port:
//! - [`settings_item_get`] — original: `FUN_081533ec` @ `0x081533ec`
//!   (**80 bytes: 72 bytes of instructions plus an 8-byte literal pool; 9
//!   direct `bl` call sites, all unconditional and zero predicated**).
//!
//! Raw ARM runs from `0x081533ec` through `pop {r4, pc}` at `0x08153430`.
//! The following words at `0x08153434` and `0x08153438` are its guard
//! (`0x089ca62c`) and record (`0x08a12700`) literals; the next independently
//! entered function starts at `0x0815343c`. Ghidra's 72-byte size therefore
//! describes only the instruction body.
//!
//! ## Algorithm
//!
//! Test bit 0 of the record's C++ guard. If clear and
//! [`cxa_guard_acquire`] accepts the full guard word, clear record byte +12,
//! set record word +8 to 100, and release the guard. Every path returns the
//! fixed record address. All nine direct callers use plain `bl`, so none
//! conditionally skips this accessor.
//!
//! ## Deliberate deviations
//!
//! Target builds use the retail fixed addresses. Host builds substitute
//! private static storage with the same word-aligned 16-byte layout, because
//! those firmware addresses are not mapped by the host process. A volatile
//! binding retains the otherwise no-op `cxa_guard_release` call boundary.

use core::ptr;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};

type CxaGuardRelease = unsafe extern "C" fn(*mut u32);

/// Volatile boundary preserves the retail `bl cxa_guard_release`, whose
/// no-op body LLVM would otherwise fold into this accessor.
static mut SETTINGS_ITEM_CXA_GUARD_RELEASE: CxaGuardRelease = cxa_guard_release;

const SETTINGS_ITEM_GUARD_ADDRESS: usize = 0x089c_a62c;
const SETTINGS_ITEM_ADDRESS: usize = 0x08a1_2700;
const SETTINGS_ITEM_VALUE_OFFSET: usize = 8;
const SETTINGS_ITEM_FLAG_OFFSET: usize = 12;

#[cfg(not(target_os = "none"))]
static mut SETTINGS_ITEM_GUARD: u32 = 0;

/// Four target words cover the initialized value at +8 and flag byte at +12.
#[cfg(not(target_os = "none"))]
static mut SETTINGS_ITEM: [u32; 4] = [0; 4];

#[inline(always)]
unsafe fn settings_item_cxa_guard_release() -> CxaGuardRelease {
    ptr::read_volatile(ptr::addr_of!(SETTINGS_ITEM_CXA_GUARD_RELEASE))
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn settings_item_state() -> (*mut u32, *mut u8) {
    (SETTINGS_ITEM_GUARD_ADDRESS as *mut u32, SETTINGS_ITEM_ADDRESS as *mut u8)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn settings_item_state() -> (*mut u32, *mut u8) {
    (
        ptr::addr_of_mut!(SETTINGS_ITEM_GUARD),
        ptr::addr_of_mut!(SETTINGS_ITEM) as *mut u8,
    )
}

/// `settings_item_get` — original: `FUN_081533ec` @ `0x081533ec` (80 bytes:
/// 72 instruction bytes and an 8-byte literal pool; 9 direct unconditional
/// `bl` call sites, binary-verified by decoding every ARM B/BL word).
///
/// Lazily initializes and returns the fixed settings record. A nonzero guard
/// with bit 0 clear takes the slow path, but `cxa_guard_acquire` rejects it,
/// so its record remains unchanged exactly as in the ARM sequence.
///
/// # Safety
///
/// On target, the fixed retailOS guard and 16-byte record must be writable.
/// Calls must be serialized with other access to the record while it is being
/// initialized.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.settings_item_get")]
pub unsafe extern "C" fn settings_item_get() -> *mut u8 {
    let (guard, item) = settings_item_state();
    if (ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        ptr::write_volatile(item.add(SETTINGS_ITEM_FLAG_OFFSET), 0);
        ptr::write_volatile(item.add(SETTINGS_ITEM_VALUE_OFFSET).cast::<u32>(), 100);
        settings_item_cxa_guard_release()(guard);
    }
    item
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
pub(crate) static SETTINGS_ITEM_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::MutexGuard;

    fn reset(guard_value: u32, words: [u32; 4]) -> MutexGuard<'static, ()> {
        let lock = SETTINGS_ITEM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            ptr::write_volatile(ptr::addr_of_mut!(SETTINGS_ITEM_GUARD), guard_value);
            ptr::write_volatile(ptr::addr_of_mut!(SETTINGS_ITEM), words);
        }
        lock
    }

    #[test]
    fn zero_guard_initializes_only_the_value_and_flag_fields() {
        let _lock = reset(0, [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444]);

        let item = unsafe { settings_item_get() };

        assert_eq!(item, ptr::addr_of_mut!(SETTINGS_ITEM) as *mut u8);
        assert_eq!(unsafe { ptr::read_volatile(ptr::addr_of!(SETTINGS_ITEM_GUARD)) }, 1);
        assert_eq!(unsafe { ptr::read_volatile(ptr::addr_of!(SETTINGS_ITEM)) }, [0x1111_1111, 0x2222_2222, 100, 0x4444_4400]);
    }

    #[test]
    fn initialized_guard_skips_all_record_writes() {
        let original = [1, 2, 3, 4];
        let _lock = reset(1, original);

        unsafe { settings_item_get() };

        assert_eq!(unsafe { ptr::read_volatile(ptr::addr_of!(SETTINGS_ITEM)) }, original);
    }

    #[test]
    fn bit_zero_clear_but_nonzero_guard_is_refused_without_writes() {
        let original = [5, 6, 7, 8];
        let _lock = reset(2, original);

        unsafe { settings_item_get() };

        assert_eq!(unsafe { ptr::read_volatile(ptr::addr_of!(SETTINGS_ITEM_GUARD)) }, 2);
        assert_eq!(unsafe { ptr::read_volatile(ptr::addr_of!(SETTINGS_ITEM)) }, original);
    }
}
