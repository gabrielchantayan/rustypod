//! `application_global_slot_is_clear` — original: `FUN_08157d6c` @
//! 0x08157d6c (20 bytes: 16 bytes of code and its literal-pool word at
//! 0x08157d80; the separately linked next function begins at 0x08157d84).
//!
//! Decoding every ARM `B`/`BL` word in `osos.dec` finds exactly **six direct,
//! unconditional `bl` call sites** (0x0815843c, 0x081b8cf0, 0x081baea0,
//! 0x081f6c90, 0x0826ea20, and 0x08287d50); there are no predicated forms.
//!
//! Algorithm: volatile-load the runtime global word at 0x089d00e4 and return
//! one only when it is zero. The `rsbs r0,r0,#1; movcc r0,#0` sequence returns
//! zero for every nonzero word, not merely for the value one. The incoming r0
//! argument is ignored. The global's subsystem role is not recoverable from
//! the leaf or its callers, so the name states only the observed slot state.
//!
//! Deliberate deviation: host builds use a private zero-initialized word in
//! place of fixed firmware RAM.
use core::ptr;

/// Runtime global loaded through `FUN_08157d6c`'s literal-pool word.
#[cfg(target_os = "none")]
const APPLICATION_GLOBAL_SLOT_ADDRESS: *const u32 = 0x089d_00e4usize as *const u32;

/// Host backing for the runtime-global slot.
#[cfg(not(target_os = "none"))]
static mut HOST_APPLICATION_GLOBAL_SLOT: u32 = 0;

/// Serializes host tests that replace the global slot.
#[cfg(test)]
static APPLICATION_GLOBAL_SLOT_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[inline(always)]
unsafe fn application_global_slot_word() -> u32 {
    #[cfg(target_os = "none")]
    {
        unsafe { ptr::read_volatile(APPLICATION_GLOBAL_SLOT_ADDRESS) }
    }

    #[cfg(not(target_os = "none"))]
    {
        unsafe { ptr::read_volatile(ptr::addr_of!(HOST_APPLICATION_GLOBAL_SLOT)) }
    }
}

/// application_global_slot_is_clear — original: `FUN_08157d6c` @ 0x08157d6c
/// (20 bytes including literal pool; six unconditional direct `bl` call sites,
/// binary-scanned).
///
/// Returns one precisely when the global slot is zero, otherwise zero. The
/// original ignores its incoming first ABI argument.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn application_global_slot_is_clear() -> u32 {
    unsafe { u32::from(application_global_slot_word() == 0) }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn install_slot(value: u32) {
        unsafe {
            ptr::write_volatile(ptr::addr_of_mut!(HOST_APPLICATION_GLOBAL_SLOT), value);
        }
    }

    #[test]
    fn reports_clear_only_for_a_zero_slot() {
        let _guard = APPLICATION_GLOBAL_SLOT_TEST_LOCK.lock();

        for (slot, expected) in [(0, 1), (1, 0), (2, 0), (u32::MAX, 0)] {
            install_slot(slot);
            assert_eq!(unsafe { application_global_slot_is_clear() }, expected);
        }

        install_slot(0);
    }
}
