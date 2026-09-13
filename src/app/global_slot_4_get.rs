//! Access to the opaque object held in a runtime global holder.
//!
//! `global_slot_4_get` — original: `FUN_081b21bc` @ **0x081b21bc**
//! (**12 code bytes**, followed by its 4-byte literal-pool word @ 0x081b21c8;
//! **16 bytes true extent**). Decoding every ARM B/BL immediate in
//! `work/firmware/osos.dec` found **7 direct `bl` call sites**, all
//! unconditional (0x0812551c, 0x08202b54, 0x08202b70, 0x0820a6c4,
//! 0x0820a764, 0x082284d4, and 0x0829f498); there are no predicated calls or
//! plain-`b` tail callers. The next separately linked function begins at
//! 0x081b21cc.
//!
//! Raw ARM loads the holder literal 0x089cfd64, then returns its `+0x04` word
//! unchanged. It performs no construction, NULL guard, or validation. The
//! holder's concrete object identity is not recovered, so this port names only
//! the verified global-slot operation. Deliberate deviation: the target reads
//! the live 32-bit runtime word, while host builds use a native-width static so
//! test pointers remain valid on 64-bit systems.

/// Runtime-global holder literal used by the retailOS body.
pub const GLOBAL_SLOT_4_HOLDER_ADDRESS: usize = 0x089c_fd64;

/// Host representation of the holder's `+0x04` object slot.
#[cfg(not(target_os = "none"))]
static mut HOST_GLOBAL_SLOT_4: *mut u8 = core::ptr::null_mut();

/// Returns the opaque object pointer held at `GLOBAL_SLOT_4_HOLDER_ADDRESS + 4`.
///
/// # Safety
///
/// Firmware callers require the runtime global word to be initialized before
/// dereferencing its result; this accessor deliberately preserves a NULL or
/// invalid word unchanged.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn global_slot_4_get() -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        return unsafe {
            ((GLOBAL_SLOT_4_HOLDER_ADDRESS + 4) as *const *mut u8).read_volatile()
        };
    }

    #[cfg(not(target_os = "none"))]
    unsafe {
        core::ptr::addr_of!(HOST_GLOBAL_SLOT_4).read_volatile()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static GLOBAL_SLOT_4_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct GlobalSlot4Reset;

    impl Drop for GlobalSlot4Reset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(HOST_GLOBAL_SLOT_4).write(core::ptr::null_mut());
            }
        }
    }

    fn install_empty_global_slot_4() -> MutexGuard<'static, ()> {
        let guard = GLOBAL_SLOT_4_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(HOST_GLOBAL_SLOT_4).write(core::ptr::null_mut());
        }
        guard
    }

    #[test]
    fn returns_null_before_global_slot_initialization() {
        let _guard = install_empty_global_slot_4();
        let _reset = GlobalSlot4Reset;

        assert!(unsafe { global_slot_4_get() }.is_null());
    }

    #[test]
    fn loads_current_global_slot_without_validation() {
        let _guard = install_empty_global_slot_4();
        let _reset = GlobalSlot4Reset;
        let mut first = [0u32; 1];
        let mut second = [0u32; 1];

        unsafe {
            core::ptr::addr_of_mut!(HOST_GLOBAL_SLOT_4).write(first.as_mut_ptr().cast());
            assert_eq!(global_slot_4_get(), first.as_mut_ptr().cast());

            core::ptr::addr_of_mut!(HOST_GLOBAL_SLOT_4).write(second.as_mut_ptr().cast());
            assert_eq!(global_slot_4_get(), second.as_mut_ptr().cast());
        }
    }
}
