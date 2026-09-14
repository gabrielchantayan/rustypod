//! Runtime-global callback dispatch.
//!
//! `global_slot_4_callback_dispatch` — original: `FUN_080b1a28` @
//! **0x080b1a28** (48 instruction bytes, `0x080b1a28..0x080b1a54`, followed
//! by its literal-pool word @ `0x080b1a58`; the next separately linked function
//! begins at `0x080b1a5c`). Decoding every immediate ARM `B`/`BL` word in
//! `osos.dec` finds six direct inbound calls, all unconditional `bl`:
//! `0x081f4994`, `0x08369adc`, `0x08369b34`, `0x08369b3c`, `0x08369b58`, and
//! `0x08369b94`. There are no predicated calls, direct tail-`b` entries, or
//! aligned raw data-word references to this entry.
//!
//! # Algorithm
//!
//! Volatile-loads the runtime global pointer at `0x089ca95c`. A NULL global
//! returns `0x11` without reading the callback. Otherwise, it volatile-loads
//! the pointed-to object's word at `+0x04`, calls it with the supplied event
//! code, discards its return register, and returns zero. The global object's
//! identity and callback's concrete role are unrecovered, so the names state
//! only this observed callback dispatch.
//!
//! # Deliberate deviation
//!
//! The firmware global and callback slot are 32-bit words. Host builds replace
//! the fixed global with a native-width pointer and model the callback slot as
//! a typed native function pointer so fixtures remain valid above 4 GiB.

use core::ptr::{addr_of, read_volatile};

/// Runtime-global pointer loaded by the stock literal pool.
pub const GLOBAL_SLOT_4_CALLBACK_TARGET_ADDRESS: usize = 0x089c_a95c;

/// Callback ABI stored in the target object's word at `+0x04`.
pub type GlobalSlot4Callback = unsafe extern "C" fn(u32);

/// Prefix of the runtime target used by this dispatcher.
#[repr(C)]
pub struct GlobalSlot4CallbackTarget {
    /// +0x00: an unrecovered word not read by this wrapper.
    pub unresolved_00: usize,
    /// +0x04 on ARM: callback invoked with the event code.
    pub callback: GlobalSlot4Callback,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x04] = [0; core::mem::offset_of!(GlobalSlot4CallbackTarget, callback)];

/// Host representation of the runtime-global callback target.
#[cfg(not(target_os = "none"))]
pub static mut GLOBAL_SLOT_4_CALLBACK_TARGET: *mut GlobalSlot4CallbackTarget = core::ptr::null_mut();

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn global_slot_4_callback_target() -> *mut GlobalSlot4CallbackTarget {
    read_volatile(GLOBAL_SLOT_4_CALLBACK_TARGET_ADDRESS as *const *mut GlobalSlot4CallbackTarget)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn global_slot_4_callback_target() -> *mut GlobalSlot4CallbackTarget {
    read_volatile(addr_of!(GLOBAL_SLOT_4_CALLBACK_TARGET))
}

/// Invokes the callback at word `+0x04` of the runtime-global target.
///
/// Returns `0x11` when the global target has not been installed; otherwise
/// returns zero after forwarding `event_code` unchanged.
///
/// # Safety
///
/// On target, `0x089ca95c` must be NULL or point to an object with a readable,
/// callable callback word at `+0x04`. The callback's event-code ABI is not
/// validated, matching the retailOS body.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn global_slot_4_callback_dispatch(event_code: u32) -> u32 {
    let target = global_slot_4_callback_target();
    if target.is_null() {
        return 0x11;
    }

    let callback = read_volatile(addr_of!((*target).callback));
    callback(event_code);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut SEEN_EVENT_CODE: u32 = 0;

    unsafe extern "C" fn record_event_code(event_code: u32) {
        SEEN_EVENT_CODE = event_code;
    }

    struct TargetRestore(*mut GlobalSlot4CallbackTarget);

    impl Drop for TargetRestore {
        fn drop(&mut self) {
            unsafe { write_volatile(addr_of_mut!(GLOBAL_SLOT_4_CALLBACK_TARGET), self.0) };
        }
    }

    #[test]
    fn returns_not_initialized_without_calling_a_callback() {
        let _lock = TEST_LOCK.lock();
        let restore = unsafe {
            let prior = read_volatile(addr_of!(GLOBAL_SLOT_4_CALLBACK_TARGET));
            write_volatile(addr_of_mut!(GLOBAL_SLOT_4_CALLBACK_TARGET), core::ptr::null_mut());
            SEEN_EVENT_CODE = 0xfeed_face;
            TargetRestore(prior)
        };

        assert_eq!(unsafe { global_slot_4_callback_dispatch(3) }, 0x11);
        assert_eq!(unsafe { SEEN_EVENT_CODE }, 0xfeed_face);
        drop(restore);
    }

    #[test]
    fn forwards_each_event_code_and_discards_callback_return_state() {
        let _lock = TEST_LOCK.lock();
        let mut target = GlobalSlot4CallbackTarget {
            unresolved_00: 0,
            callback: record_event_code,
        };
        let target = addr_of_mut!(target);
        let restore = unsafe {
            let prior = read_volatile(addr_of!(GLOBAL_SLOT_4_CALLBACK_TARGET));
            write_volatile(addr_of_mut!(GLOBAL_SLOT_4_CALLBACK_TARGET), target);
            TargetRestore(prior)
        };

        for event_code in [0, 1, 3, 4, u32::MAX] {
            unsafe { SEEN_EVENT_CODE = 0 };
            assert_eq!(unsafe { global_slot_4_callback_dispatch(event_code) }, 0);
            assert_eq!(unsafe { SEEN_EVENT_CODE }, event_code);
        }
        drop(restore);
    }
}
