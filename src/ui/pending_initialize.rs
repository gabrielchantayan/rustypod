//! Guarded media decoder initialization.
//!
//! `ui_dispatch_pending_initialize` — `FUN_08005e14` @ 0x08005e14.
//! True extent: 56 bytes (52 instruction bytes and the literal at 0x08005e48),
//! ending at the next function, 0x08005e4c. Raw ARM decoding verifies two plain
//! BLs, zero predicated BLs; two plain inbound BLs, zero predicated inbound BLs.
//!
//! If the owner byte at +6 is zero, dispatch decoder vtable slot +8 through
//! the existing decoder_initialize port, call the opaque 0x080035d0 veneer
//! with 0x22008cb8, then set the byte to one. Always return zero, ignoring
//! both callee results. Nonzero flags cause no calls or stores.
//!
//! Deliberate deviations: repr(C) gives host fixtures native-width pointers
//! and shifts the flag accordingly; ARM retains the exact +6 field layout.
//! Volatile flag accesses preserve the ordering around external calls. The
//! existing veneer reaches real retail code on ARM, not a guessed replacement.

use crate::stdio::decoder_initialize::decoder_initialize;
use crate::runtime::opaque_tail_dispatch_veneer::tail_call_retail_080cc22c;

/// Decoder owner prefix; the two intervening bytes are unrelated state.
#[repr(C)]
pub struct DecoderInitializationSlot {
    pub decoder: *mut u8,
    pub reserved: [u8; 2],
    pub initialized: u8,
}

/// Initialize once, publishing the flag only after both lifecycle calls.
///
/// The slot and (on the clear path) its decoder/vtable must be valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_dispatch_pending_initialize(
    slot: *mut DecoderInitializationSlot,
) -> i32 {
    let initialized = core::ptr::addr_of_mut!((*slot).initialized);
    if initialized.read_volatile() == 0 {
        decoder_initialize(core::ptr::addr_of_mut!((*slot).decoder));
        tail_call_retail_080cc22c(0x2200_8cb8 as *mut u8);
        initialized.write_volatile(1);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::opaque_tail_dispatch_veneer::{
        Retail080cc22c, RETAIL_080CC22C, RETAIL_080CC22C_TEST_LOCK,
    };

    #[repr(C)]
    struct Decoder {
        vtable: *const usize,
        owner: *mut DecoderInitializationSlot,
        phase: u32,
    }

    static mut ACTIVE_DECODER: *mut Decoder = core::ptr::null_mut();

    unsafe extern "C" fn initialize(object: *mut u8) -> usize {
        let decoder = &mut *object.cast::<Decoder>();
        assert_eq!(decoder.phase, 0);
        assert_eq!((*decoder.owner).initialized, 0);
        decoder.phase = 1;
        0xdead_beef
    }

    unsafe extern "C" fn notify(context: *mut u8) -> u32 {
        assert_eq!(context as usize, 0x2200_8cb8);
        let decoder = &mut *ACTIVE_DECODER;
        assert_eq!(decoder.phase, 1);
        assert_eq!((*decoder.owner).initialized, 0);
        decoder.phase = 2;
        0xffff_ffff
    }

    struct Restore(Retail080cc22c);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                RETAIL_080CC22C = self.0;
                ACTIVE_DECODER = core::ptr::null_mut();
            }
        }
    }

    #[test]
    fn publishes_after_both_calls_and_skips_every_nonzero_flag() {
        let _lock = RETAIL_080CC22C_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _restore = unsafe {
            let previous = RETAIL_080CC22C;
            RETAIL_080CC22C = notify;
            Restore(previous)
        };
        let vtable = [0, 0, initialize as *const () as usize];
        let mut slot = DecoderInitializationSlot {
            decoder: core::ptr::null_mut(), reserved: [0xa5, 0x5a], initialized: 0,
        };
        let mut decoder = Decoder { vtable: vtable.as_ptr(), owner: &mut slot, phase: 0 };
        slot.decoder = (&mut decoder as *mut Decoder).cast();
        unsafe { ACTIVE_DECODER = &mut decoder };
        assert_eq!(unsafe { ui_dispatch_pending_initialize(&mut slot) }, 0);
        assert_eq!(decoder.phase, 2);
        assert_eq!(slot.initialized, 1);
        assert_eq!(slot.reserved, [0xa5, 0x5a]);
        assert_eq!(slot.decoder, (&mut decoder as *mut Decoder).cast());
        // Invalid decoder proves that all nonzero byte values bypass dispatch.
        slot.decoder = core::ptr::null_mut();
        for flag in 1..=255 {
            slot.initialized = flag;
            assert_eq!(unsafe { ui_dispatch_pending_initialize(&mut slot) }, 0);
            assert_eq!(slot.initialized, flag);
            assert_eq!(slot.reserved, [0xa5, 0x5a]);
            assert_eq!(decoder.phase, 2);
        }
    }
}
