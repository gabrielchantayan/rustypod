//! Clears a service object's pending gateway-request byte.
//!
//! Original: `FUN_0814ad9c` @ `0x0814ad9c`, 48 bytes. Raw ARM runs through
//! `0x0814adc8`; the next real body begins at `0x0814adcc`. It reads byte
//! `object + 0x50`, and, when nonzero, posts the already ported tag-2 gateway
//! request with payload `25` and timeout `250`, clears that byte, and returns
//! one. Decoding every ARM B/BL word in `osos.dec` found four call sites:
//! two predicated `blne` calls (`0x0814ac5c`, `0x0814af4c`) and two plain
//! `bl` calls (`0x0814b270`, `0x0814b610`); there are no tail branches.
//!
//! The byte's higher-level service meaning is not established, so the name
//! states only its verified pending-request role. Deliberate deviation: the
//! gateway helper's Rust signature takes `usize`; this port widens only at
//! that seam while retaining the target's byte offset and unconditional
//! success result.

use crate::kernel::gateway_request::gateway_request_timed;

const PENDING_REQUEST_OFFSET: usize = 0x50;
const REQUEST_PAYLOAD: usize = 25;
const REQUEST_TIMEOUT: usize = 250;

/// clear_pending_gateway_request — `FUN_0814ad9c` @ `0x0814ad9c` (48 bytes;
/// two predicated and two plain `bl` call sites).
///
/// Posts the fixed tag-2 gateway request when `object + 0x50` is nonzero,
/// clears that byte afterward, and always returns one.
///
/// # Safety
///
/// `object` must point to a writable object containing a byte at `+0x50`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn clear_pending_gateway_request(object: *mut u8) -> u32 {
    unsafe {
        let pending = object.add(PENDING_REQUEST_OFFSET);
        if pending.read() != 0 {
            gateway_request_timed(REQUEST_PAYLOAD, REQUEST_TIMEOUT);
            pending.write(0);
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::task_lock;
    use crate::kernel::task_lock::tests::OPS_LOCK;
    use crate::runtime::message_dispatch_veneer::tests::DISPATCH_OPS_LOCK;
    use crate::runtime::message_dispatch_veneer::{
        MessageDispatchVeneerOps, MESSAGE_DISPATCH_VENEER_OPS,
    };
    use core::ptr::{addr_of, addr_of_mut};

    static mut DISPATCH_COUNT: usize = 0;

    unsafe extern "C" fn mock_sem(_: usize) -> usize { 0 }
    unsafe extern "C" fn mock_dispatch(_: *mut u32) {
        unsafe { *addr_of_mut!(DISPATCH_COUNT) += 1; }
    }

    #[test]
    fn inactive_byte_skips_gateway_and_returns_one() {
        let mut object = [0u8; PENDING_REQUEST_OFFSET + 1];
        unsafe {
            assert_eq!(clear_pending_gateway_request(object.as_mut_ptr()), 1);
            assert_eq!(object[PENDING_REQUEST_OFFSET], 0);
        }
    }

    #[test]
    fn any_nonzero_byte_posts_once_then_clears() {
        let dispatch_lock = DISPATCH_OPS_LOCK.lock();
        let kernel_lock = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            *addr_of_mut!(DISPATCH_COUNT) = 0;
            let saved_kernel = core::ptr::read_volatile(addr_of!(task_lock::ROM_KERNEL));
            let mut mocked_kernel = saved_kernel;
            mocked_kernel.rom_sem_wait = mock_sem;
            mocked_kernel.rom_sem_signal = mock_sem;
            addr_of_mut!(task_lock::ROM_KERNEL).write(mocked_kernel);
            let saved_dispatch = MESSAGE_DISPATCH_VENEER_OPS;
            MESSAGE_DISPATCH_VENEER_OPS = MessageDispatchVeneerOps { dispatch: mock_dispatch };

            let mut object = [0u8; PENDING_REQUEST_OFFSET + 1];
            for value in [1, u8::MAX] {
                object[PENDING_REQUEST_OFFSET] = value;
                assert_eq!(clear_pending_gateway_request(object.as_mut_ptr()), 1);
                assert_eq!(object[PENDING_REQUEST_OFFSET], 0);
            }
            assert_eq!(*addr_of!(DISPATCH_COUNT), 2);

            MESSAGE_DISPATCH_VENEER_OPS = saved_dispatch;
            addr_of_mut!(task_lock::ROM_KERNEL).write(saved_kernel);
        }
        drop(kernel_lock);
        drop(dispatch_lock);
    }
}
