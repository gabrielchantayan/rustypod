//! RTXC timer-free gateway wrapper.
//!
//! The retailOS mirror at `0x08003e1c` reaches mask-ROM service `0x11` through
//! `FUN_08003660`.  The adjacent service-`0x10` wrapper at `0x08003b8c` is
//! `KS_alloc_timer`; the RTXC service catalogue and the timer-lifecycle callers
//! of this thunk identify `0x11` as `KS_free_timer`.

use core::mem::MaybeUninit;

use crate::heap::rom_task_start::gateway_dispatch;

/// Number of words from the selector at the dispatched request pointer through
/// the timer argument at offset `0x14`.
const TIMER_FREE_REQUEST_WORDS: usize = 6;

/// timer_free_gateway — original: `FUN_08003e1c` @ `0x08003e1c` (40 bytes).
///
/// Reference: `decomp/c/000/08003e1c_FUN_08003e1c.c`; raw assembly at
/// `0x08003e1c`; thunk `0x08037f10 -> 0x22003e1c`; and the RTXC service
/// catalogue. This is `KS_free_timer`: a null timer is a complete no-op.
/// Otherwise, the original reserves seven stack words (including a leading
/// unused word), writes selector `0x11` at the dispatched pointer, leaves the
/// next four request words deliberately unwritten, and writes the timer at
/// offset `0x14`. It delegates that six-word span to `FUN_08003660` and returns
/// void. The `MaybeUninit` frame preserves those intentionally unwritten words;
/// the shared volatile gateway hook is the necessary foreign-ROM/host-test
/// seam, and target integration must bind it to the real dispatcher.
///
/// # Safety
/// `timer` is the opaque RTXC clock-block handle accepted by `KS_free_timer`.
/// A non-null handle is forwarded without dereferencing or validating it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn timer_free_gateway(timer: *mut u8) {
    if timer.is_null() {
        return;
    }

    let mut request = [MaybeUninit::<u32>::uninit(); TIMER_FREE_REQUEST_WORDS];
    let request_words = request.as_mut_ptr().cast::<u32>();
    request_words.write(0x11);
    request_words.add(5).write(timer as usize as u32);
    gateway_dispatch()(request_words);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::rom_task_start::{RomGatewayOps, DEFAULT_ROM_GATEWAY_OPS, ROM_GATEWAY_OPS};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut SELECTOR: u32 = 0;
    static mut TIMER: u32 = 0;

    unsafe extern "C" fn record_request(request: *mut u32) {
        addr_of_mut!(CALLS).write(addr_of!(CALLS).read() + 1);
        // Words 1..=4 are deliberately unwritten by the retail wrapper and
        // must never be observed by this host recorder.
        addr_of_mut!(SELECTOR).write(request.read());
        addr_of_mut!(TIMER).write(request.add(5).read());
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(CALLS).write(0);
            addr_of_mut!(SELECTOR).write(0);
            addr_of_mut!(TIMER).write(0);
            addr_of_mut!(ROM_GATEWAY_OPS).write(RomGatewayOps {
                dispatch: record_request,
            });
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe { addr_of_mut!(ROM_GATEWAY_OPS).write(DEFAULT_ROM_GATEWAY_OPS) };
        drop(guard);
    }

    #[test]
    fn zero_timer_skips_gateway_dispatch() {
        let guard = install_recorder();
        unsafe {
            timer_free_gateway(core::ptr::null_mut());
            assert_eq!(addr_of!(CALLS).read(), 0);
        }
        restore(guard);
    }

    #[test]
    fn nonzero_timer_builds_sparse_free_timer_request_and_delegates() {
        let guard = install_recorder();
        let timer = 0x1234_5678usize as *mut u8;
        unsafe {
            timer_free_gateway(timer);
            assert_eq!(addr_of!(CALLS).read(), 1, "delegates exactly once");
            assert_eq!(addr_of!(SELECTOR).read(), 0x11);
            assert_eq!(addr_of!(TIMER).read(), timer as usize as u32);
        }
        restore(guard);
    }
}
