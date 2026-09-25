//! Raw mask-ROM service-29 gateway request wrapper.
//!
//! `thunk_EXT_FUN_22003bb0` is an eight-byte ADS literal veneer at load
//! address `0x08038258`: `e51ff004` (`ldr pc, [pc, #-4]`) followed by the
//! target word `22003bb0`. The boot relocator mirrors that ROM target at
//! `0x08003bb0`, where the true 28-byte body ends before the sibling wrapper
//! at `0x08003bcc`.
//!
//! Raw ARM saves `r1`/`r2`/`r3`/`lr`, writes `{ 0x1d, first, second }` at the
//! resulting stack pointer, and passes it to `FUN_08003660`, the RTXC gateway
//! dispatcher. It does not inspect the request after dispatch. Decoding all
//! direct branch-with-link words finds three inbound plain `bl` calls and no
//! predicated `bl` calls. The service's higher-level identity is unrecovered,
//! so this module names its verified wire protocol rather than inventing it.
//!
//! # Deliberate deviation
//!
//! The literal veneer and foreign RTXC dispatcher are represented by the
//! established volatile `message_dispatch_veneer` seam. Rust cannot preserve
//! the original's caller-saved register restoration, which is not part of the
//! C ABI and is not an observable result of the wrapper.

use crate::runtime::message_dispatch_veneer::message_dispatch_veneer;

/// osos load address of `thunk_EXT_FUN_22003bb0`.
pub const SERVICE29_THUNK: u32 = 0x0803_8258;
/// ROM target literal held by [`SERVICE29_THUNK`].
pub const SERVICE29_ROM_ENTRY: u32 = 0x2200_3bb0;
/// Byte-identical osos mirror of [`SERVICE29_ROM_ENTRY`].
pub const SERVICE29_MIRROR_ENTRY: u32 = 0x0800_3bb0;

/// RTXC selector at word zero of the request record.
pub const GATEWAY_SERVICE_29: u32 = 0x1d;

/// service-29 request passed to the RTXC gateway.
pub type GatewayService29Request = [u32; 3];

/// gateway_service29 — original: `thunk_EXT_FUN_22003bb0` @ `0x08038258`
/// (8-byte veneer) → mirrored body `0x08003bb0` (28 bytes; three plain `bl`
/// call sites, no predicated forms).
///
/// Builds `{ 0x1d, first, second }` and passes the writable record to the
/// RTXC dispatcher. The original does not consume dispatcher output and its
/// Ghidra signature is `void`; this port likewise exposes no result.
///
/// # Safety
///
/// The target dispatcher interprets the selector-specific writable request.
/// On-device integration must install the real dispatcher through
/// `message_dispatch_veneer`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn gateway_service29(first: u32, second: u32) {
    let mut request: GatewayService29Request = [GATEWAY_SERVICE_29, first, second];
    message_dispatch_veneer(request.as_mut_ptr());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::runtime::message_dispatch_veneer::tests::DISPATCH_OPS_LOCK;
    use crate::runtime::message_dispatch_veneer::{
        MessageDispatchVeneerOps, MESSAGE_DISPATCH_VENEER_OPS,
    };
    use core::ptr::{addr_of, addr_of_mut};
    use parking_lot::MutexGuard;

    static mut OBSERVED: GatewayService29Request = [0; 3];

    struct Recorder {
        _lock: MutexGuard<'static, ()>,
        saved: MessageDispatchVeneerOps,
    }

    impl Drop for Recorder {
        fn drop(&mut self) {
            unsafe { MESSAGE_DISPATCH_VENEER_OPS = self.saved };
        }
    }

    unsafe extern "C" fn record(request: *mut u32) {
        addr_of_mut!(OBSERVED).write([request.read(), request.add(1).read(), request.add(2).read()]);
    }

    fn install() -> Recorder {
        let lock = DISPATCH_OPS_LOCK.lock();
        let saved = unsafe { MESSAGE_DISPATCH_VENEER_OPS };
        unsafe {
            addr_of_mut!(OBSERVED).write([0; 3]);
            MESSAGE_DISPATCH_VENEER_OPS = MessageDispatchVeneerOps { dispatch: record };
        }
        Recorder { _lock: lock, saved }
    }

    #[test]
    fn passes_the_three_word_service29_record_in_order() {
        let _recorder = install();
        unsafe { gateway_service29(0x1234_5678, 0x9abc_def0) };
        unsafe {
            assert_eq!(addr_of!(OBSERVED).read(), [GATEWAY_SERVICE_29, 0x1234_5678, 0x9abc_def0]);
        }
    }

    #[test]
    fn forwards_boundary_words_without_a_guard() {
        let _recorder = install();
        for (first, second) in [(0, 0), (u32::MAX, 1), (0x8000_0000, 0x7fff_ffff)] {
            unsafe { gateway_service29(first, second) };
            unsafe { assert_eq!(addr_of!(OBSERVED).read(), [GATEWAY_SERVICE_29, first, second]) };
        }
    }
}
