//! `slot_request_submit_and_release` — original: `FUN_080648e0` @
//! `0x080648e0` (36 bytes of code in two disjoint chunks:
//! `0x080648e0..0x080648fb` and `0x08064908..0x08064913`). Ghidra's 28-byte
//! extent stops at the mid-function `b 0x08064908`; the twelve bytes at
//! `0x080648fc..0x08064907` between that branch and its target are a
//! separate one-call-site helper (`mov r1,#0; strb r1,[r0,#0xb91]; bx lr`),
//! and the true function resumes at the branch target. The next separately
//! linked function begins at `0x08064914`.
//!
//! Call sites: exactly five direct callers, all unconditional plain `bl`,
//! verified against `osos.asm`: `0x08067e30` and `0x0806d2a0`,
//! `0x0806d2b0`, `0x0806d2c0`, `0x0806d2d0`. The body itself issues one
//! plain `bl` (`0x0806ab00`) and zero predicated BLs; its only other
//! control transfer is the predicated tail branch `bne 0x080dc754`.
//!
//! # Algorithm
//!
//! Forwards all four argument words unchanged to the unported slot-request
//! submit @ `0x0806ab00` (r1 is a dead word the callee never reads; it is
//! forwarded only to keep the register stream identical to the original).
//! When the submit returns a nonzero slot/result word, the function
//! tail-branches to the unported per-slot resource release @ `0x080dc754`
//! with (ctx, result); a zero result returns directly. The release treats
//! the word as a slot index in `1..=0x30` and frees that slot's five
//! pointer fields (`+0x224`..`+0x544`, stride 4) plus the special slots
//! 6, 7, 9 and 0x18 (`+0x534`..`+0x540`).
//!
//! Both callees are unported, so ARM builds dispatch to their retailOS
//! entries while host builds route through replaceable operations.
//! Deliberate deviation: the stock predicated tail branch
//! (`bne 0x080dc754`) becomes an ordinary Rust conditional call, matching
//! the deviation already accepted for the heap veneers.

use core::ffi::c_void;
#[cfg(not(target_os = "none"))]
use core::ptr;

/// Unported slot-request submit @ `0x0806ab00`: probes/submits a request
/// for `ctx` and returns a slot/result word (zero when there is nothing to
/// release). Forwards to the unported `0x08055040` unless the request is
/// the (`arg2 == 0x100000`, `arg3 == 0`) special case on a flagged context
/// (byte `+0x18c` bit 0), which yields slot 2 directly.
pub type SlotRequestSubmit =
    unsafe extern "C" fn(*mut c_void, u32, u32, u32) -> u32;

/// Unported per-slot resource release @ `0x080dc754`: frees the pointer
/// fields of slot `slot` (valid range `1..=0x30`) on `ctx`.
pub type SlotResourcesRelease = unsafe extern "C" fn(*mut c_void, u32);

const SLOT_REQUEST_SUBMIT_ADDRESS: usize = 0x0806_ab00;
const SLOT_RESOURCES_RELEASE_ADDRESS: usize = 0x080d_c754;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_slot_request_submit(
    ctx: *mut c_void,
    arg1: u32,
    arg2: u32,
    arg3: u32,
) -> u32 {
    let submit: SlotRequestSubmit =
        unsafe { core::mem::transmute(SLOT_REQUEST_SUBMIT_ADDRESS) };
    unsafe { submit(ctx, arg1, arg2, arg3) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_slot_request_submit(
    _ctx: *mut c_void,
    _arg1: u32,
    _arg2: u32,
    _arg3: u32,
) -> u32 {
    panic!("slot_request_submit_and_release requires 0x0806ab00")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_slot_resources_release(ctx: *mut c_void, slot: u32) {
    let release: SlotResourcesRelease =
        unsafe { core::mem::transmute(SLOT_RESOURCES_RELEASE_ADDRESS) };
    unsafe { release(ctx, slot) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_slot_resources_release(_ctx: *mut c_void, _slot: u32) {
    panic!("slot_request_submit_and_release requires 0x080dc754")
}

/// The two unported helpers called by [`slot_request_submit_and_release`].
///
/// Target builds dispatch directly to retailOS; host tests install recording
/// implementations before exercising the port.
#[derive(Clone, Copy)]
pub struct SlotRequestReleaseOps {
    pub submit: SlotRequestSubmit,
    pub release: SlotResourcesRelease,
}

/// Replaceable operations; see [`SlotRequestReleaseOps`].
pub static mut SLOT_REQUEST_RELEASE_OPS: SlotRequestReleaseOps = SlotRequestReleaseOps {
    submit: firmware_slot_request_submit,
    release: firmware_slot_resources_release,
};

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn slot_request_release_ops() -> SlotRequestReleaseOps {
    unsafe { ptr::read_volatile(ptr::addr_of!(SLOT_REQUEST_RELEASE_OPS)) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn slot_request_release_ops() -> SlotRequestReleaseOps {
    SlotRequestReleaseOps {
        submit: firmware_slot_request_submit,
        release: firmware_slot_resources_release,
    }
}

/// Calls the unported per-slot resource-release routine.
///
/// Host builds use the installed [`SlotRequestReleaseOps`]; ARM builds call
/// retailOS at `0x080dc754`.
///
/// # Safety
///
/// `ctx` and `slot` must meet the firmware release routine's requirements.
pub unsafe fn slot_resources_release(ctx: *mut c_void, slot: u32) {
    let ops = unsafe { slot_request_release_ops() };
    unsafe { (ops.release)(ctx, slot) };
}

/// Releases resources for every valid slot in `ctx`.
///
/// Original: `FUN_080e1f8c` @ `0x080e1f8c`, 48 bytes
/// (`0x080e1f8c..0x080e1f8bb`); the next real function starts at
/// `0x080e1fbc`. Full-image decoding finds three inbound plain `bl` calls
/// and no predicated inbound BL calls. The body has one predicated `blne`,
/// to `slot_resources_release` @ `0x080dc754`, and no plain BL calls.
///
/// # Algorithm
///
/// Counts upward from zero and conditionally calls the per-slot release
/// routine after each increment, stopping before slot `0x31`; consequently
/// it releases slots `1..=0x30`. Deliberate deviation: Rust expresses the
/// stock `movne`/`blne` sequence as an ordinary loop body call. The callee is
/// the existing unported retailOS seam, so ARM builds retain the physical
/// dispatch and host builds use its replaceable operations.
///
/// # Safety
///
/// `ctx` must satisfy the unported release routine for each slot `1..=0x30`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn slot_resources_release_all(ctx: *mut c_void) {
    for slot in 1..=0x30 {
        unsafe { slot_resources_release(ctx, slot) };
    }
}


/// Submits a slot request for `ctx` and releases the returned slot's
/// resources when the submit reports a nonzero slot/result word.
///
/// Original: `FUN_080648e0` @ `0x080648e0` (36 bytes of code in two
/// chunks; five unconditional `bl` callers). `arg1`..`arg3` are the
/// request words forwarded unchanged to the submit @ `0x0806ab00`; their
/// semantics belong to that unported callee. `arg1` is never read by the
/// callee and is forwarded only to preserve the original register stream.
///
/// # Safety
///
/// `ctx` must be a valid context pointer for the firmware submit/release
/// pair: the submit may read the flag byte at `+0x18c`, and the release
/// walks pointer fields up to `ctx + 0x30 * 4 + 0x544`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn slot_request_submit_and_release(
    ctx: *mut c_void,
    arg1: u32,
    arg2: u32,
    arg3: u32,
) {
    let ops = unsafe { slot_request_release_ops() };
    let slot = unsafe { (ops.submit)(ctx, arg1, arg2, arg3) };
    if slot != 0 {
        unsafe { slot_resources_release(ctx, slot) };
    }
}
#[cfg(test)]
mod tests {
    extern crate std;

    use core::ffi::c_void;
    use core::ptr;
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Mutex;

    use super::{
        slot_request_submit_and_release, slot_resources_release_all,
        SlotRequestReleaseOps, SLOT_REQUEST_RELEASE_OPS,
    };

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static SUBMIT_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RELEASE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static SUBMIT_RESULT: AtomicUsize = AtomicUsize::new(0);
    static LAST_SUBMIT_CTX: AtomicUsize = AtomicUsize::new(0);
    static LAST_SUBMIT_ARGS: [AtomicUsize; 3] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];
    static LAST_RELEASE_CTX: AtomicUsize = AtomicUsize::new(0);
    static LAST_RELEASE_SLOT: AtomicUsize = AtomicUsize::new(0);
    static RELEASED_SLOTS: AtomicU64 = AtomicU64::new(0);

    unsafe extern "C" fn record_submit(ctx: *mut c_void, arg1: u32, arg2: u32, arg3: u32) -> u32 {
        SUBMIT_CALLS.fetch_add(1, Ordering::Relaxed);
        LAST_SUBMIT_CTX.store(ctx as usize, Ordering::Relaxed);
        LAST_SUBMIT_ARGS[0].store(arg1 as usize, Ordering::Relaxed);
        LAST_SUBMIT_ARGS[1].store(arg2 as usize, Ordering::Relaxed);
        LAST_SUBMIT_ARGS[2].store(arg3 as usize, Ordering::Relaxed);
        SUBMIT_RESULT.load(Ordering::Relaxed) as u32
    }

    unsafe extern "C" fn record_release(ctx: *mut c_void, slot: u32) {
        RELEASE_CALLS.fetch_add(1, Ordering::Relaxed);
        LAST_RELEASE_CTX.store(ctx as usize, Ordering::Relaxed);
        LAST_RELEASE_SLOT.store(slot as usize, Ordering::Relaxed);
        RELEASED_SLOTS.fetch_or(1u64 << slot, Ordering::Relaxed);
    }

    struct OpsRestore(SlotRequestReleaseOps);

    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe { ptr::write_volatile(ptr::addr_of_mut!(SLOT_REQUEST_RELEASE_OPS), self.0) }
        }
    }

    fn install_ops(submit_result: u32) -> OpsRestore {
        SUBMIT_CALLS.store(0, Ordering::Relaxed);
        RELEASE_CALLS.store(0, Ordering::Relaxed);
        SUBMIT_RESULT.store(submit_result as usize, Ordering::Relaxed);
        LAST_SUBMIT_CTX.store(0, Ordering::Relaxed);
        for slot in &LAST_SUBMIT_ARGS {
            slot.store(0, Ordering::Relaxed);
        }
        LAST_RELEASE_CTX.store(0, Ordering::Relaxed);
        LAST_RELEASE_SLOT.store(0, Ordering::Relaxed);
        RELEASED_SLOTS.store(0, Ordering::Relaxed);

        unsafe {
            let previous = ptr::read_volatile(ptr::addr_of!(SLOT_REQUEST_RELEASE_OPS));
            ptr::write_volatile(
                ptr::addr_of_mut!(SLOT_REQUEST_RELEASE_OPS),
                SlotRequestReleaseOps {
                    submit: record_submit,
                    release: record_release,
                },
            );
            OpsRestore(previous)
        }
    }

    #[test]
    fn zero_result_skips_the_release() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = install_ops(0);
        let ctx = 0x1234usize as *mut c_void;

        unsafe { slot_request_submit_and_release(ctx, 0xaa, 0xbb, 0xcc) };

        assert_eq!(SUBMIT_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(RELEASE_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn nonzero_result_releases_that_slot() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = install_ops(7);
        let ctx = 0x5678usize as *mut c_void;

        unsafe { slot_request_submit_and_release(ctx, 1, 2, 3) };

        assert_eq!(SUBMIT_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(RELEASE_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(LAST_RELEASE_CTX.load(Ordering::Relaxed), ctx as usize);
        assert_eq!(LAST_RELEASE_SLOT.load(Ordering::Relaxed), 7);
    }

    #[test]
    fn forwards_ctx_and_all_request_words_unchanged() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = install_ops(0);
        let ctx = 0x9abcusize as *mut c_void;

        unsafe { slot_request_submit_and_release(ctx, 0x1000, 0x2000_0000, 0x40_0000) };

        assert_eq!(LAST_SUBMIT_CTX.load(Ordering::Relaxed), ctx as usize);
        assert_eq!(LAST_SUBMIT_ARGS[0].load(Ordering::Relaxed), 0x1000);
        assert_eq!(LAST_SUBMIT_ARGS[1].load(Ordering::Relaxed), 0x2000_0000);
        assert_eq!(LAST_SUBMIT_ARGS[2].load(Ordering::Relaxed), 0x40_0000);
    }

    #[test]
    fn releases_every_valid_slot_once_in_ascending_range() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = install_ops(0);
        let ctx = 0xdef0usize as *mut c_void;

        unsafe { slot_resources_release_all(ctx) };

        assert_eq!(SUBMIT_CALLS.load(Ordering::Relaxed), 0);
        assert_eq!(RELEASE_CALLS.load(Ordering::Relaxed), 0x30);
        assert_eq!(LAST_RELEASE_CTX.load(Ordering::Relaxed), ctx as usize);
        assert_eq!(LAST_RELEASE_SLOT.load(Ordering::Relaxed), 0x30);
        assert_eq!(RELEASED_SLOTS.load(Ordering::Relaxed), (1u64 << 49) - 2);
    }
}
