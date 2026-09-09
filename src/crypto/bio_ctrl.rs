//! OpenSSL's `BIO_ctrl` callback and method-control dispatcher.
//!
//! Port: `bio_ctrl` — `FUN_0803d294` @ 0x0803d294 (**196 bytes**,
//! `0x0803d294..0x0803d358`; the next separately linked function is the
//! eight-byte `ldr r0,[pc]` veneer at 0x0803d358). Raw decoding of every ARM
//! B/BL word in `osos.dec` found **18 call sites**, all unconditional `bl`:
//! `0x0803d6dc`, `0x0805fc88`, `0x0805fe8c`, `0x0805feac`, `0x08060030`,
//! `0x08060088`, `0x08060320`, `0x080606f0`, `0x080ebea4`, `0x080ebefc`,
//! `0x080ee608`, `0x080ee648`, `0x080ef128`, `0x080ef1a8`, `0x0827293c`,
//! `0x08272950`, `0x082d4538`, and `0x082d45e0`. There are no predicated
//! calls, tail branches, or image data words holding this address.
//!
//! # Algorithm
//!
//! A null BIO returns zero. A missing method or its `ctrl` slot logs
//! `ERR_LIB_BIO` `(32, 0x67, 0x79, 0, 0)` and returns `-2`. Otherwise a
//! non-null callback receives `(bio, BIO_CB_CTRL=6, parg, cmd, larg, 1)`;
//! its non-positive result short-circuits the method. The method's `ctrl`
//! slot at `method+0x18` then receives `(bio, cmd, larg, parg)`. If a
//! callback exists, its return notification uses `BIO_CB_CTRL|BIO_CB_RETURN`
//! (`0x86`) and replaces the method result.
//!
//! # Deliberate deviations
//!
//! The target dispatches the two raw 32-bit code-pointer words directly. On
//! a 64-bit host those words cannot contain Rust function pointers, so tests
//! use [`BIO_CTRL_OPS`] as a host-only execution model while preserving the
//! firmware's non-null tests and 32-bit object layout. `diag_ring_record` is
//! already ported and is called directly.

use core::ffi::c_void;

use crate::kernel::diag_ring_record::diag_ring_record;

/// `BIO_CB_CTRL`, the callback operation before a control method runs.
pub const BIO_CB_CTRL: u32 = 6;
/// `BIO_CB_RETURN` ORed into [`BIO_CB_CTRL`] after the control method returns.
pub const BIO_CB_RETURN: u32 = 0x80;
/// The callback operation after a control method runs.
pub const BIO_CB_CTRL_RETURN: u32 = BIO_CB_CTRL | BIO_CB_RETURN;

/// The first two target words of an OpenSSL BIO. Both are four-byte target
/// pointers even on hosts, so this representation must not use Rust pointers.
#[repr(C)]
pub struct Bio {
    /// +0x00 — `BIO_METHOD *`.
    pub method: u32,
    /// +0x04 — `BIO_callback_fn *`.
    pub callback: u32,
}

/// The portion of an OpenSSL BIO method used by [`bio_ctrl`].
#[repr(C)]
pub struct BioMethod {
    /// +0x00..+0x14 — method slots not read here.
    pub _reserved: [u32; 6],
    /// +0x18 — `ctrl` method slot.
    pub ctrl: u32,
}

/// The BIO callback ABI: `bio, operation, parg, cmd, larg, return_value`.
pub type BioCallback =
    unsafe extern "C" fn(*mut Bio, u32, *mut c_void, i32, i32, i32) -> i32;
/// The BIO method-control ABI: `bio, cmd, larg, parg`.
pub type BioMethodCtrl = unsafe extern "C" fn(*mut Bio, i32, i32, *mut c_void) -> i32;

/// Host execution model for target function-pointer words.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct BioCtrlOps {
    pub callback: BioCallback,
    pub ctrl: BioMethodCtrl,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bio_callback(
    _bio: *mut Bio,
    _operation: u32,
    _parg: *mut c_void,
    _cmd: i32,
    _larg: i32,
    _return_value: i32,
) -> i32 {
    panic!("bio_ctrl requires installed host BIO_CTRL_OPS")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bio_method_ctrl(
    _bio: *mut Bio,
    _cmd: i32,
    _larg: i32,
    _parg: *mut c_void,
) -> i32 {
    panic!("bio_ctrl requires installed host BIO_CTRL_OPS")
}

/// Host-only model of the two function-pointer words in [`Bio`] and
/// [`BioMethod`]. Target builds invoke those words themselves.
#[cfg(not(target_os = "none"))]
pub static mut BIO_CTRL_OPS: BioCtrlOps = BioCtrlOps {
    callback: missing_bio_callback,
    ctrl: missing_bio_method_ctrl,
};

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn bio_ctrl_ops() -> BioCtrlOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BIO_CTRL_OPS)) }
}

#[inline(always)]
unsafe fn invoke_callback(
    bio: *mut Bio,
    operation: u32,
    parg: *mut c_void,
    cmd: i32,
    larg: i32,
    return_value: i32,
) -> i32 {
    #[cfg(target_os = "none")]
    {
        let callback: BioCallback = unsafe { core::mem::transmute((*bio).callback as usize) };
        unsafe { callback(bio, operation, parg, cmd, larg, return_value) }
    }

    #[cfg(not(target_os = "none"))]
    unsafe {
        (bio_ctrl_ops().callback)(bio, operation, parg, cmd, larg, return_value)
    }
}

#[inline(always)]
unsafe fn invoke_ctrl(bio: *mut Bio, cmd: i32, larg: i32, parg: *mut c_void) -> i32 {
    #[cfg(target_os = "none")]
    {
        let method = unsafe { (*bio).method as usize as *const BioMethod };
        let ctrl: BioMethodCtrl = unsafe { core::mem::transmute((*method).ctrl as usize) };
        unsafe { ctrl(bio, cmd, larg, parg) }
    }

    #[cfg(not(target_os = "none"))]
    unsafe {
        (bio_ctrl_ops().ctrl)(bio, cmd, larg, parg)
    }
}

/// bio_ctrl — original: `FUN_0803d294` @ 0x0803d294 (196 bytes; 18 direct,
/// unconditional `bl` call sites, binary-verified from `osos.dec`).
///
/// Runs an OpenSSL BIO control command through its optional callback and the
/// method `ctrl` slot. The pre-callback may reject with a non-positive result;
/// the post-callback's result replaces the method result. Null BIOs return
/// zero; a missing method or control slot logs `(32, 0x67, 0x79, 0, 0)` and
/// returns `-2`.
///
/// # Safety
///
/// `bio` must be null or point to the two-word target layout above. A nonzero
/// `method` must point to a word-aligned [`BioMethod`], and target nonzero
/// callback/control words must be valid function entries with these ABIs.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bio_ctrl(
    bio: *mut Bio,
    cmd: i32,
    larg: i32,
    parg: *mut c_void,
) -> i32 {
    if bio.is_null() {
        return 0;
    }

    let method = unsafe { (*bio).method as usize as *const BioMethod };
    if method.is_null() || unsafe { (*method).ctrl } == 0 {
        unsafe { diag_ring_record(32, 0x67, 0x79, 0, 0) };
        return -2;
    }

    let callback = unsafe { (*bio).callback };
    if callback != 0 {
        let before = unsafe { invoke_callback(bio, BIO_CB_CTRL, parg, cmd, larg, 1) };
        if before <= 0 {
            return before;
        }
    }

    let result = unsafe { invoke_ctrl(bio, cmd, larg, parg) };
    if callback == 0 {
        return result;
    }
    unsafe { invoke_callback(bio, BIO_CB_CTRL_RETURN, parg, cmd, larg, result) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::{Mutex, MutexGuard};
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const METHOD_OFFSET: usize = 0x100;
    const PRESENT_POINTER: u32 = 1;

    static BIO_CTRL_TEST_LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BIO_CTRL, FIXTURE_LEN).map(|pointer| pointer as usize)
    });

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct CallbackCall {
        operation: u32,
        parg: usize,
        cmd: i32,
        larg: i32,
        return_value: i32,
    }

    #[derive(Clone, Copy)]
    struct Calls {
        before_result: i32,
        ctrl_result: i32,
        after_result: i32,
        callback_count: usize,
        ctrl_count: usize,
        callback: [CallbackCall; 2],
        ctrl: Option<(usize, i32, i32, usize)>,
    }

    impl Calls {
        const fn new() -> Self {
            Self {
                before_result: 1,
                ctrl_result: 0,
                after_result: 0,
                callback_count: 0,
                ctrl_count: 0,
                callback: [CallbackCall {
                    operation: 0,
                    parg: 0,
                    cmd: 0,
                    larg: 0,
                    return_value: 0,
                }; 2],
                ctrl: None,
            }
        }
    }

    static CALLS: Mutex<Calls> = Mutex::new(Calls::new());

    unsafe extern "C" fn recording_callback(
        bio: *mut Bio,
        operation: u32,
        parg: *mut c_void,
        cmd: i32,
        larg: i32,
        return_value: i32,
    ) -> i32 {
        let mut calls = CALLS.lock();
        let index = calls.callback_count;
        calls.callback[index] = CallbackCall {
            operation,
            parg: parg as usize,
            cmd,
            larg,
            return_value,
        };
        calls.callback_count += 1;
        if operation == BIO_CB_CTRL {
            calls.before_result
        } else {
            calls.after_result
        }
    }

    unsafe extern "C" fn recording_ctrl(
        bio: *mut Bio,
        cmd: i32,
        larg: i32,
        parg: *mut c_void,
    ) -> i32 {
        let mut calls = CALLS.lock();
        calls.ctrl_count += 1;
        calls.ctrl = Some((bio as usize, cmd, larg, parg as usize));
        calls.ctrl_result
    }

    struct OpsGuard {
        saved: BioCtrlOps,
    }

    impl OpsGuard {
        unsafe fn install() -> Self {
            let saved = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BIO_CTRL_OPS)) };
            unsafe {
                BIO_CTRL_OPS = BioCtrlOps {
                    callback: recording_callback,
                    ctrl: recording_ctrl,
                };
            }
            Self { saved }
        }
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { BIO_CTRL_OPS = self.saved };
        }
    }

    struct Fixture {
        bio: *mut Bio,
        method: *mut BioMethod,
    }

    impl Fixture {
        fn new() -> Option<Self> {
            let base = *SLAB.as_ref()? as *mut u8;
            unsafe {
                core::ptr::write_bytes(base, 0, FIXTURE_LEN);
                Some(Self {
                    bio: base.cast(),
                    method: base.add(METHOD_OFFSET).cast(),
                })
            }
        }

        unsafe fn configure(&self, method: bool, ctrl: bool, callback: bool) {
            unsafe {
                (*self.bio).method = if method { self.method as usize as u32 } else { 0 };
                (*self.bio).callback = if callback { PRESENT_POINTER } else { 0 };
                (*self.method).ctrl = if ctrl { PRESENT_POINTER } else { 0 };
            }
        }
    }

    fn locked_calls() -> MutexGuard<'static, Calls> {
        CALLS.lock()
    }

    fn reset_calls(before: i32, ctrl: i32, after: i32) {
        *locked_calls() = Calls {
            before_result: before,
            ctrl_result: ctrl,
            after_result: after,
            ..Calls::new()
        };
    }

    #[test]
    fn null_bio_returns_zero_without_dispatch() {
        let _lock = BIO_CTRL_TEST_LOCK.lock();
        let _ops = unsafe { OpsGuard::install() };
        reset_calls(1, 2, 3);

        assert_eq!(unsafe { bio_ctrl(core::ptr::null_mut(), 7, -9, 0x1234usize as *mut c_void) }, 0);
        let calls = locked_calls();
        assert_eq!(calls.callback_count, 0);
        assert_eq!(calls.ctrl_count, 0);
    }

    #[test]
    fn missing_method_or_control_slot_logs_and_returns_minus_two() {
        let _lock = BIO_CTRL_TEST_LOCK.lock();
        let _ops = unsafe { OpsGuard::install() };
        let Some(fixture) = Fixture::new() else {
            note_missing_u32_fixture("crypto::bio_ctrl");
            return;
        };
        reset_calls(1, 2, 3);

        unsafe { fixture.configure(false, true, true) };
        assert_eq!(unsafe { bio_ctrl(fixture.bio, 7, -9, core::ptr::null_mut()) }, -2);
        unsafe { fixture.configure(true, false, true) };
        assert_eq!(unsafe { bio_ctrl(fixture.bio, 7, -9, core::ptr::null_mut()) }, -2);
        let calls = locked_calls();
        assert_eq!(calls.callback_count, 0);
        assert_eq!(calls.ctrl_count, 0);
    }

    #[test]
    fn pre_callback_rejection_short_circuits_control() {
        let _lock = BIO_CTRL_TEST_LOCK.lock();
        let _ops = unsafe { OpsGuard::install() };
        let Some(fixture) = Fixture::new() else {
            note_missing_u32_fixture("crypto::bio_ctrl");
            return;
        };
        unsafe { fixture.configure(true, true, true) };
        reset_calls(-17, 22, 33);
        let parg = 0x1234_5678usize as *mut c_void;

        assert_eq!(unsafe { bio_ctrl(fixture.bio, 0x5a, -3, parg) }, -17);
        let calls = locked_calls();
        assert_eq!(calls.callback_count, 1);
        assert_eq!(calls.callback[0], CallbackCall {
            operation: BIO_CB_CTRL,
            parg: parg as usize,
            cmd: 0x5a,
            larg: -3,
            return_value: 1,
        });
        assert_eq!(calls.ctrl_count, 0);
    }

    #[test]
    fn callback_wraps_control_and_its_post_result_wins() {
        let _lock = BIO_CTRL_TEST_LOCK.lock();
        let _ops = unsafe { OpsGuard::install() };
        let Some(fixture) = Fixture::new() else {
            note_missing_u32_fixture("crypto::bio_ctrl");
            return;
        };
        unsafe { fixture.configure(true, true, true) };
        reset_calls(1, 41, -8);
        let parg = 0xabcd_1234usize as *mut c_void;

        assert_eq!(unsafe { bio_ctrl(fixture.bio, -7, 0x1020_3040, parg) }, -8);
        let calls = locked_calls();
        assert_eq!(calls.ctrl_count, 1);
        assert_eq!(calls.ctrl, Some((fixture.bio as usize, -7, 0x1020_3040, parg as usize)));
        assert_eq!(calls.callback_count, 2);
        assert_eq!(calls.callback[1], CallbackCall {
            operation: BIO_CB_CTRL_RETURN,
            parg: parg as usize,
            cmd: -7,
            larg: 0x1020_3040,
            return_value: 41,
        });
    }

    #[test]
    fn absent_callback_returns_control_result_directly() {
        let _lock = BIO_CTRL_TEST_LOCK.lock();
        let _ops = unsafe { OpsGuard::install() };
        let Some(fixture) = Fixture::new() else {
            note_missing_u32_fixture("crypto::bio_ctrl");
            return;
        };
        unsafe { fixture.configure(true, true, false) };
        reset_calls(1, -23, 99);

        assert_eq!(unsafe { bio_ctrl(fixture.bio, 3, 4, core::ptr::null_mut()) }, -23);
        let calls = locked_calls();
        assert_eq!(calls.callback_count, 0);
        assert_eq!(calls.ctrl_count, 1);
    }
}
