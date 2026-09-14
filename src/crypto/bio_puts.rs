//! OpenSSL's `BIO_puts` callback and method dispatcher.
//!
//! Port: `bio_puts` — `FUN_0803d6e8` @ **0x0803d6e8** (220 bytes,
//! `0x0803d6e8..0x0803d7c4`; the next separately linked function starts at
//! `0x0803d7c4`). Raw decoding of every immediate ARM B/BL word in `osos.dec`
//! finds **six inbound call sites**: five unconditional `bl` at `0x08078210`,
//! `0x0807d220`, `0x0807d248`, `0x0809c04c`, and `0x080aed34`, plus `blne` at
//! `0x0807d204`. The predicated call means that caller independently gates the
//! no-NULL-guarded call; this entry still validates its BIO and method slots.
//!
//! # Algorithm
//!
//! A missing BIO, method, or method `bputs` slot logs `(32, 0x6e, 0x79, 0, 0)`
//! and returns `-2`; a non-initialized BIO logs `(32, 0x6e, 0x78, 0, 0)` and
//! does the same. A callback wraps the method call with `BIO_CB_PUTS=4` and
//! `BIO_CB_PUTS|BIO_CB_RETURN=0x84`; a non-positive pre-callback result skips
//! the method, while the post-callback result replaces the method result.
//! Positive method results add, wrapping, to `bio->num_write` at +0x34.
//!
//! # Deliberate deviations
//!
//! The target's `BIO` and `BIO_METHOD` store 32-bit function pointers. Host
//! builds cannot put Rust pointers in those words, so [`BIO_PUTS_OPS`] models
//! callback and `bputs` execution while retaining the original slot-presence
//! tests and target layout. The existing `diag_ring_record` port is called
//! directly.

#[cfg(not(target_os = "none"))]
use core::ffi::c_void;

use super::bio_ctrl::{Bio, BioCallback, BioMethod};
use crate::kernel::diag_ring_record::diag_ring_record;

/// `BIO_CB_PUTS`, the callback operation before the `bputs` method runs.
pub const BIO_CB_PUTS: u32 = 4;
/// `BIO_CB_RETURN` ORed into [`BIO_CB_PUTS`] after the method returns.
pub const BIO_CB_PUTS_RETURN: u32 = BIO_CB_PUTS | 0x80;

/// The `BIO_METHOD::bputs` ABI: BIO and NUL-terminated string, returning the
/// number of bytes accepted or a non-positive failure result.
pub type BioMethodPuts = unsafe extern "C" fn(*mut Bio, *const u8) -> i32;

/// The `BIO_METHOD` word holding `bputs`: target offset +0x10.
const BIO_METHOD_BPUTS_WORD: usize = 4;

/// Host execution model for the two target function-pointer words used here.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct BioPutsOps {
    pub callback: BioCallback,
    pub puts: BioMethodPuts,
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
    panic!("bio_puts requires installed host BIO_PUTS_OPS")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bio_puts(_bio: *mut Bio, _text: *const u8) -> i32 {
    panic!("bio_puts requires installed host BIO_PUTS_OPS")
}

/// Host-only replacement for the raw callback and `bputs` pointer words.
#[cfg(not(target_os = "none"))]
pub static mut BIO_PUTS_OPS: BioPutsOps = BioPutsOps {
    callback: missing_bio_callback,
    puts: missing_bio_puts,
};

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn bio_puts_ops() -> BioPutsOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BIO_PUTS_OPS)) }
}

#[inline(always)]
unsafe fn invoke_callback(
    bio: *mut Bio,
    operation: u32,
    text: *const u8,
    return_value: i32,
) -> i32 {
    #[cfg(target_os = "none")]
    {
        let callback: BioCallback = unsafe { core::mem::transmute((*bio).callback as usize) };
        unsafe { callback(bio, operation, text.cast_mut().cast(), 0, 0, return_value) }
    }

    #[cfg(not(target_os = "none"))]
    unsafe {
        (bio_puts_ops().callback)(bio, operation, text.cast_mut().cast(), 0, 0, return_value)
    }
}

#[inline(always)]
unsafe fn invoke_puts(bio: *mut Bio, method: *const BioMethod, text: *const u8) -> i32 {
    #[cfg(target_os = "none")]
    {
        let puts: BioMethodPuts = unsafe {
            core::mem::transmute((*method)._reserved[BIO_METHOD_BPUTS_WORD] as usize)
        };
        unsafe { puts(bio, text) }
    }

    #[cfg(not(target_os = "none"))]
    unsafe {
        (bio_puts_ops().puts)(bio, text)
    }
}

/// Performs OpenSSL's `BIO_puts` callback and `bputs` dispatch.
///
/// # Safety
///
/// `bio` must be null or point to a live target-layout [`Bio`]. A nonzero
/// `method` must point to a word-aligned [`BioMethod`]. On target, the nonzero
/// callback and `bputs` words must be valid entries with the documented ABIs;
/// `text` must be NUL-terminated when the method reads it.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.bio_puts")]
pub unsafe extern "C" fn bio_puts(bio: *mut Bio, text: *const u8) -> i32 {
    if bio.is_null() {
        unsafe { diag_ring_record(32, 0x6e, 0x79, 0, 0) };
        return -2;
    }

    let method = unsafe { (*bio).method as usize as *const BioMethod };
    if method.is_null() || unsafe { (*method)._reserved[BIO_METHOD_BPUTS_WORD] } == 0 {
        unsafe { diag_ring_record(32, 0x6e, 0x79, 0, 0) };
        return -2;
    }

    let callback = unsafe { (*bio).callback };
    if callback != 0 {
        let before = unsafe { invoke_callback(bio, BIO_CB_PUTS, text, 1) };
        if before <= 0 {
            return before;
        }
    }

    if unsafe { (*bio)._init } == 0 {
        unsafe { diag_ring_record(32, 0x6e, 0x78, 0, 0) };
        return -2;
    }

    let result = unsafe { invoke_puts(bio, method, text) };
    if result > 0 {
        unsafe { (*bio)._num_write = (*bio)._num_write.wrapping_add(result as u32) };
    }
    if callback == 0 {
        return result;
    }
    unsafe { invoke_callback(bio, BIO_CB_PUTS_RETURN, text, result) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::kernel::diag_ring_record::{DiagEventRing, DIAG_RING_BLOCK_GETTER};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, DIAG_RING_TEST_LOCK};
    use parking_lot::{Mutex, MutexGuard};
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const METHOD_OFFSET: usize = 0x100;
    const PRESENT_POINTER: u32 = 1;

    static BIO_PUTS_TEST_LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BIO_PUTS, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static CALLS: Mutex<Calls> = Mutex::new(Calls::new());
    static mut DIAGNOSTIC_RING: *mut DiagEventRing = core::ptr::null_mut();

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct CallbackCall {
        operation: u32,
        text: usize,
        cmd: i32,
        larg: i32,
        return_value: i32,
    }

    #[derive(Clone, Copy)]
    struct Calls {
        before_result: i32,
        puts_result: i32,
        after_result: i32,
        callback_count: usize,
        puts_count: usize,
        callbacks: [CallbackCall; 2],
        puts: Option<(usize, usize)>,
    }

    impl Calls {
        const fn new() -> Self {
            Self {
                before_result: 1,
                puts_result: 0,
                after_result: 0,
                callback_count: 0,
                puts_count: 0,
                callbacks: [CallbackCall {
                    operation: 0,
                    text: 0,
                    cmd: 0,
                    larg: 0,
                    return_value: 0,
                }; 2],
                puts: None,
            }
        }
    }

    unsafe extern "C" fn recording_callback(
        bio: *mut Bio,
        operation: u32,
        text: *mut c_void,
        cmd: i32,
        larg: i32,
        return_value: i32,
    ) -> i32 {
        let mut calls = CALLS.lock();
        let index = calls.callback_count;
        calls.callbacks[index] = CallbackCall {
            operation,
            text: text as usize,
            cmd,
            larg,
            return_value,
        };
        calls.callback_count += 1;
        let _ = bio;
        if operation == BIO_CB_PUTS {
            calls.before_result
        } else {
            calls.after_result
        }
    }

    unsafe extern "C" fn recording_puts(bio: *mut Bio, text: *const u8) -> i32 {
        let mut calls = CALLS.lock();
        calls.puts_count += 1;
        calls.puts = Some((bio as usize, text as usize));
        calls.puts_result
    }

    unsafe extern "C" fn diagnostic_ring() -> *mut DiagEventRing {
        unsafe { DIAGNOSTIC_RING }
    }

    struct OpsGuard {
        saved: BioPutsOps,
    }

    impl OpsGuard {
        unsafe fn install() -> Self {
            let saved = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BIO_PUTS_OPS)) };
            unsafe {
                BIO_PUTS_OPS = BioPutsOps {
                    callback: recording_callback,
                    puts: recording_puts,
                };
            }
            Self { saved }
        }
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { BIO_PUTS_OPS = self.saved };
        }
    }

    struct DiagnosticGuard {
        saved: Option<unsafe extern "C" fn() -> *mut DiagEventRing>,
    }

    impl DiagnosticGuard {
        unsafe fn install(ring: *mut DiagEventRing) -> Self {
            let saved = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DIAG_RING_BLOCK_GETTER)) };
            unsafe {
                DIAGNOSTIC_RING = ring;
                DIAG_RING_BLOCK_GETTER = Some(diagnostic_ring);
            }
            Self { saved }
        }
    }

    impl Drop for DiagnosticGuard {
        fn drop(&mut self) {
            unsafe {
                DIAG_RING_BLOCK_GETTER = self.saved;
                DIAGNOSTIC_RING = core::ptr::null_mut();
            }
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

        unsafe fn configure(&self, method: bool, bputs: bool, callback: bool, initialized: bool) {
            unsafe {
                (*self.bio).method = if method { self.method as usize as u32 } else { 0 };
                (*self.bio).callback = if callback { PRESENT_POINTER } else { 0 };
                (*self.bio)._init = initialized.into();
                (*self.method)._reserved[BIO_METHOD_BPUTS_WORD] = if bputs { PRESENT_POINTER } else { 0 };
            }
        }
    }

    fn reset_calls(before: i32, puts: i32, after: i32) {
        *CALLS.lock() = Calls {
            before_result: before,
            puts_result: puts,
            after_result: after,
            ..Calls::new()
        };
    }

    fn calls() -> MutexGuard<'static, Calls> {
        CALLS.lock()
    }

    fn fresh_ring() -> DiagEventRing {
        DiagEventRing {
            owner: 0,
            tags: [0; 16],
            pointers: [0; 16],
            flags: [0; 16],
            data0: [0; 16],
            data1: [0; 16],
            head: 0,
            tail: 0,
        }
    }

    #[test]
    fn invalid_bio_or_bputs_slot_logs_uninitialized_method_error() {
        let _lock = BIO_PUTS_TEST_LOCK.lock();
        let _diagnostic_lock = DIAG_RING_TEST_LOCK.lock();
        let _ops = unsafe { OpsGuard::install() };
        let mut ring = fresh_ring();
        let _diagnostics = unsafe { DiagnosticGuard::install(&mut ring) };
        reset_calls(1, 2, 3);

        assert_eq!(unsafe { bio_puts(core::ptr::null_mut(), core::ptr::null()) }, -2);
        assert_eq!(ring.tags[1], 0x20_06e_079);
        let Some(fixture) = Fixture::new() else {
            note_missing_u32_fixture("crypto::bio_puts");
            return;
        };
        unsafe { fixture.configure(true, false, true, true) };
        assert_eq!(unsafe { bio_puts(fixture.bio, b"x\0".as_ptr()) }, -2);
        assert_eq!(ring.tags[2], 0x20_06e_079);
        let recorded = calls();
        assert_eq!((recorded.callback_count, recorded.puts_count), (0, 0));
    }

    #[test]
    fn pre_callback_rejection_skips_initialization_and_method() {
        let _lock = BIO_PUTS_TEST_LOCK.lock();
        let _ops = unsafe { OpsGuard::install() };
        let Some(fixture) = Fixture::new() else {
            note_missing_u32_fixture("crypto::bio_puts");
            return;
        };
        unsafe { fixture.configure(true, true, true, false) };
        reset_calls(-17, 22, 33);
        let text = b"rejected\0";

        assert_eq!(unsafe { bio_puts(fixture.bio, text.as_ptr()) }, -17);
        let recorded = calls();
        assert_eq!(recorded.callback_count, 1);
        assert_eq!(recorded.callbacks[0], CallbackCall {
            operation: BIO_CB_PUTS,
            text: text.as_ptr() as usize,
            cmd: 0,
            larg: 0,
            return_value: 1,
        });
        assert_eq!(recorded.puts_count, 0);
    }

    #[test]
    fn initialized_bio_wraps_puts_and_post_callback_result_wins() {
        let _lock = BIO_PUTS_TEST_LOCK.lock();
        let _ops = unsafe { OpsGuard::install() };
        let Some(fixture) = Fixture::new() else {
            note_missing_u32_fixture("crypto::bio_puts");
            return;
        };
        unsafe { fixture.configure(true, true, true, true) };
        unsafe { (*fixture.bio)._num_write = u32::MAX };
        reset_calls(1, 1, -8);
        let text = b"write\0";

        assert_eq!(unsafe { bio_puts(fixture.bio, text.as_ptr()) }, -8);
        assert_eq!(unsafe { (*fixture.bio)._num_write }, 0, "positive count wraps like add r1,r1,r0");
        let recorded = calls();
        assert_eq!(recorded.puts, Some((fixture.bio as usize, text.as_ptr() as usize)));
        assert_eq!(recorded.callback_count, 2);
        assert_eq!(recorded.callbacks[1], CallbackCall {
            operation: BIO_CB_PUTS_RETURN,
            text: text.as_ptr() as usize,
            cmd: 0,
            larg: 0,
            return_value: 1,
        });
    }

    #[test]
    fn uninitialized_bio_logs_after_callback_without_method_dispatch() {
        let _lock = BIO_PUTS_TEST_LOCK.lock();
        let _diagnostic_lock = DIAG_RING_TEST_LOCK.lock();
        let _ops = unsafe { OpsGuard::install() };
        let Some(fixture) = Fixture::new() else {
            note_missing_u32_fixture("crypto::bio_puts");
            return;
        };
        let mut ring = fresh_ring();
        let _diagnostics = unsafe { DiagnosticGuard::install(&mut ring) };
        unsafe { fixture.configure(true, true, true, false) };
        reset_calls(1, 10, 99);

        assert_eq!(unsafe { bio_puts(fixture.bio, b"x\0".as_ptr()) }, -2);
        assert_eq!(ring.tags[1], 0x20_06e_078);
        let recorded = calls();
        assert_eq!(recorded.callback_count, 1);
        assert_eq!(recorded.puts_count, 0);
    }

    #[test]
    fn absent_callback_returns_nonpositive_puts_result_without_counting() {
        let _lock = BIO_PUTS_TEST_LOCK.lock();
        let _ops = unsafe { OpsGuard::install() };
        let Some(fixture) = Fixture::new() else {
            note_missing_u32_fixture("crypto::bio_puts");
            return;
        };
        unsafe { fixture.configure(true, true, false, true) };
        unsafe { (*fixture.bio)._num_write = 0x44 };
        reset_calls(1, -23, 99);

        assert_eq!(unsafe { bio_puts(fixture.bio, b"x\0".as_ptr()) }, -23);
        assert_eq!(unsafe { (*fixture.bio)._num_write }, 0x44);
        let recorded = calls();
        assert_eq!((recorded.callback_count, recorded.puts_count), (0, 1));
    }
}
