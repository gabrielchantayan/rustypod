//! Verify a proprietary digest and release its context.
//!
//! Original: `FUN_0803c1cc` @ 0x0803c1cc. True extent
//! [0x0803c1cc, 0x0803c264): 136 instruction bytes plus 16 literal bytes.
//! Raw ARM has one plain outbound BL, no predicated outbound BLs; whole-image
//! word decoding finds one inbound BL and one inbound BLNE.
//!
//! The initial state is 0x2d133efe, one above the dispatch base 0x2d133efd.
//! It installs the incoming arguments, calls the worker at 0x08392dbc, then
//! advances to the return state. The length and result multipliers
//! 0xaf777bff and 0x0c7883ff multiply to 1 modulo 2^32, so both values pass
//! through unchanged, including negative status bits and overflowing lengths.
//!
//! Deliberate deviations: remove the opaque state machine and inverse wrapping
//! multiplications. Retain the unported worker at its verified address; its
//! raw body validates a non-null context, non-null expected digest and length
//! 20, compares a computed digest, then clears/releases the context. Ghidra's
//! fourth argument is spurious: neither wrapper nor worker reads it.
//! ARM codegen tail-dispatches through the worker seam instead of using BL.
//! A host smoke compared 100,000 length/status pairs against the literal-driven
//! retail state transitions, including the effective call count and length.

/// Verified three-register ABI of the worker at 0x08392dbc.
pub type DigestVerifyWorker = unsafe extern "C" fn(*mut u8, *const u8, u32) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_verify(context: *mut u8, expected: *const u8, len: u32) -> i32 {
    let worker: DigestVerifyWorker = core::mem::transmute(0x0839_2dbcusize);
    worker(context, expected, len)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_verify(_context: *mut u8, _expected: *const u8, _len: u32) -> i32 {
    panic!("digest_verify_and_release requires retail worker 0x08392dbc")
}

#[cfg(target_os = "none")]
pub static mut DIGEST_VERIFY_WORKER: DigestVerifyWorker = firmware_verify;
#[cfg(not(target_os = "none"))]
pub static mut DIGEST_VERIFY_WORKER: DigestVerifyWorker = missing_verify;

/// Verify the expected digest, returning the worker's exact signed status.
///
/// # Safety
/// Arguments must satisfy the retail worker's contract. For non-null arguments
/// and length 20, `context` is a live 0x5c-byte proprietary context consumed by
/// the worker and `expected` points to 20 readable bytes. Invalid arguments are
/// passed to the worker without local validation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn digest_verify_and_release(
    context: *mut u8, expected: *const u8, len: u32,
) -> i32 {
    let worker = core::ptr::read_volatile(core::ptr::addr_of!(DIGEST_VERIFY_WORKER));
    worker(context, expected, len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    const INVALID: i32 = -42023; // raw literal 0xffff5bd9
    const MISMATCH: i32 = -42022; // raw literal 0xffff5bda

    // A contract model, not a port of the worker's proprietary hash algorithm:
    // the already-computed digest stands in for its finalization dependencies.
    #[repr(C)]
    struct CompletedDigest {
        digest: [u8; 20],
        consumed: bool,
        status: i32,
    }

    unsafe extern "C" fn completed_digest_worker(
        context: *mut u8, expected: *const u8, len: u32,
    ) -> i32 {
        if context.is_null() || expected.is_null() || len != 20 { return INVALID; }
        let context = &mut *context.cast::<CompletedDigest>();
        let status = if crate::memcmp::memcmp(context.digest.as_ptr(), expected, 20) == 0 {
            context.status
        } else { MISMATCH };
        context.digest.fill(0x42);
        context.consumed = true;
        status
    }

    struct Restore(DigestVerifyWorker);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { DIGEST_VERIFY_WORKER = self.0; } }
    }

    #[test]
    fn validation_consumption_and_exact_signed_status() {
        let _lock = LOCK.lock();
        let _restore = Restore(unsafe { DIGEST_VERIFY_WORKER });
        unsafe { DIGEST_VERIFY_WORKER = completed_digest_worker; }
        let expected = [0x9au8; 20];
        let mut context = CompletedDigest { digest: expected, consumed: false, status: 0 };
        let ptr = (&mut context as *mut CompletedDigest).cast::<u8>();
        unsafe {
            for len in [0, 1, 19, 21, 0x8000_0000, u32::MAX] {
                assert_eq!(digest_verify_and_release(ptr, expected.as_ptr(), len), INVALID);
                assert!(!context.consumed);
                assert_eq!(context.digest, expected);
            }
            assert_eq!(digest_verify_and_release(core::ptr::null_mut(), expected.as_ptr(), 20), INVALID);
            assert_eq!(digest_verify_and_release(ptr, core::ptr::null(), 20), INVALID);
            assert!(!context.consumed);
            for status in [0, 1, -1, i32::MIN, i32::MAX, INVALID] {
                context.digest = expected;
                context.consumed = false;
                context.status = status;
                assert_eq!(digest_verify_and_release(ptr, expected.as_ptr(), 20), status);
                assert!(context.consumed);
                assert_eq!(context.digest, [0x42; 20]);
            }
            for index in [0, 19] {
                context.digest = expected;
                context.digest[index] ^= 0xff;
                context.consumed = false;
                assert_eq!(digest_verify_and_release(ptr, expected.as_ptr(), 20), MISMATCH);
                assert!(context.consumed);
            }
        }
    }
}
