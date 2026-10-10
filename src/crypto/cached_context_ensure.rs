//! Ensure the crypto object's cached context exists under resource lock 9.
//!
//! `FUN_0809c6fc` @ 0x0809c6fc: 92 bytes, ending at 0x0809c758,
//! where the next real function starts with push {r2,r3,lr}. Raw ARM words
//! verify two incoming plain BL sites (0x080cb934, 0x080cbc94), no
//! predicated incoming BLs, and three outgoing plain BLs, no predicated
//! outgoing BLs. Ghidra's extent is correct; the assigned call count refers
//! to callers, not calls in this body.
//!
//! Acquire resource 9, inspect the aligned word at object +0x50, call the
//! initializer at 0x08062218 only if zero, release resource 9, and return
//! the initializer's complete u32 result (otherwise 1). The initializer's
//! raw-verified call target and C body establish that it populates +0x50;
//! the precise crypto context type is not established, so names stay neutral.
//!
//! Deviations: use the existing Rust resource dispatcher and its descriptor
//! hooks; the unported initializer uses its verified firmware address on
//! target and a recording replacement only in host tests. Word indices
//! retain the target's four-byte field spacing on hosts as well.

use crate::kernel::resource_op::resource_op_dispatch;

type Initialize = unsafe extern "C" fn(*mut u32, u32) -> u32;

#[cfg(target_os = "none")]
unsafe fn initialize(object: *mut u32, context: u32) -> u32 {
    let call: Initialize = unsafe { core::mem::transmute(0x08062218usize) };
    unsafe { call(object, context) }
}

#[cfg(not(target_os = "none"))]
unsafe fn initialize(object: *mut u32, context: u32) -> u32 {
    #[cfg(test)]
    return unsafe { (INITIALIZE)(object, context) };
    #[cfg(not(test))]
    { let _ = (object, context); panic!("firmware crypto initializer requires target hardware") }
}

/// Ensure object word +0x50 is initialized, serialized by resource 9.
///
/// # Safety
/// `object` must be aligned and valid through word 20. On target it must
/// be a complete stock crypto object accepted by 0x08062218, and `context`
/// must be a valid stock context handle (zero requests a temporary context).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn crypto_cached_context_ensure(object: *mut u32, context: u32) -> u32 {
    unsafe { resource_op_dispatch(9, 9, 0, 0) };
    let result = if unsafe { object.add(20).read() } == 0 {
        unsafe { initialize(object, context) }
    } else {
        1
    };
    unsafe { resource_op_dispatch(10, 9, 0, 0) };
    result
}

#[cfg(test)]
static mut INITIALIZE: Initialize = tests::initialize;

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::kernel::resource_op::{RESOURCE_OP_HOOKS, RESOURCE_OP_HOOKS_TEST_LOCK};
    use std::vec::Vec;

    static mut EVENTS: Vec<u32> = Vec::new();
    static mut OBJECT: *mut u32 = core::ptr::null_mut();
    static mut RESULT: u32 = 0;
    static mut PUBLISH_ON_LOCK: u32 = 0;

    unsafe extern "C" fn lock(op: u32, resource: i32, arg0: u32, arg1: u32) {
        assert_eq!((resource, arg0, arg1), (9, 0, 0));
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).push(op);
            if op == 9 && PUBLISH_ON_LOCK != 0 {
                OBJECT.add(20).write(PUBLISH_ON_LOCK);
            }
        }
    }

    pub(super) unsafe extern "C" fn initialize(object: *mut u32, context: u32) -> u32 {
        unsafe {
            assert_eq!(object, OBJECT);
            assert_eq!(object.add(20).read(), 0);
            (*core::ptr::addr_of_mut!(EVENTS)).extend_from_slice(&[99, context]);
            if RESULT != 0 { object.add(20).write(0x12345678); }
            RESULT
        }
    }

    struct Restore(crate::kernel::resource_op::ResourceOpHooks);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(RESOURCE_OP_HOOKS).write(self.0) };
        }
    }

    #[test]
    fn lock_recheck_failure_retry_and_result_preservation() {
        let _guard = RESOURCE_OP_HOOKS_TEST_LOCK.lock();
        let saved = unsafe { core::ptr::addr_of!(RESOURCE_OP_HOOKS).read() };
        let _restore = Restore(saved);
        unsafe { (*core::ptr::addr_of_mut!(RESOURCE_OP_HOOKS)).static_op = Some(lock) };
        for (cached, publish, result, context) in [
            (1, 0, 0, 7), (u32::MAX, 0, 0, 8),
            (0, 5, 0, 9), (0, 0, 0, 0),
            (0, 0, 1, 0), (0, 0, 0x80000002, u32::MAX),
        ] {
            let mut object = [0xa5a5a5a5u32; 22];
            object[20] = cached;
            unsafe {
                OBJECT = object.as_mut_ptr(); RESULT = result; PUBLISH_ON_LOCK = publish;
                (*core::ptr::addr_of_mut!(EVENTS)).clear();
                let actual = crypto_cached_context_ensure(OBJECT, context);
                let skipped = cached != 0 || publish != 0;
                assert_eq!(actual, if skipped { 1 } else { result });
                let events = &*core::ptr::addr_of!(EVENTS);
                if skipped { assert_eq!(events.as_slice(), &[9, 10]); }
                else { assert_eq!(events.as_slice(), &[9, 99, context, 10]); }
                assert_eq!(object[20], if cached != 0 { cached } else if publish != 0 {
                    publish
                } else if result != 0 { 0x12345678 } else { 0 });
                assert!(object[..20].iter().all(|&word| word == 0xa5a5a5a5));
                assert_eq!(object[21], 0xa5a5a5a5);
                // Failed initialization remains retryable; success suppresses a second call.
                if !skipped {
                    RESULT = 1;
                    (*core::ptr::addr_of_mut!(EVENTS)).clear();
                    assert_eq!(crypto_cached_context_ensure(OBJECT, context), 1);
                    let expected: &[u32] = if result == 0 { &[9, 99, context, 10] } else { &[9, 10] };
                    assert_eq!((&*core::ptr::addr_of!(EVENTS)).as_slice(), expected);
                }
            }
        }
    }
}
