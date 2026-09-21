//! Resolving an object payload and dispatching its operation record.

/// Host-side seams for the two unported calls in this wrapper.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct HostObjectWordPayloadDispatchOps {
    pub resolve: unsafe extern "C" fn(*mut u32, *mut u32) -> *mut u32,
    pub dispatch: unsafe extern "C" fn(u32, *mut u32, u32, u32) -> u32,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_resolve(_: *mut u32, _: *mut u32) -> *mut u32 {
    panic!("object_word_payload_dispatch requires payload resolver")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dispatch(_: u32, _: *mut u32, _: u32, _: u32) -> u32 {
    panic!("object_word_payload_dispatch requires operation dispatcher 0x081404b4")
}

#[cfg(not(target_os = "none"))]
pub static mut OBJECT_WORD_PAYLOAD_DISPATCH_OPS: HostObjectWordPayloadDispatchOps =
    HostObjectWordPayloadDispatchOps {
        resolve: missing_resolve,
        dispatch: missing_dispatch,
    };

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch_operation(key: u32, payload: *mut u32, arg2: u32, arg3: u32) -> u32 {
    let dispatch: unsafe extern "C" fn(u32, u32, u32, u32) -> u32 =
        unsafe { core::mem::transmute(0x0814_04b4usize) };
    unsafe { dispatch(key, payload as usize as u32, arg2, arg3) }
}

/// object_word_payload_dispatch — original: `FUN_0829b734` @ **0x0829b734**
/// (**48 bytes exactly**, `0x0829b734..0x0829b760`; the next independently
/// linked function begins at `0x0829b764`).
///
/// Raw A32 decoding verifies **3 inbound plain `bl` call sites**
/// (0x08127100, 0x081271f8, and 0x08127e20), all unconditional, and **0
/// predicated `bl` forms**. Its body makes three unconditional direct `bl`
/// calls. It resolves the object's four-word payload, copies it to a second
/// stack record, then dispatches an operation keyed by payload word 1. The
/// dispatcher receives the resolver's payload record in r1 and the incoming
/// r2/r3 values unchanged; incoming r1 is overwritten before dispatch.
///
/// `FUN_081404b4` has no recovered semantic identity, so it remains an
/// explicit operation-dispatch seam. On target it is called at its verified
/// retail address. Host tests inject both unported calls; no semantic
/// deviation is made to the target path.
///
/// # Safety
/// `object` must satisfy the unported payload resolver's object contract.
/// The firmware does not validate it.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_word_payload_dispatch(
    object: *mut u32,
    _discarded_arg1: u32,
    operation_arg2: u32,
    operation_arg3: u32,
) -> u32 {
    let mut payload = [0u32; 4];

    #[cfg(target_os = "none")]
    unsafe {
        crate::util::object_word_payload_resolve::object_word_payload_resolve(payload.as_mut_ptr(), object);
        return dispatch_operation(payload[1], payload.as_mut_ptr(), operation_arg2, operation_arg3);
    }

    #[cfg(not(target_os = "none"))]
    unsafe {
        let ops = core::ptr::addr_of_mut!(OBJECT_WORD_PAYLOAD_DISPATCH_OPS).read_volatile();
        (ops.resolve)(payload.as_mut_ptr(), object);
        (ops.dispatch)(payload[1], payload.as_mut_ptr(), operation_arg2, operation_arg3)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{
        object_word_payload_dispatch, HostObjectWordPayloadDispatchOps, OBJECT_WORD_PAYLOAD_DISPATCH_OPS,
    };
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut SEEN_OBJECT: *mut u32 = core::ptr::null_mut();
    static mut SEEN_DISPATCH: (u32, [u32; 4], u32, u32) = (0, [0; 4], 0, 0);

    unsafe extern "C" fn resolve(destination: *mut u32, object: *mut u32) -> *mut u32 {
        unsafe {
            SEEN_OBJECT = object;
            destination.write(0x1122_3344);
            destination.add(1).write(0x5566_7788);
            destination.add(2).write(0x99aa_bbcc);
            destination.add(3).write(0xddee_ff00);
        }
        destination
    }

    unsafe extern "C" fn dispatch(key: u32, payload: *mut u32, arg2: u32, arg3: u32) -> u32 {
        unsafe {
            SEEN_DISPATCH = (
                key,
                [payload.read(), payload.add(1).read(), payload.add(2).read(), payload.add(3).read()],
                arg2,
                arg3,
            );
        }
        0x08ad_2ce8
    }

    struct OpsGuard(HostObjectWordPayloadDispatchOps);

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { OBJECT_WORD_PAYLOAD_DISPATCH_OPS = self.0 };
        }
    }

    #[test]
    fn resolves_four_words_then_dispatches_with_word_one_key() {
        let _lock = OPS_LOCK.lock();
        let previous = unsafe { core::ptr::read(core::ptr::addr_of!(OBJECT_WORD_PAYLOAD_DISPATCH_OPS)) };
        let _restore = OpsGuard(previous);
        unsafe {
            OBJECT_WORD_PAYLOAD_DISPATCH_OPS = HostObjectWordPayloadDispatchOps { resolve, dispatch };
            SEEN_OBJECT = core::ptr::null_mut();
            SEEN_DISPATCH = (0, [0; 4], 0, 0);
        }
        let mut object = [0u32; 11];

        let result = unsafe {
            object_word_payload_dispatch(object.as_mut_ptr(), 0xdead_beef, 0x1234_5678, 0x9abc_def0)
        };

        assert_eq!(result, 0x08ad_2ce8);
        assert_eq!(unsafe { SEEN_OBJECT }, object.as_mut_ptr());
        assert_eq!(
            unsafe { SEEN_DISPATCH },
            (0x5566_7788, [0x1122_3344, 0x5566_7788, 0x99aa_bbcc, 0xddee_ff00], 0x1234_5678, 0x9abc_def0)
        );
    }
}
