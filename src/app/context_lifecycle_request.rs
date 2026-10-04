//! Dispatches a request to a context's lifecycle object.
//!
//! `context_lifecycle_request` — `FUN_081f1244` @ `0x081f1244`.
//! True size: 124 bytes [0x081f1244, 0x081f12c0); next word is a new push.
//! Whole-image aligned A32 decoding verifies two inbound plain BLs at
//! 0x081f0874 and 0x081fcfb4, zero predicated inbound BLs. Outbound: zero
//! plain BLs, one BLNE to context_lifecycle_rearm and one indirect BLX.
//! If byte +0x70 is set or the object at +0x48 is absent, return zero.
//! Otherwise increment word +0x60 with wrapping arithmetic, invoke vtable
//! slot +0x18 with (object, request, output-byte pointer, mode, lower, upper),
//! and rearm if both the output byte and result are nonzero. Return the
//! result unchanged. Ghidra's u64 return is spurious: r1 is merely restored.
//! No target behavioral deviations. Hosts widen only the object/vtable
//! pointers within the reserved context prefix; all context offsets remain
//! fixed. The unresolved virtual operation retains its native ABI on hosts.

use super::context_lifecycle_rearm::context_lifecycle_rearm;

pub type LifecycleRequest = unsafe extern "C" fn(*mut u8, u32, *mut u8, u32, u32, u32) -> u32;

/// # Safety
/// `context` is writable through +0x70, with a valid guard at +0x50. Its
/// non-null lifecycle object and slot +0x18 must satisfy the virtual ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_lifecycle_request(context: *mut u8, request: u32, mode: u32, lower: u32, upper: u32) -> u32 {
    if context.add(0x70).read() != 0 {
        return 0;
    }
    let object = context.add(0x48).cast::<*mut u8>().read();
    if object.is_null() {
        return 0;
    }
    let counter = context.add(0x60).cast::<u32>();
    counter.write(counter.read().wrapping_add(1));
    let table = object.cast::<*const LifecycleRequest>().read();
    let dispatch = table.add(0x18 / 4).read();
    // Stock initializes an entire stack word, but only exposes/reads its byte.
    let mut output = 0u32;
    let result = dispatch(object, request, (&mut output as *mut u32).cast(), mode, lower, upper);
    if (&output as *const u32).cast::<u8>().read() != 0 && result != 0 {
        context_lifecycle_rearm(context);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use super::super::context_lifecycle_rearm::FRAMEWORK_ROOT_CONTEXT_OPERATION;

    static NOTIFICATIONS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn notify(_: *mut u8, context: *mut u8) {
        assert_eq!(context.add(0x60).cast::<u32>().read(), 0);
        NOTIFICATIONS.fetch_add(1, Ordering::Relaxed);
    }

    struct Restore(super::super::context_lifecycle_rearm::FrameworkRootContextOperation);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { FRAMEWORK_ROOT_CONTEXT_OPERATION = self.0; } }
    }

    #[repr(C)]
    struct Object {
        table: *const LifecycleRequest,
        result: u32,
        output: u8,
        accepted: u32,
    }

    unsafe extern "C" fn select(object: *mut u8, request: u32, output: *mut u8, mode: u32, lower: u32, upper: u32) -> u32 {
        let object = &mut *object.cast::<Object>();
        assert_eq!(output.read(), 0);
        if mode == 1 && request >= lower && request <= upper {
            object.accepted = request;
            output.write(object.output);
            object.result
        } else {
            0
        }
    }

    #[test]
    fn gating_wraparound_selection_and_notification_conditions() {
        let _lock = super::super::context_lifecycle_rearm::TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _restore = unsafe {
            let old = FRAMEWORK_ROOT_CONTEXT_OPERATION;
            FRAMEWORK_ROOT_CONTEXT_OPERATION = notify;
            Restore(old)
        };
        let table = [select as LifecycleRequest; 7];
        for disabled in [0, 1, 255] {
            for present in [false, true] {
                for result in [0, 1, 0x8000_0000, u32::MAX] {
                    for output in [0, 1, 255] {
                        for request in [0, 10, 20, 21, u32::MAX] {
                            let mut storage = [0u64; 16];
                            let context = storage.as_mut_ptr().cast::<u8>();
                            let mut object = Object { table: table.as_ptr(), result, output, accepted: 99 };
                            unsafe {
                                context.add(0x48).cast::<*mut u8>().write(if present { (&mut object as *mut Object).cast() } else { core::ptr::null_mut() });
                                NOTIFICATIONS.store(0, Ordering::Relaxed);
                                context.add(0x70).write(disabled);
                                context.add(0x60).cast::<u32>().write(u32::MAX);
                                let actual = context_lifecycle_request(context, request, 1, 10, 20);
                                let dispatched = disabled == 0 && present;
                                let accepted = dispatched && (10..=20).contains(&request);
                                assert_eq!(actual, if accepted { result } else { 0 });
                                assert_eq!(object.accepted, if accepted { request } else { 99 });
                                assert_eq!(context.add(0x60).cast::<u32>().read(), if dispatched { 0 } else { u32::MAX });
                                assert_eq!(NOTIFICATIONS.load(Ordering::Relaxed), (accepted && output != 0 && result != 0) as usize);
                            }
                        }
                    }
                }
            }
        }
    }
}
