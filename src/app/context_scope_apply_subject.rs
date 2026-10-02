//! Applies the subject operation guarded by a context scope's virtual predicate.
//!
//! Original `FUN_08283ff8` @ `0x08283ff8`, true size 60 bytes: the final
//! pop is at 0x08284030 and the next function begins at 0x08284034.
//! Whole-image aligned A32 decoding verifies two inbound plain BLs
//! (0x08044e60, 0x08238b98), zero predicated BLs. The body has one plain BL
//! to 0x08048204, one BLEQ to 0x08061378, and one virtual BLX at slot +0x0c.
//! Call the scope predicate; return zero if unavailable. Otherwise apply the
//! unported subject operation and, if it returns zero, reload the subject
//! and notify teardown. Return one regardless of the operation's result.
//!
//! Deliberate deviations: replaceable volatile operation boundaries follow
//! context_scope_complete_selection. The unnamed 0x08048204 remains a raw
//! retail call, not a guessed callee; teardown uses its existing Rust port.
//! Host defaults panic for unavailable firmware boundaries. Target pointers
//! remain u32 words to preserve +0x04 even on 64-bit hosts.

use core::ptr;
use super::context_scope_complete_selection::ContextScopeSubjectAvailable;

pub type ContextScopeSubjectOperation = unsafe extern "C" fn(*mut u8) -> i32;
pub type ContextScopeTeardown = unsafe extern "C" fn(*mut u8);

#[derive(Clone, Copy)]
pub struct ContextScopeApplySubjectOps {
    pub subject_available: ContextScopeSubjectAvailable,
    pub subject_operation: ContextScopeSubjectOperation,
    pub notify_teardown: ContextScopeTeardown,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_subject_available(scope: *mut u8) -> i32 {
    let vtable = unsafe { scope.cast::<u32>().read_volatile() };
    let address = unsafe { ((vtable as usize + 0x0c) as *const u32).read_volatile() };
    let available: ContextScopeSubjectAvailable = unsafe { core::mem::transmute(address as usize) };
    unsafe { available(scope) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_subject_operation(subject: *mut u8) -> i32 {
    let operation: ContextScopeSubjectOperation = unsafe { core::mem::transmute(0x0804_8204usize) };
    unsafe { operation(subject) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_subject_available(_scope: *mut u8) -> i32 {
    panic!("context scope virtual predicate requires firmware or installed host ops")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_subject_operation(_subject: *mut u8) -> i32 {
    panic!("subject operation at 0x08048204 requires firmware or installed host ops")
}

pub static mut CONTEXT_SCOPE_APPLY_SUBJECT_OPS: ContextScopeApplySubjectOps = ContextScopeApplySubjectOps {
    subject_available: firmware_subject_available,
    subject_operation: firmware_subject_operation,
    notify_teardown: crate::ui::plst_element_teardown::plst_element_notify_teardown,
};

/// # Safety
/// `scope` must be aligned and readable through word 1. Its vtable predicate,
/// subject operation and teardown boundaries must accept the supplied objects.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn context_scope_apply_subject(scope: *mut u8) -> i32 {
    let ops = unsafe { ptr::read_volatile(ptr::addr_of!(CONTEXT_SCOPE_APPLY_SUBJECT_OPS)) };
    if unsafe { (ops.subject_available)(scope) } == 0 {
        return 0;
    }
    let subject = unsafe { scope.cast::<u32>().add(1).read() } as usize as *mut u8;
    if unsafe { (ops.subject_operation)(subject) } == 0 {
        let subject = unsafe { scope.cast::<u32>().add(1).read() } as usize as *mut u8;
        unsafe { (ops.notify_teardown)(subject) };
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut AVAILABLE: i32 = 0;
    static mut RESULT: i32 = 0;
    static mut SCOPE: *mut u32 = ptr::null_mut();
    static mut PHASE: u32 = 0;

    unsafe extern "C" fn available(scope: *mut u8) -> i32 {
        unsafe {
            assert_eq!(PHASE, 0);
            assert_eq!(scope.cast::<u32>(), SCOPE);
            PHASE = 1;
            AVAILABLE
        }
    }
    unsafe extern "C" fn operation(subject: *mut u8) -> i32 {
        unsafe {
            assert_eq!(PHASE, 1);
            assert_eq!(subject as usize, 0x1234_5000);
            PHASE = 2;
            SCOPE.add(1).write(0x8765_4000);
            RESULT
        }
    }
    unsafe extern "C" fn notify(subject: *mut u8) {
        unsafe {
            assert_eq!(PHASE, 2);
            assert_eq!(subject as usize, 0x8765_4000);
            PHASE = 3;
        }
    }

    #[test]
    fn gates_operation_normalizes_return_and_reloads_changed_subject() {
        let _guard = LOCK.lock();
        unsafe {
            let saved = ptr::read(ptr::addr_of!(CONTEXT_SCOPE_APPLY_SUBJECT_OPS));
            CONTEXT_SCOPE_APPLY_SUBJECT_OPS = ContextScopeApplySubjectOps {
                subject_available: available, subject_operation: operation, notify_teardown: notify,
            };
            for available_result in [0, 1, -1, i32::MIN] {
                for operation_result in [0, 1, -1, i32::MIN] {
                    let mut scope = [0, 0x1234_5000, 0xaaaa_aaaa, 0xbbbb_bbbb, 0xcccc_cccc];
                    SCOPE = scope.as_mut_ptr();
                    AVAILABLE = available_result;
                    RESULT = operation_result;
                    PHASE = 0;
                    assert_eq!(context_scope_apply_subject(SCOPE.cast()), i32::from(available_result != 0));
                    assert_eq!(PHASE, if available_result == 0 { 1 } else if operation_result == 0 { 3 } else { 2 });
                    assert_eq!(scope[1], if available_result == 0 { 0x1234_5000 } else { 0x8765_4000 });
                    assert_eq!(&scope[2..], &[0xaaaa_aaaa, 0xbbbb_bbbb, 0xcccc_cccc]);
                }
            }
            CONTEXT_SCOPE_APPLY_SUBJECT_OPS = saved;
        }
    }
}
