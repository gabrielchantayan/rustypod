//! `resource_handle_execute` — original: `FUN_082620f0` @ **0x082620f0**
//! (32 bytes).
//!
//! Raw ARM is `push {r4,lr}; mov r4,r0; mov r0,#0; str r0,[r4,#4]; mov
//! r0,r4; bl 0x08262070; mov r0,r4; pop {r4,pc}`. The distinct next function
//! starts at 0x08262110, so the 32-byte Ghidra extent is exact. Decoding every
//! ARM branch-with-link word in `osos.dec` finds five plain callers
//! (0x081e6ba0, 0x082628a8, 0x0839e918, 0x0839ea84, and 0x0839f460) and no
//! predicated BL callers.
//!
//! Algorithm: clear the result's operation-status word at +0x04, forward the
//! unchanged four ARM arguments to the worker at 0x08262070, then return the
//! result pointer. The worker may replace the cleared status with its result.
//!
//! Deliberate deviation: the worker is unported. Target builds call its fixed
//! retailOS address; host builds use a volatile callback seam to verify the
//! field write, argument forwarding, and return-pointer identity.

#[cfg(not(target_os = "none"))]
use core::ptr;

const RETAIL_RESOURCE_HANDLE_EXECUTE_WORKER: usize = 0x0826_2070;

type ResourceHandleExecuteWorker = unsafe extern "C" fn(*mut u8, u32, u32, u32);

#[repr(C)]
struct ResourceHandleExecution {
    _value: u32,
    operation_status: u32,
}

/// Host boundary for the unported resource-handle execution worker at
/// 0x08262070.
#[cfg(not(target_os = "none"))]
pub struct ResourceHandleExecuteOps {
    pub worker: ResourceHandleExecuteWorker,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_resource_handle_execute_worker(
    _result: *mut u8,
    _operation: u32,
    _subject: u32,
    _context: u32,
) {
}

/// Host callback seam for the unported worker. Target builds call 0x08262070
/// directly.
#[cfg(not(target_os = "none"))]
pub static mut RESOURCE_HANDLE_EXECUTE_OPS: ResourceHandleExecuteOps = ResourceHandleExecuteOps {
    worker: missing_resource_handle_execute_worker,
};

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn resource_handle_execute_worker(result: *mut u8, operation: u32, subject: u32, context: u32) {
    let worker: ResourceHandleExecuteWorker = core::mem::transmute(RETAIL_RESOURCE_HANDLE_EXECUTE_WORKER);
    worker(result, operation, subject, context);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn resource_handle_execute_worker(result: *mut u8, operation: u32, subject: u32, context: u32) {
    let worker = ptr::read_volatile(ptr::addr_of!(RESOURCE_HANDLE_EXECUTE_OPS.worker));
    worker(result, operation, subject, context);
}

/// Clears `result`'s operation status, starts its requested operation, and
/// returns `result`.
///
/// # Safety
/// `result` must point to an execution-result object with a writable u32 at
/// offset +0x04. The retail worker receives all arguments unchanged and may
/// access their pointed-to objects; this wrapper performs no NULL checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.resource_handle_execute")]
#[inline(never)]
pub unsafe extern "C" fn resource_handle_execute(
    result: *mut u8,
    operation: u32,
    subject: u32,
    context: u32,
) -> *mut u8 {
    let result_fields = result.cast::<ResourceHandleExecution>();
    unsafe {
        (*result_fields).operation_status = 0;
        resource_handle_execute_worker(result, operation, subject, context);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static WORKER_CALLS: AtomicUsize = AtomicUsize::new(0);
    static WORKER_RESULT: AtomicUsize = AtomicUsize::new(0);
    static WORKER_OPERATION: AtomicU32 = AtomicU32::new(0);
    static WORKER_SUBJECT: AtomicU32 = AtomicU32::new(0);
    static WORKER_CONTEXT: AtomicU32 = AtomicU32::new(0);
    static STATUS_AT_WORKER: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn record_worker(result: *mut u8, operation: u32, subject: u32, context: u32) {
        let fields = result.cast::<ResourceHandleExecution>();
        STATUS_AT_WORKER.store(unsafe { (*fields).operation_status }, Ordering::SeqCst);
        WORKER_RESULT.store(result as usize, Ordering::SeqCst);
        WORKER_OPERATION.store(operation, Ordering::SeqCst);
        WORKER_SUBJECT.store(subject, Ordering::SeqCst);
        WORKER_CONTEXT.store(context, Ordering::SeqCst);
        WORKER_CALLS.fetch_add(1, Ordering::SeqCst);
        unsafe { (*fields).operation_status = 0x7e57_0001 };
    }

    fn install_recording_worker() {
        unsafe {
            RESOURCE_HANDLE_EXECUTE_OPS = ResourceHandleExecuteOps { worker: record_worker };
        }
        WORKER_CALLS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn clears_status_before_forwarding_all_arguments() {
        let _guard = TEST_LOCK.lock();
        install_recording_worker();
        let mut result = ResourceHandleExecution {
            _value: 0xa5a5_a5a5,
            operation_status: 0xffff_ffff,
        };
        let result_ptr = (&mut result as *mut ResourceHandleExecution).cast::<u8>();

        let returned = unsafe { resource_handle_execute(result_ptr, 0x1122_3344, 0x5566_7788, 0x99aa_bbcc) };

        assert_eq!(returned, result_ptr);
        assert_eq!(result._value, 0xa5a5_a5a5);
        assert_eq!(STATUS_AT_WORKER.load(Ordering::SeqCst), 0);
        assert_eq!(WORKER_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(WORKER_RESULT.load(Ordering::SeqCst), result_ptr as usize);
        assert_eq!(WORKER_OPERATION.load(Ordering::SeqCst), 0x1122_3344);
        assert_eq!(WORKER_SUBJECT.load(Ordering::SeqCst), 0x5566_7788);
        assert_eq!(WORKER_CONTEXT.load(Ordering::SeqCst), 0x99aa_bbcc);
        assert_eq!(result.operation_status, 0x7e57_0001);
    }
}
