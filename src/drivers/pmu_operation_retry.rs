//! PMU operation retry and recovery.
//!
//! `pmu_operation_retry` — original: `FUN_082bc998` @ `0x082bc998`.
//! Raw ARM establishes the true **80-byte** extent (`0x082bc998..0x082bc9e7`):
//! the literal-pool word at `0x082bc9e8` is followed by the distinct
//! `push {r4,r5,r6,lr}` prologue at `0x082bc9ec`. Decoding every ARM B/BL
//! word in `osos.dec` verifies four direct inbound plain `bl` calls
//! (`0x08051564`, `0x0825a9b0`, `0x082bc4d0`, `0x082bc980`) and no predicated
//! calls. The body has four unconditional outbound `bl` instructions:
//! `0x082bc910` once per attempt, and on failure semaphore-5 wait,
//!
//! # Algorithm
//!
//! The system-info word at `0x089caaac + 4` is a retry count. Attempt the
//! PMU operation once plus that count, retaining only the final status. Each
//! nonzero status holds semaphore 5 while invoking the recovery operation.
//! After all attempts, clear the retry count and return the final status.
//!
//! # Deliberate deviations
//!
//! The two unported retail callees use literal veneers in the payload because
//! their original PC-relative `bl` transfers cannot reach from it. Host builds
//! substitute callback seams and a static retry word for the target RAM word;
//! the callback seams include semaphore-5 bracketing so failed paths remain
//! testable without installing the process-wide ROM-kernel test table.

#[cfg(target_os = "none")]
use crate::kernel::task_lock::{kernel_sem5_signal, kernel_sem5_wait};

/// Target RAM system-info base; retail uses its word at +4 as retry count.
#[cfg(target_os = "none")]
const SYSTEM_INFO_RETRY_COUNT: *mut u32 = 0x089c_aab0 as *mut u32;

/// Host replacement for system-info +4.
#[cfg(not(target_os = "none"))]
static mut HOST_PMU_RETRY_COUNT: u32 = 0;

/// PMU operation ABI at retail entry `0x082bc910`.
pub type PmuOperation = unsafe extern "C" fn(*mut u32) -> u32;
/// PMU recovery ABI at retail entry `0x0836bb2c`.
pub type PmuRecovery = unsafe extern "C" fn() -> u32;

pub type PmuSync = unsafe extern "C" fn();

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pmu_sync() {}

#[cfg(not(target_os = "none"))]
pub static mut PMU_SEM5_WAIT: PmuSync = missing_pmu_sync;
#[cfg(not(target_os = "none"))]
pub static mut PMU_SEM5_SIGNAL: PmuSync = missing_pmu_sync;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_pmu_operation(_request: *mut u32) -> u32 { 0 }
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_pmu_recovery() -> u32 { 0 }

/// Host seam for the attempted PMU operation.
#[cfg(not(target_arch = "arm"))]
pub static mut PMU_OPERATION: PmuOperation = missing_pmu_operation;
/// Host seam for the recovery operation after a failed attempt.
#[cfg(not(target_arch = "arm"))]
pub static mut PMU_RECOVERY: PmuRecovery = missing_pmu_recovery;

#[inline(always)]
fn retry_count_slot() -> *mut u32 {
    #[cfg(target_os = "none")]
    { SYSTEM_INFO_RETRY_COUNT }
    #[cfg(not(target_os = "none"))]
    { core::ptr::addr_of_mut!(HOST_PMU_RETRY_COUNT) }
}

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_pmu_operation(request: *mut u32) -> u32;
    fn retail_pmu_failure_recover() -> u32;
}

#[cfg(not(target_arch = "arm"))]
unsafe fn retail_pmu_operation(request: *mut u32) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(PMU_OPERATION))(request)
}
#[cfg(not(target_arch = "arm"))]
unsafe fn retail_pmu_failure_recover() -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(PMU_RECOVERY))()
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_pmu_operation
    .type retail_pmu_operation, %function
retail_pmu_operation:
    ldr pc, [pc, #-4]
    .word 0x082bc910
    .size retail_pmu_operation, . - retail_pmu_operation

    .globl retail_pmu_failure_recover
    .type retail_pmu_failure_recover, %function
retail_pmu_failure_recover:
    ldr pc, [pc, #-4]
    .word 0x0836bb2c
    .size retail_pmu_failure_recover, . - retail_pmu_failure_recover
"#);

#[inline(always)]
unsafe fn pmu_sem5_wait() {
    #[cfg(target_os = "none")]
    { kernel_sem5_wait(); }
    #[cfg(not(target_os = "none"))]
    { core::ptr::read_volatile(core::ptr::addr_of!(PMU_SEM5_WAIT))(); }
}
#[inline(always)]
unsafe fn pmu_sem5_signal() {
    #[cfg(target_os = "none")]
    { kernel_sem5_signal(); }
    #[cfg(not(target_os = "none"))]
    { core::ptr::read_volatile(core::ptr::addr_of!(PMU_SEM5_SIGNAL))(); }
}

/// Retries a PMU operation according to system-info +4, recovers after each
/// failed attempt, clears that word, and returns the last operation status.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_operation_retry(request: *mut u32) -> u32 {
    let retry_count = retry_count_slot();
    let mut remaining = retry_count.read_volatile().wrapping_add(1);
    let mut status;
    loop {
        status = retail_pmu_operation(request);
        if status != 0 {
            pmu_sem5_wait();
            retail_pmu_failure_recover();
            pmu_sem5_signal();
        }
        remaining = remaining.wrapping_sub(1);
        if remaining == 0 {
            break;
        }
    }
    retry_count.write_volatile(0);
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut STATUSES: [u32; 4] = [0; 4];
    static mut ATTEMPTS: usize = 0;
    static mut RECOVERIES: usize = 0;
    static mut SEEN_REQUEST: *mut u32 = core::ptr::null_mut();
    static mut SEMAPHORE_WAITS: usize = 0;
    static mut SEMAPHORE_SIGNALS: usize = 0;

    unsafe extern "C" fn scripted_operation(request: *mut u32) -> u32 {
        SEEN_REQUEST = request;
        let status = STATUSES[ATTEMPTS];
        ATTEMPTS += 1;
        status
    }
    unsafe extern "C" fn recording_recovery() -> u32 {
        RECOVERIES += 1;
        0
    }
    unsafe extern "C" fn recording_wait() { SEMAPHORE_WAITS += 1; }
    unsafe extern "C" fn recording_signal() { SEMAPHORE_SIGNALS += 1; }

    struct Fixture;
    impl Fixture {
        fn install(retry_count: u32, statuses: [u32; 4]) -> Self {
            unsafe {
                HOST_PMU_RETRY_COUNT = retry_count;
                STATUSES = statuses;
                ATTEMPTS = 0;
                RECOVERIES = 0;
                SEEN_REQUEST = core::ptr::null_mut();
                PMU_OPERATION = scripted_operation;
                PMU_RECOVERY = recording_recovery;
                SEMAPHORE_WAITS = 0;
                SEMAPHORE_SIGNALS = 0;
                PMU_SEM5_WAIT = recording_wait;
                PMU_SEM5_SIGNAL = recording_signal;
            }
            Self
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                HOST_PMU_RETRY_COUNT = 0;
                PMU_OPERATION = missing_pmu_operation;
                PMU_RECOVERY = missing_pmu_recovery;
                PMU_SEM5_WAIT = missing_pmu_sync;
                PMU_SEM5_SIGNAL = missing_pmu_sync;
            }
        }
    }

    #[test]
    fn zero_retry_count_still_makes_one_successful_attempt() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _fixture = Fixture::install(0, [0, 0, 0, 0]);
        let mut request = 0x1234_5678;
        assert_eq!(unsafe { pmu_operation_retry(&mut request) }, 0);
        unsafe {
            assert_eq!(ATTEMPTS, 1);
            assert_eq!(RECOVERIES, 0);
            assert_eq!(SEEN_REQUEST, core::ptr::addr_of_mut!(request));
            assert_eq!(HOST_PMU_RETRY_COUNT, 0);
        }
    }

    #[test]
    fn retries_failures_recovers_each_and_returns_final_status() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _fixture = Fixture::install(2, [7, 9, 3, 0]);
        let mut request = 0;
        assert_eq!(unsafe { pmu_operation_retry(&mut request) }, 3);
        unsafe {
            assert_eq!(ATTEMPTS, 3);
            assert_eq!(RECOVERIES, 3);
            assert_eq!(SEMAPHORE_WAITS, 3);
            assert_eq!(SEMAPHORE_SIGNALS, 3);
            assert_eq!(HOST_PMU_RETRY_COUNT, 0);
        }
    }
}
