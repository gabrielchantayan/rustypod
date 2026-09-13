//! ATA task-file register reader — `FUN_080d7314` @ `0x080d7314`.
//!
//! Raw `osos.dec` extent is **76 bytes** at `0x080d7314..0x080d735f`: 16 ARM
//! instructions (64 bytes) followed by three literal words. `0x080d7360`
//! begins the independently linked sibling. Decoding every
//! ARM `B`/`BL` immediate finds exactly **7 inbound direct calls**, all plain,
//! unconditional `bl` (no predicated forms): `0x080a973c`, `0x080c495c`,
//! `0x080c4978`, `0x080c49a0`, `0x080c49bc`, `0x080cdf74`, and `0x080cdf9c`.
//!
//! # Algorithm
//!
//! Submit the fixed `0x0004_00a7` ATA transaction. Its second argument packs
//! the runtime context word at `0x089d03bc + 0x0c` into bits 16..31 and the
//! caller's task-file register selector shifted left eight bits; its third
//! argument is the caller's result slot and its fourth is the context word at
//! `+0x14`. Return one for a non-zero submission result. On zero, emit the
//! stock diagnostic format pointer `0x088f8cf4` and return zero.
//!
//! The transaction worker `FUN_08077490` is not ported, so target builds use
//! a literal veneer and host tests replace it with a volatile seam. The stock
//! diagnostic receives whatever volatile argument registers the worker leaves
//! behind; Rust's fixed `debug_printf` interface instead supplies a null
//! argument-list pointer. This is the deliberate diagnostic-only deviation;
//! the transaction arguments, call order, and success predicate are exact.

use core::ptr;

use crate::stdio::debug_printf::debug_printf;

/// Fixed first argument passed to `FUN_08077490`.
pub const ATA_TASKFILE_REGISTER_READ_COMMAND: u32 = 0x0004_00a7;
const ATA_TASKFILE_REGISTER_READ_FAILURE_FORMAT: *const u8 = 0x088f_8cf4 as *const u8;
const CONTEXT_SELECTOR_WORD: usize = 3;
const CONTEXT_TIMEOUT_WORD: usize = 5;

pub type AtaTaskfileTransaction = unsafe extern "C" fn(u32, u32, *mut u32, u32) -> u32;
pub type AtaTaskfileReadFailureReport = unsafe extern "C" fn(*const u8);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_ata_taskfile_transaction(
    _command: u32,
    _packed_selector: u32,
    _result: *mut u32,
    _timeout: u32,
) -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn ignore_ata_taskfile_read_failure(_format: *const u8) {}

/// Host-side replacements for the still-unported transaction and diagnostic.
#[cfg(not(target_arch = "arm"))]
#[derive(Clone, Copy)]
pub struct AtaTaskfileRegisterReadOps {
    pub submit: AtaTaskfileTransaction,
    pub report_failure: AtaTaskfileReadFailureReport,
}

/// Default host replacements for [`ATA_TASKFILE_REGISTER_READ_OPS`].
#[cfg(not(target_arch = "arm"))]
pub const DEFAULT_ATA_TASKFILE_REGISTER_READ_OPS: AtaTaskfileRegisterReadOps =
    AtaTaskfileRegisterReadOps {
        submit: missing_ata_taskfile_transaction,
        report_failure: ignore_ata_taskfile_read_failure,
    };

/// Host-only seams for the two unported stock calls.
#[cfg(not(target_arch = "arm"))]
pub static mut ATA_TASKFILE_REGISTER_READ_OPS: AtaTaskfileRegisterReadOps =
    DEFAULT_ATA_TASKFILE_REGISTER_READ_OPS;

/// Host model of the six target-width words beginning at `0x089d03bc`.
///
/// The existing `heap::state::GlobalIndirectHolder` only models this global's
/// `+0x04` target pointer. This function instead reads the raw `+0x0c` and
/// `+0x14` words directly, as confirmed by its ARM loads.
#[cfg(not(target_os = "none"))]
pub static mut ATA_TASKFILE_REGISTER_READ_CONTEXT: [u32; 6] = [0; 6];

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_ata_taskfile_transaction(
        command: u32,
        packed_selector: u32,
        result: *mut u32,
        timeout: u32,
    ) -> u32;
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_ata_taskfile_transaction
    .type retail_ata_taskfile_transaction, %function
retail_ata_taskfile_transaction:
    ldr     pc, [pc, #-4]
    .word   0x08077490
    .size retail_ata_taskfile_transaction, . - retail_ata_taskfile_transaction
"#
);

#[inline(always)]
unsafe fn context_word(index: usize) -> u32 {
    #[cfg(target_os = "none")]
    {
        ptr::read_volatile((0x089d_03bc as *const u32).add(index))
    }
    #[cfg(not(target_os = "none"))]
    {
        ptr::read_volatile(ptr::addr_of!(ATA_TASKFILE_REGISTER_READ_CONTEXT).cast::<u32>().add(index))
    }
}

#[inline(always)]
unsafe fn submit_transaction(
    command: u32,
    packed_selector: u32,
    result: *mut u32,
    timeout: u32,
) -> u32 {
    #[cfg(target_arch = "arm")]
    {
        retail_ata_taskfile_transaction(command, packed_selector, result, timeout)
    }
    #[cfg(not(target_arch = "arm"))]
    {
        let submit = ptr::read_volatile(ptr::addr_of!(ATA_TASKFILE_REGISTER_READ_OPS.submit));
        submit(command, packed_selector, result, timeout)
    }
}

#[inline(always)]
unsafe fn report_failure() {
    #[cfg(target_os = "none")]
    {
        debug_printf(ATA_TASKFILE_REGISTER_READ_FAILURE_FORMAT, ptr::null());
    }
    #[cfg(not(target_os = "none"))]
    {
        let report = ptr::read_volatile(ptr::addr_of!(ATA_TASKFILE_REGISTER_READ_OPS.report_failure));
        report(ATA_TASKFILE_REGISTER_READ_FAILURE_FORMAT);
    }
}

/// ata_taskfile_register_read — original: `FUN_080d7314` @ `0x080d7314`
/// (76 bytes: 64 instruction bytes plus a 12-byte literal pool).
///
/// Seven unconditional direct `bl` call sites, verified from every ARM branch
/// immediate in `osos.dec`. Packs a task-file register selector with the
/// `0x089d03bc + 0x0c` context word, submits command `0x0004_00a7` with the
/// `+0x14` timeout, and converts any non-zero worker result to one. Failure
/// reports the stock format pointer; Rust passes a null varargs pointer rather
/// than the worker's unspecified volatile registers.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ata_taskfile_register_read")]
#[inline(never)]
pub unsafe extern "C" fn ata_taskfile_register_read(register_selector: u32, result: *mut u32) -> u32 {
    let packed_selector = context_word(CONTEXT_SELECTOR_WORD).wrapping_shl(16)
        | register_selector.wrapping_shl(8);
    let submitted = submit_transaction(
        ATA_TASKFILE_REGISTER_READ_COMMAND,
        packed_selector,
        result,
        context_word(CONTEXT_TIMEOUT_WORD),
    );
    if submitted != 0 {
        1
    } else {
        report_failure();
        0
    }
}

#[cfg(test)]
pub(crate) static ATA_TASKFILE_REGISTER_READ_TEST_LOCK: parking_lot::Mutex<()> =
    parking_lot::Mutex::new(());

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static mut SUBMIT_RESULT: u32 = 0;
    static mut SUBMIT_ARGS: [u32; 4] = [0; 4];
    static REPORT_COUNT: AtomicUsize = AtomicUsize::new(0);
    static REPORT_FORMAT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_submit(
        command: u32,
        packed_selector: u32,
        result: *mut u32,
        timeout: u32,
    ) -> u32 {
        SUBMIT_ARGS = [command, packed_selector, result as usize as u32, timeout];
        SUBMIT_RESULT
    }

    unsafe extern "C" fn record_failure(format: *const u8) {
        REPORT_FORMAT.store(format as usize, Ordering::Relaxed);
        REPORT_COUNT.fetch_add(1, Ordering::Relaxed);
    }

    struct Reset {
        ops: AtaTaskfileRegisterReadOps,
    }

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(ptr::addr_of_mut!(ATA_TASKFILE_REGISTER_READ_OPS), self.ops);
                ptr::write_volatile(ptr::addr_of_mut!(ATA_TASKFILE_REGISTER_READ_CONTEXT), [0; 6]);
                SUBMIT_RESULT = 0;
                SUBMIT_ARGS = [0; 4];
            }
            REPORT_COUNT.store(0, Ordering::Relaxed);
            REPORT_FORMAT.store(0, Ordering::Relaxed);
        }
    }

    unsafe fn install(context_selector: u32, timeout: u32, submit_result: u32) -> Reset {
        let old = ptr::read_volatile(ptr::addr_of!(ATA_TASKFILE_REGISTER_READ_OPS));
        ptr::write_volatile(
            ptr::addr_of_mut!(ATA_TASKFILE_REGISTER_READ_OPS),
            AtaTaskfileRegisterReadOps {
                submit: record_submit,
                report_failure: record_failure,
            },
        );
        ptr::write_volatile(ptr::addr_of_mut!(ATA_TASKFILE_REGISTER_READ_CONTEXT), [0, 0, 0, context_selector, 0, timeout]);
        SUBMIT_RESULT = submit_result;
        Reset { ops: old }
    }

    #[test]
    fn packs_full_width_selector_and_forwards_result_slot_on_success() {
        let _lock = ATA_TASKFILE_REGISTER_READ_TEST_LOCK.lock();
        let _reset = unsafe { install(0xa5a5_1234, 0xfeed_beef, 7) };
        let mut result = 0u32;

        let status = unsafe { ata_taskfile_register_read(0xdead_beef, &mut result) };

        assert_eq!(status, 1);
        assert_eq!(
            unsafe { SUBMIT_ARGS },
            [
                ATA_TASKFILE_REGISTER_READ_COMMAND,
                0xa5a5_1234u32.wrapping_shl(16) | 0xdead_beefu32.wrapping_shl(8),
                (&mut result as *mut u32) as usize as u32,
                0xfeed_beef,
            ],
        );
        assert_eq!(REPORT_COUNT.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn reports_and_returns_zero_when_transaction_fails() {
        let _lock = ATA_TASKFILE_REGISTER_READ_TEST_LOCK.lock();
        let _reset = unsafe { install(0x0000_0012, 10_000, 0) };

        let status = unsafe { ata_taskfile_register_read(0x0f, ptr::null_mut()) };

        assert_eq!(status, 0);
        assert_eq!(unsafe { SUBMIT_ARGS }, [ATA_TASKFILE_REGISTER_READ_COMMAND, 0x0012_0f00, 0, 10_000]);
        assert_eq!(REPORT_COUNT.load(Ordering::Relaxed), 1);
        assert_eq!(
            REPORT_FORMAT.load(Ordering::Relaxed),
            ATA_TASKFILE_REGISTER_READ_FAILURE_FORMAT as usize,
        );
    }
}
