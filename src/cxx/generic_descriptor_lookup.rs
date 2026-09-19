//! Generic descriptor lookup — original: `FUN_0803a7f0` @ load address
//! `0x0803a7f0` (100 bytes; `0x0803a7f0..0x0803a854`). The next distinct
//! function begins with `stmdb sp!, {r2,r3,r4,r5,r6,lr}` at `0x0803a854`.
//!
//! Raw `osos.dec` disassembly finds four incoming plain `bl` calls and no
//! incoming predicated `bl` calls. This wrapper supplies a stack-local output
//! word when its output argument is NULL, initializes the parser's 24-byte
//! status area, and calls the descriptor parser at `0x0803a99c` with selector
//! `-1` and both optional flags clear. A positive parser result returns the
//! resolved output word; zero or negative results return NULL.
//!
//! Deliberate deviation: target builds use the 25 original ARM words verbatim.
//! Host builds call a recording seam for the still-unported parser, so tests can
//! verify the wrapper's local-output and result-status behavior.

/// ABI of the unrecovered descriptor parser at `0x0803a99c`.
pub type DescriptorParser = unsafe extern "C" fn(
    *mut u32,
    *mut u8,
    u32,
    *mut u8,
    i32,
    u32,
    u32,
    *mut u8,
) -> i32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_descriptor_parser(
    _output: *mut u32,
    _input: *mut u8,
    _input_len: u32,
    _descriptor: *mut u8,
    _selector: i32,
    _option_a: u32,
    _option_b: u32,
    _status: *mut u8,
) -> i32 {
    0
}

/// Host boundary for the still-unported descriptor parser.
#[cfg(not(target_arch = "arm"))]
pub static mut DESCRIPTOR_PARSER: DescriptorParser = missing_descriptor_parser;

#[cfg(test)]
pub(crate) static DESCRIPTOR_PARSER_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// Resolves an object through a format-specific descriptor parser.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn generic_descriptor_lookup(
    output: *mut u32,
    input: *mut u8,
    input_len: u32,
    descriptor: *mut u8,
) -> *mut u8 {
    let mut local_output = 0u32;
    let mut status = [0u8; 24];
    let output = if output.is_null() { core::ptr::addr_of_mut!(local_output) } else { output };
    let parser = core::ptr::read_volatile(core::ptr::addr_of!(DESCRIPTOR_PARSER));
    if parser(output, input, input_len, descriptor, -1, 0, 0, status.as_mut_ptr()) > 0 {
        output.read() as usize as *mut u8
    } else {
        core::ptr::null_mut()
    }
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .section .text.generic_descriptor_lookup, "ax", %progbits
    .p2align 2
    .globl generic_descriptor_lookup
    .type generic_descriptor_lookup, %function
generic_descriptor_lookup:
    stmdb   sp!, {{r4, r5, lr}}
    movs    r4, r0
    sub     sp, sp, #0x2c
    mov     r0, #0
    mov     lr, r2
    mov     r5, r3
    mov     r12, r1
    str     r0, [sp, #0x10]
    strb    r0, [sp, #0x14]
    mvn     r0, #0
    mov     r1, #0
    add     r3, sp, #0x14
    mov     r2, #0
    stmia   sp, {{r0, r1, r2, r3}}
    addeq   r4, sp, #0x10
    mov     r0, r4
    mov     r3, r5
    mov     r2, lr
    mov     r1, r12
    bl      0x0803a99c
    cmp     r0, #0
    ldrgt   r0, [r4]
    add     sp, sp, #0x2c
    movle   r0, #0
    ldmia   sp!, {{r4, r5, pc}}
    .size generic_descriptor_lookup, . - generic_descriptor_lookup
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};

    static STATUS: AtomicI32 = AtomicI32::new(0);
    static RESULT: AtomicU32 = AtomicU32::new(0);
    static OUTPUT: AtomicUsize = AtomicUsize::new(0);
    static SELECTOR: AtomicI32 = AtomicI32::new(0);
    static FLAGS: AtomicU32 = AtomicU32::new(u32::MAX);
    static STATUS_BYTE: AtomicUsize = AtomicUsize::new(usize::MAX);

    unsafe extern "C" fn record_parser(
        output: *mut u32, _input: *mut u8, _input_len: u32, _descriptor: *mut u8,
        selector: i32, option_a: u32, option_b: u32, status: *mut u8,
    ) -> i32 {
        OUTPUT.store(output as usize, Ordering::SeqCst);
        SELECTOR.store(selector, Ordering::SeqCst);
        FLAGS.store(option_a | option_b, Ordering::SeqCst);
        STATUS_BYTE.store(status.read() as usize, Ordering::SeqCst);
        output.write(RESULT.load(Ordering::SeqCst));
        STATUS.load(Ordering::SeqCst)
    }

    struct SeamReset;
    impl Drop for SeamReset {
        fn drop(&mut self) { unsafe { DESCRIPTOR_PARSER = missing_descriptor_parser }; }
    }

    fn install_parser(status: i32, result: u32) -> SeamReset {
        STATUS.store(status, Ordering::SeqCst);
        RESULT.store(result, Ordering::SeqCst);
        OUTPUT.store(0, Ordering::SeqCst);
        SELECTOR.store(0, Ordering::SeqCst);
        FLAGS.store(u32::MAX, Ordering::SeqCst);
        STATUS_BYTE.store(usize::MAX, Ordering::SeqCst);
        unsafe { DESCRIPTOR_PARSER = record_parser };
        SeamReset
    }

    #[test]
    fn null_output_uses_initialized_local_result_for_positive_status() {
        let _guard = DESCRIPTOR_PARSER_TEST_LOCK.lock();
        let _reset = install_parser(1, 0x1234_5678);
        let result = unsafe {
            generic_descriptor_lookup(core::ptr::null_mut(), 0x1000usize as *mut u8, 9, 0x2000usize as *mut u8)
        };
        assert_eq!(result as usize, 0x1234_5678);
        assert_ne!(OUTPUT.load(Ordering::SeqCst), 0);
        assert_eq!(SELECTOR.load(Ordering::SeqCst), -1);
        assert_eq!(FLAGS.load(Ordering::SeqCst), 0);
        assert_eq!(STATUS_BYTE.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn nonpositive_status_returns_null_without_reading_caller_output() {
        let _guard = DESCRIPTOR_PARSER_TEST_LOCK.lock();
        let _reset = install_parser(0, 0xdead_beef);
        let mut output = 0xa5a5_a5a5;
        let result = unsafe {
            generic_descriptor_lookup(core::ptr::addr_of_mut!(output), core::ptr::null_mut(), 0, core::ptr::null_mut())
        };
        assert!(result.is_null());
        assert_eq!(output, 0xdead_beef);
    }
}
