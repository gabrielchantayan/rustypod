//! Stream query result — `FUN_083d8e88` @ load address `0x083d8e88`.
//!
//! Raw `osos.dec` words establish the 44-byte extent
//! `0x083d8e88..0x083d8eb0`; `0x083d8eb4` begins the next function with
//! `push {r4,r5,r6,r7,r8,r9,sl,lr}`. The body has one plain unconditional
//! `bl`, to the unrecovered stream query at `0x08266bc0`, and no predicated
//! `bl` instructions. Whole-image A32 decoding finds three inbound plain
//! `bl` calls (`0x083d9014`, `0x083d92b4`, and `0x083d93e8`) and no
//! predicated calls. It forwards the three query arguments after adding 48 to
//! the stream object's address, stores the returned word, and clears the
//! result's second word.
//!
//! Deliberate deviation: ARM builds retain the eleven original instructions.
//! Host builds use a seam for `0x08266bc0`, whose semantic identity has not
//! been recovered; this permits testing the wrapper without inventing it.

/// ABI of the unrecovered query at `0x08266bc0`.
pub type StreamQuery = unsafe extern "C" fn(*mut u8, u32, u32) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_stream_query(_stream_state: *mut u8, _arg2: u32, _arg3: u32) -> u32 {
    0
}

/// Host boundary for the still-unported query at `0x08266bc0`.
#[cfg(not(target_arch = "arm"))]
pub static mut STREAM_QUERY: StreamQuery = missing_stream_query;

#[cfg(test)]
pub(crate) static STREAM_QUERY_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// Queries the stream subobject at offset 48 and forms its two-word result.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_query_result(
    result: *mut u32,
    stream: *mut u8,
    arg2: u32,
    arg3: u32,
) {
    let query = core::ptr::read_volatile(core::ptr::addr_of!(STREAM_QUERY));
    result.write_volatile(query(stream.add(0x30), arg2, arg3));
    result.add(1).write_volatile(0);
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .section .text.stream_query_result, "ax", %progbits
    .p2align 2
    .globl stream_query_result
    .type stream_query_result, %function
stream_query_result:
    push    {{r4, lr}}
    mov     r4, r0
    mov     r0, r1
    mov     r1, r2
    mov     r2, r3
    add     r0, r0, #0x30
    bl      0x08266bc0
    str     r0, [r4]
    mov     r0, #0
    str     r0, [r4, #4]
    pop     {{r4, pc}}
    .size stream_query_result, . - stream_query_result
"#
);

#[cfg(test)]
mod tests {
    use super::{stream_query_result, StreamQuery, STREAM_QUERY, STREAM_QUERY_TEST_LOCK};
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    static OBSERVED_STREAM_STATE: AtomicUsize = AtomicUsize::new(0);
    static OBSERVED_ARG2: AtomicU32 = AtomicU32::new(0);
    static OBSERVED_ARG3: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn recording_stream_query(stream_state: *mut u8, arg2: u32, arg3: u32) -> u32 {
        OBSERVED_STREAM_STATE.store(stream_state as usize, Ordering::Relaxed);
        OBSERVED_ARG2.store(arg2, Ordering::Relaxed);
        OBSERVED_ARG3.store(arg3, Ordering::Relaxed);
        0x81e2_4a09
    }

    #[test]
    fn queries_offset_0x30_and_clears_result_tail() {
        let _lock = STREAM_QUERY_TEST_LOCK.lock();
        let saved_query: StreamQuery = unsafe { STREAM_QUERY };
        unsafe { STREAM_QUERY = recording_stream_query };

        let mut stream = [0u8; 0x34];
        let mut result = [0xffff_ffff; 2];
        unsafe { stream_query_result(result.as_mut_ptr(), stream.as_mut_ptr(), 0x1234_5678, 0x9abc_def0) };

        assert_eq!(OBSERVED_STREAM_STATE.load(Ordering::Relaxed), unsafe { stream.as_mut_ptr().add(0x30) } as usize);
        assert_eq!(OBSERVED_ARG2.load(Ordering::Relaxed), 0x1234_5678);
        assert_eq!(OBSERVED_ARG3.load(Ordering::Relaxed), 0x9abc_def0);
        assert_eq!(result, [0x81e2_4a09, 0]);

        unsafe { STREAM_QUERY = saved_query };
    }
}
