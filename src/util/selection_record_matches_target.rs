//! `selection_record_matches_target` — original: `FUN_0836991c` @
//! `0x0836991c` (100 bytes; true extent `0x0836991c..0x08369917f`). The next
//! real function starts with `push {r4, lr}` at `0x083699180`.
//!
//! Raw A32 decoding finds two unconditional plain inbound `bl` call sites
//! (`0x082b6e88` and `0x082b7050`), no predicated inbound `bl` calls, and one
//! unconditional plain body `bl` at `0x0836995c` to unported `0x083672e4`.
//!
//! # Algorithm
//!
//! Read the selected record through the target-width pointer at `state+0xc`.
//! It matches only when its tag is `0x95`, its word at `+0x24` equals `target`,
//! and its signed word at `+0x28` is `-1`. Then ask retail `0x083672e4` to
//! validate the remaining records, starting at index one. On success copy the
//! selected record holder's byte at `+8` to `out` and return one; otherwise
//! return zero.
//!
//! # Deliberate deviations
//!
//! `0x083672e4` remains unported and unnamed: its observable role here is a
//! four-word validation call, not a sufficiently established identity. The
//! relocated ARM port reaches that exact address through an absolute veneer;
//! host tests install a recording seam. The ARM implementation intentionally
//! preserves the stock instruction sequence and call boundary.

/// ABI of unported retail `FUN_083672e4` at `0x083672e4`.
pub type Retail083672e4 = unsafe extern "C" fn(*const u32, u32, u32, u32) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_retail_083672e4(
    _state: *const u32,
    _context: u32,
    _start_index: u32,
    _target: u32,
) -> u32 {
    1
}

/// Host replacement for the unresolved validation callee.
#[cfg(not(target_arch = "arm"))]
pub static mut RETAIL_083672E4: Retail083672e4 = missing_retail_083672e4;

#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selection_record_matches_target(
    target: u32,
    state: *const u32,
    context: u32,
    out: *mut u32,
) -> u32 {
    let record_holder = state.add(3).read() as usize as *const u8;
    let record = (record_holder as *const u32).read() as usize as *const u8;
    if record.read() != 0x95
        || (record.add(0x24) as *const u32).read() != target
        || (record.add(0x28) as *const i32).read() != -1
    {
        return 0;
    }

    let validate = core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_083672E4));
    if validate(state, context, 1, target) != 0 {
        return 0;
    }
    out.write(record_holder.add(8).read() as u32);
    1
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(r#"
    .syntax unified
    .arm
    .p2align 2
    .globl selection_record_matches_target
    .type selection_record_matches_target, %function
selection_record_matches_target:
    push    {{r4, r5, r6, lr}}
    mov     r4, r1
    mov     r1, r2
    ldr     r2, [r4, #12]
    mov     r5, r3
    ldr     r2, [r2]
    ldrb    r3, [r2]
    cmp     r3, #149
    ldreq   r3, [r2, #36]
    cmpeq   r3, r0
    ldreq   r2, [r2, #40]
    cmneq   r2, #1
    bne     1f
    mov     r3, r0
    mov     r0, r4
    mov     r2, #1
    bl      retail_083672e4
    cmp     r0, #0
    ldreq   r0, [r4, #12]
    ldrbeq  r0, [r0, #8]
    streq   r0, [r5]
    moveq   r0, #1
    popeq   {{r4, r5, r6, pc}}
1:  mov     r0, #0
    pop     {{r4, r5, r6, pc}}
retail_083672e4:
    ldr     pc, 1f
1:  .word   0x083672e4
    .size selection_record_matches_target, . - selection_record_matches_target
"#);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    use parking_lot::Mutex;
    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut CALL: (*const u32, u32, u32, u32) = (core::ptr::null(), 0, 0, 0);
    static mut RESULT: u32 = 0;

    unsafe extern "C" fn recording_validator(
        state: *const u32,
        context: u32,
        start_index: u32,
        target: u32,
    ) -> u32 {
        unsafe { CALL = (state, context, start_index, target) };
        unsafe { RESULT }
    }

    struct Restore(Retail083672e4);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { RETAIL_083672E4 = self.0 };
        }
    }

    fn checks_header_before_validating_and_returns_holder_byte_on_success() {
        let _lock = SEAM_LOCK.lock();
        let Some(holder) = crate::testing::try_map_u32_slab(
            crate::testing::hints::SELECTION_RECORD_MATCHES_TARGET,
            0x1000,
        ) else {
            crate::testing::note_missing_u32_fixture("selection_record_matches_target");
            return;
        };
        let record = unsafe { holder.add(0x40) };
        unsafe {
            (holder as *mut u32).write(record as usize as u32);
            holder.add(8).write(0x7a);
            record.write(0x95);
            (record.add(0x24) as *mut u32).write(0x1234_5678);
            (record.add(0x28) as *mut i32).write(-1);
        }
        let mut state = [0_u32; 4];
        state[3] = holder as usize as u32;
        let mut out = 0xa5a5_a5a5;
        let _restore = unsafe {
            let previous = RETAIL_083672E4;
            RETAIL_083672E4 = recording_validator;
            RESULT = 0;
            CALL = (core::ptr::null(), 0, 0, 0);
            Restore(previous)
        };

        assert_eq!(unsafe { selection_record_matches_target(0x1234_5678, state.as_ptr(), 9, &mut out) }, 1);
        assert_eq!(out, 0x7a);
        assert_eq!(unsafe { CALL }, (state.as_ptr(), 9, 1, 0x1234_5678));

        unsafe { record.write(0x94) };
        out = 0xa5a5_a5a5;
        assert_eq!(unsafe { selection_record_matches_target(0x1234_5678, state.as_ptr(), 9, &mut out) }, 0);
        assert_eq!(out, 0xa5a5_a5a5);
        assert_eq!(unsafe { CALL }, (state.as_ptr(), 9, 1, 0x1234_5678));

        unsafe { record.write(0x95) };
        unsafe { (record.add(0x28) as *mut i32).write(0) };
        assert_eq!(unsafe { selection_record_matches_target(0x1234_5678, state.as_ptr(), 9, &mut out) }, 0);

        unsafe { (record.add(0x28) as *mut i32).write(-1) };
        unsafe { RESULT = 1 };
        assert_eq!(unsafe { selection_record_matches_target(0x1234_5678, state.as_ptr(), 9, &mut out) }, 0);
    }
}
