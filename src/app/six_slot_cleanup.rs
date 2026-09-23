//! `six_slot_cleanup` — original: `FUN_081d8f24` @ **0x081d8f24**
//! (**40 bytes**, `0x081d8f24..0x081d8f4c`; the next function starts at
//! `0x081d8f4c`). Raw whole-image A32 decoding finds **3 inbound plain `bl`
//! calls** (`0x081d8e98`, `0x081d8f74`, and `0x081d9294`) and **0 predicated
//! inbound `bl` calls**. The body has one predicated outbound `blne`.
//!
//! # Algorithm
//!
//! Iterates the six target-width words at `slots`, passing each nonzero word to
//! retail `FUN_08120700` at `0x08120700`.
//!
//! # Deliberate deviations
//!
//! `FUN_08120700` has no `names.yaml` identity, so this port preserves its
//! verified raw address on ARM rather than inventing a callee name. Host builds
//! expose that fixed-address call as a recording callback solely for tests.

/// Host replacement for retail `FUN_08120700` at `0x08120700`.
pub type SixSlotCleanupCallback = unsafe extern "C" fn(u32);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_six_slot_cleanup_callback(_slot: u32) {
    panic!("six_slot_cleanup requires a cleanup callback fixture")
}

#[cfg(not(target_arch = "arm"))]
pub static mut SIX_SLOT_CLEANUP_CALLBACK: SixSlotCleanupCallback = missing_six_slot_cleanup_callback;

/// Calls the retail cleanup routine for every nonzero word in six slots.
///
/// # Safety
///
/// `slots` must point to six readable, four-byte-aligned target words. Each
/// nonzero word must be valid for retail `FUN_08120700` on target; host callers
/// must install [`SIX_SLOT_CLEANUP_CALLBACK`].
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn six_slot_cleanup(slots: *const u32) {
    for slot_index in 0..6 {
        let slot = unsafe { core::ptr::read_volatile(slots.add(slot_index)) };
        if slot != 0 {
            unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SIX_SLOT_CLEANUP_CALLBACK))(slot) };
        }
    }
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl six_slot_cleanup
    .type six_slot_cleanup, %function
six_slot_cleanup:
    push    {{r4, r5, r6, lr}}
    mov     r5, r0
    mov     r4, #0
1:
    ldr     r0, [r5, r4, lsl #2]
    cmp     r0, #0
    blne    2f
    add     r4, r4, #1
    cmp     r4, #6
    blt     1b
    pop     {{r4, r5, r6, pc}}
2:
    ldr     pc, [pc, #-4]
    .word   0x08120700
    .size six_slot_cleanup, . - six_slot_cleanup
"#
);

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());


    static mut SEEN: [u32; 6] = [0; 6];
    static mut CALL_COUNT: usize = 0;

    unsafe extern "C" fn record_slot(slot: u32) {
        unsafe {
            SEEN[CALL_COUNT] = slot;
            CALL_COUNT += 1;
        }
    }

    #[test]
    fn cleans_only_nonzero_slots_in_index_order() {
        let _guard = TEST_LOCK.lock();

        unsafe {
            SEEN = [0; 6];
            CALL_COUNT = 0;
            SIX_SLOT_CLEANUP_CALLBACK = record_slot;
            let slots = [0, 0x10, 0, 0x20, 0x30, 0];
            six_slot_cleanup(slots.as_ptr());
            assert_eq!(CALL_COUNT, 3);
            assert_eq!(&SEEN[..CALL_COUNT], &[0x10, 0x20, 0x30]);
        }
    }

    #[test]
    fn accepts_an_all_zero_slot_array() {
        let _guard = TEST_LOCK.lock();

        unsafe {
            CALL_COUNT = 0;
            SIX_SLOT_CLEANUP_CALLBACK = record_slot;
            six_slot_cleanup([0; 6].as_ptr());
            assert_eq!(CALL_COUNT, 0);
        }
    }
}
